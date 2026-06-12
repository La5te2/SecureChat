using System.Text.Json;
using SecureChat.Web;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory,
    WebRootPath = Path.Combine(AppContext.BaseDirectory, "wwwroot")
});
builder.Services.AddSingleton<ChatEventBus>();
builder.Services.AddSingleton<MediaRegistry>();

var app = builder.Build();
var events = app.Services.GetRequiredService<ChatEventBus>();
var media = app.Services.GetRequiredService<MediaRegistry>();
NativeChat.Initialize(events, media);

app.Lifetime.ApplicationStopping.Register(NativeChat.Shutdown);

app.UseDefaultFiles();
app.UseStaticFiles();

// Serve attachment files that the native core has already received and registered.
app.MapGet("/media/{id}", (string id, MediaRegistry registry) =>
{
    if (!registry.TryGet(id, out var item) || !File.Exists(item.Path))
    {
        return Results.NotFound();
    }

    return Results.File(item.Path, item.ContentType, enableRangeProcessing: true);
});

// Browser clients receive native status, message, and attachment events over SSE.
app.MapGet("/events", async (HttpContext context, ChatEventBus bus) =>
{
    context.Response.Headers.Append("Cache-Control", "no-cache");
    context.Response.Headers.Append("X-Accel-Buffering", "no");
    context.Response.ContentType = "text/event-stream";

    var reader = bus.Subscribe(context.RequestAborted);
    await foreach (var chatEvent in reader.ReadAllAsync(context.RequestAborted))
    {
        var json = JsonSerializer.Serialize(chatEvent);
        await context.Response.WriteAsync($"data: {json}\n\n", context.RequestAborted);
        await context.Response.Body.FlushAsync(context.RequestAborted);
    }
});

// Host creates a room on an already running Server; the Server itself is not a room member.
app.MapPost("/api/host", (HostRequest request, ChatEventBus bus) =>
{
    var ok = NativeChat.HostStart(request.ServerUrl, request.RoomId, request.Username, request.Password);
    if (ok == 0) return Results.BadRequest(new { ok = false });

    bus.Publish("status", $"Web host connected to {request.ServerUrl}");
    return Results.Ok(new { ok = true });
});

// Client joins an existing room through the relay Server.
app.MapPost("/api/join", (JoinRequest request, ChatEventBus bus) =>
{
    var ok = NativeChat.JoinStart(request.Url, request.RoomId, request.Username, request.Password);
    if (ok == 0) return Results.BadRequest(new { ok = false });

    bus.Publish("status", $"Web client joining {request.Url}");
    return Results.Ok(new { ok = true });
});

app.MapPost("/api/stop", (ChatEventBus bus) =>
{
    NativeChat.Stop();
    bus.Publish("status", "Session stopped");
    return Results.Ok(new { ok = true });
});

// Send room text by default, or private text when Target contains a member name/id.
app.MapPost("/api/send", (SendRequest request) =>
{
    if (string.IsNullOrWhiteSpace(request.Text)) return Results.BadRequest(new { ok = false });
    var ok = NativeChat.SendLine(request.Text.Trim(), request.Target ?? "");
    return ok == 0 ? Results.BadRequest(new { ok = false }) : Results.Ok(new { ok = true });
});

// Store browser uploads locally first, then let the native layer encrypt and relay them.
app.MapPost("/api/upload", async (HttpRequest request) =>
{
    if (!request.HasFormContentType) return Results.BadRequest(new { ok = false });

    var form = await request.ReadFormAsync();
    var file = form.Files.GetFile("file");
    if (file is null || file.Length == 0) return Results.BadRequest(new { ok = false });

    var kind = request.Query["kind"].ToString();
    var uploadRoot = Path.Combine(AppContext.BaseDirectory, "uploads");
    Directory.CreateDirectory(uploadRoot);

    var safeName = string.Join("_", Path.GetFileName(file.FileName).Split(Path.GetInvalidFileNameChars()));
    var path = Path.Combine(uploadRoot, $"{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}_{safeName}");
    await using (var stream = File.Create(path))
    {
        await file.CopyToAsync(stream);
    }

    var target = form["target"].ToString();
    var ok = NativeChat.SendFile(kind, path, target);
    return ok == 0 ? Results.BadRequest(new { ok = false }) : Results.Ok(new { ok = true });
});

app.Run();

internal sealed record HostRequest(
    string ServerUrl,
    string RoomId,
    string Username,
    string Password);
internal sealed record JoinRequest(string Url, string RoomId, string Username, string Password);
internal sealed record SendRequest(string Text, string? Target);
