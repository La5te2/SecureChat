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

app.MapGet("/media/{id}", (string id, MediaRegistry registry) =>
{
    if (!registry.TryGet(id, out var item) || !File.Exists(item.Path))
    {
        return Results.NotFound();
    }

    return Results.File(item.Path, item.ContentType, enableRangeProcessing: true);
});

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

app.MapPost("/api/host", (HostRequest request, ChatEventBus bus) =>
{
    var ok = NativeChat.HostStart(request.ServerUrl, request.RoomId, request.Username, request.Password);
    if (ok == 0) return Results.BadRequest(new { ok = false });

    bus.Publish("status", $"Web host connected to {request.ServerUrl}");
    return Results.Ok(new { ok = true });
});

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

app.MapPost("/api/send", (SendRequest request) =>
{
    if (string.IsNullOrWhiteSpace(request.Text)) return Results.BadRequest(new { ok = false });
    var ok = NativeChat.SendLine(request.Text.Trim());
    return ok == 0 ? Results.BadRequest(new { ok = false }) : Results.Ok(new { ok = true });
});

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

    var ok = NativeChat.SendFile(kind, path);
    return ok == 0 ? Results.BadRequest(new { ok = false }) : Results.Ok(new { ok = true });
});

app.Run();

internal sealed record HostRequest(
    string ServerUrl,
    string RoomId,
    string Username,
    string Password);
internal sealed record JoinRequest(string Url, string RoomId, string Username, string Password);
internal sealed record SendRequest(string Text);
