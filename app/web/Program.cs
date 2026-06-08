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
    ConfigureSignalingMode(request);
    var ok = NativeChat.HostStart(request.RoomId, request.Port, request.Username, request.Password);
    if (ok == 0) return Results.BadRequest(new { ok = false });

    var scheme = IsWss(request.SignalingMode) ? "wss" : "ws";
    bus.Publish("status", $"Web host started on {scheme}://127.0.0.1:{request.Port}");
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

app.MapGet("/api/discover", (string? roomId, int? timeoutMs) =>
{
    var json = NativeChat.DiscoverRoomsJson(roomId ?? "", timeoutMs.GetValueOrDefault(1500));
    return Results.Content(json, "application/json");
});

app.Run();

static bool IsWss(string? mode)
{
    return string.Equals(mode, "wss", StringComparison.OrdinalIgnoreCase);
}

static void ConfigureSignalingMode(HostRequest request)
{
    if (!IsWss(request.SignalingMode))
    {
        Environment.SetEnvironmentVariable("SECURECHAT_SIGNALING_TLS", null);
        Environment.SetEnvironmentVariable("SECURECHAT_TLS_CERT_FILE", null);
        Environment.SetEnvironmentVariable("SECURECHAT_TLS_KEY_FILE", null);
        Environment.SetEnvironmentVariable("SECURECHAT_TLS_KEY_PASS", null);
        return;
    }

    if (string.IsNullOrWhiteSpace(request.TlsCertFile) || string.IsNullOrWhiteSpace(request.TlsKeyFile))
    {
        throw new BadHttpRequestException("WSS requires TLS certificate and private key files.");
    }

    Environment.SetEnvironmentVariable("SECURECHAT_SIGNALING_TLS", "1");
    Environment.SetEnvironmentVariable("SECURECHAT_TLS_CERT_FILE", request.TlsCertFile);
    Environment.SetEnvironmentVariable("SECURECHAT_TLS_KEY_FILE", request.TlsKeyFile);
    Environment.SetEnvironmentVariable("SECURECHAT_TLS_KEY_PASS", string.IsNullOrEmpty(request.TlsKeyPass) ? null : request.TlsKeyPass);
}

internal sealed record HostRequest(
    string RoomId,
    int Port,
    string Username,
    string Password,
    string? SignalingMode,
    string? TlsCertFile,
    string? TlsKeyFile,
    string? TlsKeyPass);
internal sealed record JoinRequest(string Url, string RoomId, string Username, string Password);
internal sealed record SendRequest(string Text);
