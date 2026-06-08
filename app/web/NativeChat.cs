using System.Runtime.InteropServices;
using System.Text.Json;

namespace SecureChat.Web;

internal sealed record ChatEvent(string Kind, string Message, string? Url = null, string? Name = null, string? Sender = null);
internal sealed record RegisteredMedia(string Path, string ContentType, string Name);

internal sealed class MediaRegistry
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, RegisteredMedia> media = new();

    public string Register(string path, string kind)
    {
        var id = Guid.NewGuid().ToString("N");
        media[id] = new RegisteredMedia(path, ContentType(kind, path), System.IO.Path.GetFileName(path));
        return "/media/" + id;
    }

    public bool TryGet(string id, out RegisteredMedia registered)
    {
        return media.TryGetValue(id, out registered!);
    }

    private static string ContentType(string kind, string path)
    {
        if (kind == "voice") return "audio/wav";
        if (kind == "image")
        {
            return System.IO.Path.GetExtension(path).ToLowerInvariant() switch
            {
                ".png" => "image/png",
                ".bmp" => "image/bmp",
                _ => "image/jpeg"
            };
        }
        return "text/plain; charset=utf-8";
    }
}

internal sealed class ChatEventBus
{
    private readonly object sync = new();
    private readonly List<System.Threading.Channels.Channel<ChatEvent>> subscribers = new();

    public System.Threading.Channels.ChannelReader<ChatEvent> Subscribe(CancellationToken cancellationToken)
    {
        var channel = System.Threading.Channels.Channel.CreateUnbounded<ChatEvent>();
        lock (sync)
        {
            subscribers.Add(channel);
        }

        cancellationToken.Register(() =>
        {
            lock (sync)
            {
                subscribers.Remove(channel);
            }
            channel.Writer.TryComplete();
        });

        return channel.Reader;
    }

    public void Publish(string kind, string message, string? url = null, string? name = null, string? sender = null)
    {
        var chatEvent = new ChatEvent(kind, message, url, name, sender);
        System.Threading.Channels.Channel<ChatEvent>[] snapshot;
        lock (sync)
        {
            snapshot = subscribers.ToArray();
        }

        foreach (var channel in snapshot)
        {
            channel.Writer.TryWrite(chatEvent);
        }
    }
}

internal static partial class NativeChat
{
    private static ChatEventBus? eventBus;
    private static MediaRegistry? mediaRegistry;
    private static readonly ChatEventCallback Callback = OnNativeEvent;
    private static readonly Dictionary<string, Queue<string>> PendingAttachmentSenders = new(StringComparer.OrdinalIgnoreCase);

    internal static void Initialize(ChatEventBus bus, MediaRegistry media)
    {
        eventBus = bus;
        mediaRegistry = media;
        chat_set_event_callback(Callback, IntPtr.Zero);
    }

    internal static int HostStart(string roomId, int port, string username, string password)
    {
        return chat_host_start(roomId, port, username, password);
    }

    internal static int JoinStart(string url, string roomId, string username, string password)
    {
        return chat_join_start(url, roomId, username, password);
    }

    internal static string DiscoverRoomsJson(string roomId, int timeoutMs)
    {
        var ptr = chat_discover_rooms_json(roomId, timeoutMs);
        return ptr == IntPtr.Zero ? "[]" : Marshal.PtrToStringUTF8(ptr) ?? "[]";
    }

    internal static int SendLine(string line)
    {
        return chat_send_line(line);
    }

    internal static int SendFile(string kind, string path)
    {
        return kind.ToLowerInvariant() switch
        {
            "image" => chat_send_image(path),
            "voice" => chat_send_voice(path),
            _ => chat_send_file(path)
        };
    }

    internal static void Stop()
    {
        chat_stop();
    }

    internal static void Shutdown()
    {
        chat_set_event_callback(null, IntPtr.Zero);
        chat_shutdown();
    }

    private static void OnNativeEvent(IntPtr kindPtr, IntPtr messagePtr, IntPtr userData)
    {
        var kind = Marshal.PtrToStringUTF8(kindPtr) ?? "status";
        var message = Marshal.PtrToStringUTF8(messagePtr) ?? "";
        if (kind == "message")
        {
            RememberAttachmentSender(message);
        }

        if (kind is "image" or "file" or "voice" && File.Exists(message))
        {
            var url = mediaRegistry?.Register(message, kind);
            eventBus?.Publish(kind, message, url, Path.GetFileName(message), TakeAttachmentSender(kind));
            return;
        }

        eventBus?.Publish(kind, message);
    }

    private static void RememberAttachmentSender(string message)
    {
        try
        {
            using var document = JsonDocument.Parse(message);
            var root = document.RootElement;
            var type = root.TryGetProperty("type", out var typeValue) ? typeValue.GetString() ?? "" : "";
            var kind = type.ToLowerInvariant() switch
            {
                "image_meta" => "image",
                "voice_meta" => "voice",
                "file_meta" => "file",
                _ => ""
            };
            if (kind.Length == 0) return;

            var sender = root.TryGetProperty("from", out var fromValue) ? fromValue.GetString() ?? "" : "";
            if (root.TryGetProperty("payload", out var payload) &&
                payload.ValueKind == JsonValueKind.Object &&
                payload.TryGetProperty("displayName", out var displayName))
            {
                sender = displayName.GetString() ?? sender;
            }
            if (string.IsNullOrWhiteSpace(sender)) return;

            if (!PendingAttachmentSenders.TryGetValue(kind, out var queue))
            {
                queue = new Queue<string>();
                PendingAttachmentSenders[kind] = queue;
            }
            queue.Enqueue(sender);
        }
        catch
        {
        }
    }

    private static string TakeAttachmentSender(string kind)
    {
        if (!PendingAttachmentSenders.TryGetValue(kind, out var queue) || queue.Count == 0)
        {
            return "";
        }
        return queue.Dequeue();
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void ChatEventCallback(IntPtr kind, IntPtr message, IntPtr userData);

    [DllImport("native", CallingConvention = CallingConvention.Winapi)]
    private static extern void chat_set_event_callback(ChatEventCallback? callback, IntPtr userData);

    [DllImport("native", CallingConvention = CallingConvention.Winapi)]
    private static extern int chat_host_start(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string roomId,
        int port,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string username,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string password);

    [DllImport("native", CallingConvention = CallingConvention.Winapi)]
    private static extern int chat_join_start(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string url,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string roomId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string username,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string password);

    [DllImport("native", CallingConvention = CallingConvention.Winapi)]
    private static extern IntPtr chat_discover_rooms_json(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string roomId,
        int timeoutMs);

    [DllImport("native", CallingConvention = CallingConvention.Winapi)]
    private static extern int chat_send_line([MarshalAs(UnmanagedType.LPUTF8Str)] string line);

    [DllImport("native", CallingConvention = CallingConvention.Winapi)]
    private static extern int chat_send_image([MarshalAs(UnmanagedType.LPUTF8Str)] string filePath);

    [DllImport("native", CallingConvention = CallingConvention.Winapi)]
    private static extern int chat_send_file([MarshalAs(UnmanagedType.LPUTF8Str)] string filePath);

    [DllImport("native", CallingConvention = CallingConvention.Winapi)]
    private static extern int chat_send_voice([MarshalAs(UnmanagedType.LPUTF8Str)] string filePath);

    [DllImport("native", CallingConvention = CallingConvention.Winapi)]
    private static extern void chat_stop();

    [DllImport("native", CallingConvention = CallingConvention.Winapi)]
    private static extern void chat_shutdown();
}
