// WinUI-to-native bridge. These declarations expose C functions from native.dll
// so C# UI code can reuse the C++ session, PKI, relay, and attachment logic.
using System;
using System.Runtime.InteropServices;

namespace chat;

// Thin P/Invoke surface for the C++ session core. UI code should keep policy and
// presentation logic outside this file so native interop stays easy to audit.
internal static class NativeMethods
{
    // Native event strings are transient UTF-8 buffers. Keep them as raw
    // pointers and copy them in the callback before dispatching UI work.
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void ChatEventCallback(
        IntPtr kind,
        IntPtr message,
        IntPtr userData);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern void chat_set_event_callback(ChatEventCallback callback, IntPtr userData);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_set_environment_variable(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string name,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string value);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_list_local_room_dirs(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string roomName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string username,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string role,
        IntPtr outputJson,
        int outputJsonSize);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_get_message_history(IntPtr outputJson, int outputJsonSize);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_host_start(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string serverUrl,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string roomDir,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string username,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string nickname,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string keyPass);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_host_start_auto(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string serverUrl,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string roomName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string username,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string nickname,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string keyPass);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_join_start(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string url,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string roomDir,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string username,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string nickname,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string keyPass);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_join_start_auto(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string url,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string roomName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string username,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string nickname,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string entranceFile,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string keyPass);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_send_line([MarshalAs(UnmanagedType.LPUTF8Str)] string line);

    // Private text send. Target is resolved by the C++ core from a certificate
    // fingerprint prefix of at least 8 hex characters; display names are not routable.
    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_send_line_to(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string target,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string line);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_send_image([MarshalAs(UnmanagedType.LPUTF8Str)] string filePath);

    // Private image attachment send.
    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_send_image_to(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string target,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string filePath);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_send_file([MarshalAs(UnmanagedType.LPUTF8Str)] string filePath);

    // Private generic file attachment send.
    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_send_file_to(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string target,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string filePath);

    // 语音路径由 WinUI 按住录音生成，不来自文件选择器。
    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_send_voice([MarshalAs(UnmanagedType.LPUTF8Str)] string filePath);

    // 私发 WinUI 录音附件。
    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_send_voice_to(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string target,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string filePath);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern void chat_stop();

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern void chat_close_room();

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern void chat_shutdown();
}
