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
    internal static extern int chat_host_start(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string serverUrl,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string roomId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string username,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string password);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_join_start(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string url,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string roomId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string username,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string password);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_send_line([MarshalAs(UnmanagedType.LPUTF8Str)] string line);

    // Private text send. Target may be the displayed member name or the member id.
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

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_send_voice([MarshalAs(UnmanagedType.LPUTF8Str)] string filePath);

    // Private voice attachment send.
    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_send_voice_to(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string target,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string filePath);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern void chat_stop();

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern void chat_shutdown();
}
