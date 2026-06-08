using System;
using System.Runtime.InteropServices;

namespace chat;

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
        [MarshalAs(UnmanagedType.LPUTF8Str)] string roomId,
        int port,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string username,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string password);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_join_start(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string url,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string roomId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string username,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string password);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    private static extern IntPtr chat_discover_rooms_json(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string roomId,
        int timeoutMs);

    internal static string ChatDiscoverRoomsJson(string roomId, int timeoutMs)
    {
        var ptr = chat_discover_rooms_json(roomId, timeoutMs);
        return ptr == IntPtr.Zero ? "[]" : Marshal.PtrToStringUTF8(ptr) ?? "[]";
    }

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_send_line([MarshalAs(UnmanagedType.LPUTF8Str)] string line);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_send_image([MarshalAs(UnmanagedType.LPUTF8Str)] string filePath);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_send_file([MarshalAs(UnmanagedType.LPUTF8Str)] string filePath);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern int chat_send_voice([MarshalAs(UnmanagedType.LPUTF8Str)] string filePath);

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern void chat_stop();

    [DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
    internal static extern void chat_shutdown();
}
