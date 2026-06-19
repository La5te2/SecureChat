// native.dll 导出的 C ABI。C# 前端通过 P/Invoke 调用这些函数，
// 不依赖 C++ 类布局或名称修饰。
#pragma once

#ifdef _WIN32
// Windows 导出 native.dll 符号并使用 stdcall，使 P/Invoke 签名匹配
// 生成的函数名和栈清理规则。
#define CHAT_API __declspec(dllexport)
#define CHAT_CALL __stdcall
#else
#define CHAT_API
#define CHAT_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

// 事件回调约定：native 代码只在本次调用期间拥有 char* 内存。
// 托管调用方必须在返回前复制字符串。
typedef void(CHAT_CALL* chat_event_callback)(const char* kind, const char* message, void* user_data);

// 注册 WinUI 包装层接收 native 事件所用的进程级回调。
CHAT_API void CHAT_CALL chat_set_event_callback(chat_event_callback callback, void* user_data);
// 在 native runtime 内设置或清除进程环境变量。
// WinUI 在启动会话前调用它，使基于 std::getenv 的 C++ 代码能看到
// GUI 中输入的设置，而不要求从 PowerShell 启动进程。
CHAT_API int CHAT_CALL chat_set_environment_variable(const char* name, const char* value);
// 从 room-dir 加载 room token 和房间级 PKI 后启动 Host。
CHAT_API int CHAT_CALL chat_host_start(
    const char* server_url,
    const char* room_dir,
    const char* username,
    const char* key_pass);
// WinUI 自动生成 logs/certs/<digest>/entrance.scp，并隐藏 room-dir 细节。
CHAT_API int CHAT_CALL chat_host_start_auto(
    const char* server_url,
    const char* room_name,
    const char* username,
    const char* key_pass);
// WinUI 按房间名/用户名查找本机已有 Host room-dir，并重新接管房间。
CHAT_API int CHAT_CALL chat_host_join_existing(
    const char* server_url,
    const char* room_name,
    const char* username,
    const char* key_pass);
// 从 room-dir 加载 room token 和房间级 PKI 后启动 Client。
CHAT_API int CHAT_CALL chat_join_start(
    const char* url,
    const char* room_dir,
    const char* username,
    const char* key_pass);
// WinUI 选择 Host 分发的 entrance.scp 后自动导入并发起 pending join。
CHAT_API int CHAT_CALL chat_join_start_auto(
    const char* url,
    const char* room_name,
    const char* username,
    const char* entrance_file,
    const char* key_pass);
// WinUI 按房间名/用户名查找本机已有 Client room-dir，并加入或重连房间。
CHAT_API int CHAT_CALL chat_join_existing(
    const char* url,
    const char* room_name,
    const char* username,
    const char* key_pass);
// 通过活动 native 会话发送房间文本行或斜杠命令。
CHAT_API int CHAT_CALL chat_send_line(const char* line);
// 向某个成员显示名发送文本行或斜杠附件命令。
CHAT_API int CHAT_CALL chat_send_line_to(const char* target, const char* line);
// 广播一个指定媒体类型的附件。
CHAT_API int CHAT_CALL chat_send_image(const char* file_path);
// 向某个成员显示名发送一个图片附件。
CHAT_API int CHAT_CALL chat_send_image_to(const char* target, const char* file_path);
CHAT_API int CHAT_CALL chat_send_file(const char* file_path);
// 向某个成员显示名发送一个普通文件附件。
CHAT_API int CHAT_CALL chat_send_file_to(const char* target, const char* file_path);
CHAT_API int CHAT_CALL chat_send_voice(const char* file_path);
// 向某个成员显示名发送一个语音附件。
CHAT_API int CHAT_CALL chat_send_voice_to(const char* target, const char* file_path);
// 停止活动 Host 或 Client 会话，但不卸载 native 模块。
CHAT_API void CHAT_CALL chat_stop();
// Host 显式关闭当前 room instance。Client 调用时退化为本地停止。
CHAT_API void CHAT_CALL chat_close_room();
// GUI 宿主进程退出时的最终清理。它清除回调状态，并释放普通 stop 后
// 有意保留的已退役 native 对象。
CHAT_API void CHAT_CALL chat_shutdown();

#ifdef __cplusplus
}
#endif
