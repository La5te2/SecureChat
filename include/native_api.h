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
// 启动 Host 成员，并在已经运行的 Server 上创建 room_id。
CHAT_API int CHAT_CALL chat_host_start(const char* server_url, const char* room_id, const char* username, const char* password);
// 启动 Client 成员，并通过已经运行的 Server 加入 room_id。
CHAT_API int CHAT_CALL chat_join_start(const char* url, const char* room_id, const char* username, const char* password);
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
// GUI 宿主进程退出时的最终清理。它清除回调状态，并释放普通 stop 后
// 有意保留的已退役 native 对象。
CHAT_API void CHAT_CALL chat_shutdown();

#ifdef __cplusplus
}
#endif
