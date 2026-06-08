#pragma once

#ifdef _WIN32
#define CHAT_API __declspec(dllexport)
#define CHAT_CALL __stdcall
#else
#define CHAT_API
#define CHAT_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef void(CHAT_CALL* chat_event_callback)(const char* kind, const char* message, void* user_data);

CHAT_API void CHAT_CALL chat_set_event_callback(chat_event_callback callback, void* user_data);
CHAT_API int CHAT_CALL chat_host_start(const char* room_id, int port, const char* username, const char* password);
CHAT_API int CHAT_CALL chat_join_start(const char* url, const char* room_id, const char* username, const char* password);
// Returned UTF-8 pointers are thread-local scratch buffers. Copy the string before
// calling another CHAT API function on the same thread.
CHAT_API const char* CHAT_CALL chat_discover_rooms_json(const char* room_id, int timeout_ms);
CHAT_API int CHAT_CALL chat_send_line(const char* line);
CHAT_API int CHAT_CALL chat_send_image(const char* file_path);
CHAT_API int CHAT_CALL chat_send_file(const char* file_path);
CHAT_API int CHAT_CALL chat_send_voice(const char* file_path);
CHAT_API void CHAT_CALL chat_stop();
// Final process-exit cleanup for GUI hosts. This clears callback state and
// releases retired native objects that are intentionally kept after normal stop.
CHAT_API void CHAT_CALL chat_shutdown();

#ifdef __cplusplus
}
#endif
