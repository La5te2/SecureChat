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

// Registers the process-wide callback used by WinUI/Web wrappers to receive native events.
CHAT_API void CHAT_CALL chat_set_event_callback(chat_event_callback callback, void* user_data);
// Starts a Host member and creates room_id on an already running Server.
CHAT_API int CHAT_CALL chat_host_start(const char* server_url, const char* room_id, const char* username, const char* password);
// Starts a Client member and joins room_id through an already running Server.
CHAT_API int CHAT_CALL chat_join_start(const char* url, const char* room_id, const char* username, const char* password);
// Sends a room text line or slash command through the active native session.
CHAT_API int CHAT_CALL chat_send_line(const char* line);
// Sends a text line or slash attachment command to one member name/id.
CHAT_API int CHAT_CALL chat_send_line_to(const char* target, const char* line);
// Broadcasts one attachment of the selected media kind.
CHAT_API int CHAT_CALL chat_send_image(const char* file_path);
// Sends one image attachment to one member name/id.
CHAT_API int CHAT_CALL chat_send_image_to(const char* target, const char* file_path);
CHAT_API int CHAT_CALL chat_send_file(const char* file_path);
// Sends one generic file attachment to one member name/id.
CHAT_API int CHAT_CALL chat_send_file_to(const char* target, const char* file_path);
CHAT_API int CHAT_CALL chat_send_voice(const char* file_path);
// Sends one voice attachment to one member name/id.
CHAT_API int CHAT_CALL chat_send_voice_to(const char* target, const char* file_path);
// Stops the active Host or Client session without unloading the native module.
CHAT_API void CHAT_CALL chat_stop();
// Final process-exit cleanup for GUI hosts. This clears callback state and
// releases retired native objects that are intentionally kept after normal stop.
CHAT_API void CHAT_CALL chat_shutdown();

#ifdef __cplusplus
}
#endif
