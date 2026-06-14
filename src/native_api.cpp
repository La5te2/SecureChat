// Native C API implementation used by WinUI. It owns process-wide
// Host/Client sessions and translates C++ callbacks into C ABI callbacks.
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

#include "native_api.h"

#include "host_session_core.hpp"
#include "client_session_core.hpp"

#include <rtc/rtc.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <mutex>
#include <cstdint>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {
#ifdef _WIN32
constexpr DWORD exceptionHeapCorruption = 0xC0000374;
#endif
std::recursive_mutex gMutex;
chat_event_callback gCallback = nullptr;
void* gUserData = nullptr;
std::shared_ptr<HostSessionCore> gHostSession;
std::shared_ptr<ClientSessionCore> gPlSession;
std::vector<std::shared_ptr<HostSessionCore>> gRetiredHostSessions;
std::vector<std::shared_ptr<ClientSessionCore>> gRetiredPlSessions;
std::atomic_bool gShutdownCleanupQueued = false;
bool gLoggerInitialized = false;
std::once_flag gCrashHandlerOnce;

// Converts nullable C API strings into safe std::string values.
std::string safeString(const char* value) {
    return value ? value : "";
}

// Emits one event to the managed callback registered by WinUI.
void emitEvent(const char* kind, const std::string& message) {
    chat_event_callback callback = nullptr;
    void* userData = nullptr;
    {
        std::lock_guard<std::recursive_mutex> lock(gMutex);
        callback = gCallback;
        userData = gUserData;
    }

    if (callback) callback(kind, message.c_str(), userData);
}

// Creates native session callbacks that map C++ events to C API event kinds.
ChatCallbacks makeCallbacks() {
    ChatCallbacks callbacks;
    callbacks.onLog = [](const std::string& message) { emitEvent("log", message); };
    callbacks.onError = [](const std::string& message) { emitEvent("error", message); };
    callbacks.onMessage = [](const std::string& message) { emitEvent("message", message); };
    callbacks.onImage = [](const std::string& message) { emitEvent("image", message); };
    callbacks.onFile = [](const std::string& message) { emitEvent("file", message); };
    callbacks.onVoice = [](const std::string& message) { emitEvent("voice", message); };
    callbacks.onStatus = [](const std::string& message) { emitEvent("status", message); };
    return callbacks;
}

// Initializes libdatachannel logging once for the native process.
void initLoggerOnce() {
    if (!gLoggerInitialized) {
        rtc::InitLogger(rtc::LogLevel::Info);
        gLoggerInitialized = true;
    }
}

// Locates the directory containing native.dll for crash reports and logs.
std::filesystem::path moduleDirectory() {
#ifdef _WIN32
    HMODULE module = nullptr;
    if (GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(&moduleDirectory),
            &module)) {
        char path[MAX_PATH] = {};
        const DWORD length = GetModuleFileNameA(module, path, MAX_PATH);
        if (length > 0 && length < MAX_PATH) {
            return std::filesystem::path(path).parent_path();
        }
    }
#endif
    return std::filesystem::current_path();
}

#ifdef _WIN32
// Resolves an exception address to the loaded module that contains it.
std::string moduleNameForAddress(const void* address) {
    if (!address) return "";

    HMODULE module = nullptr;
    if (!GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            static_cast<LPCSTR>(address),
            &module)) {
        return "";
    }

    char path[MAX_PATH] = {};
    const DWORD length = GetModuleFileNameA(module, path, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) return "";

    std::ostringstream stream;
    stream << path << "+0x"
           << std::hex
           << (reinterpret_cast<std::uintptr_t>(address) - reinterpret_cast<std::uintptr_t>(module));
    return stream.str();
}
#endif

// Formats a timestamp suitable for crash-report file names.
std::string timestampForFile() {
    const auto now = std::chrono::system_clock::now();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    const std::time_t time = std::chrono::system_clock::to_time_t(now);
    std::tm tm = {};
#ifdef _WIN32
    localtime_s(&tm, &time);
#else
    localtime_r(&time, &tm);
#endif
    std::ostringstream stream;
    stream << std::put_time(&tm, "%Y%m%d_%H%M%S_") << std::setw(3) << std::setfill('0') << ms.count();
    return stream.str();
}

// Writes a best-effort native crash report without throwing outward.
void writeNativeCrashReport(const std::string& source, const std::string& detail) {
    static std::atomic_flag writing = ATOMIC_FLAG_INIT;
    if (writing.test_and_set()) return;

    try {
        const auto directory = moduleDirectory() / "cr";
        std::filesystem::create_directories(directory);
        const auto path = directory / (timestampForFile() + "_native.log");
        std::ofstream file(path, std::ios::out | std::ios::trunc);
        file << "SecureChat native crash report\n";
        file << "source: " << source << "\n";
        file << "module_directory: " << moduleDirectory().string() << "\n\n";
        file << detail << "\n";
    }
    catch (...) {
    }
}

#ifdef _WIN32
// Managed handlers cannot catch fatal faults below the P/Invoke boundary.
// Record native crash details before Windows tears the process down.
// Captures fatal Windows exceptions before normal unhandled-exception dispatch.
LONG CALLBACK nativeVectoredExceptionHandler(EXCEPTION_POINTERS* exceptionInfo) {
    const auto code = exceptionInfo && exceptionInfo->ExceptionRecord
        ? exceptionInfo->ExceptionRecord->ExceptionCode
        : 0;
    if (code != EXCEPTION_ACCESS_VIOLATION &&
        code != exceptionHeapCorruption &&
        code != EXCEPTION_ILLEGAL_INSTRUCTION &&
        code != EXCEPTION_STACK_OVERFLOW &&
        code != EXCEPTION_ARRAY_BOUNDS_EXCEEDED) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    std::ostringstream detail;
    const auto address = exceptionInfo && exceptionInfo->ExceptionRecord
        ? exceptionInfo->ExceptionRecord->ExceptionAddress
        : nullptr;
    detail << "exception_code: 0x" << std::hex << code << "\n";
    detail << "exception_address: " << address << "\n";
    detail << "exception_module: " << moduleNameForAddress(address) << "\n";
    writeNativeCrashReport("VectoredExceptionHandler", detail.str());
    return EXCEPTION_CONTINUE_SEARCH;
}

// Captures fatal Windows exceptions that reach the process unhandled filter.
LONG WINAPI nativeUnhandledExceptionFilter(EXCEPTION_POINTERS* exceptionInfo) {
    std::ostringstream detail;
    const auto code = exceptionInfo && exceptionInfo->ExceptionRecord
        ? exceptionInfo->ExceptionRecord->ExceptionCode
        : 0;
    const auto address = exceptionInfo && exceptionInfo->ExceptionRecord
        ? exceptionInfo->ExceptionRecord->ExceptionAddress
        : nullptr;
    detail << "exception_code: 0x" << std::hex << code << "\n";
    detail << "exception_address: " << address << "\n";
    detail << "exception_module: " << moduleNameForAddress(address) << "\n";
    writeNativeCrashReport("SetUnhandledExceptionFilter", detail.str());
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif

// Records uncaught C++ exceptions before delegating to process abort.
void nativeTerminateHandler() {
    std::string detail = "std::terminate was called.";
    if (auto exception = std::current_exception()) {
        try {
            std::rethrow_exception(exception);
        }
        catch (const std::exception& e) {
            detail = std::string("unhandled C++ exception: ") + e.what();
        }
        catch (...) {
            detail = "unhandled non-std C++ exception";
        }
    }
    writeNativeCrashReport("std::terminate", detail);
    std::abort();
}

// Installs native crash-report hooks once per process.
void installNativeCrashHandlersOnce() {
    std::call_once(gCrashHandlerOnce, []() {
#ifdef _WIN32
        // Vectored handlers run before the unhandled filter, which gives heap
        // corruption and access violations a better chance to leave a report.
        AddVectoredExceptionHandler(1, nativeVectoredExceptionHandler);
        SetUnhandledExceptionFilter(nativeUnhandledExceptionFilter);
#endif
        std::set_terminate(nativeTerminateHandler);
    });
}

// Keeps a bounded tail of retired sessions alive for in-flight callbacks.
void trimRetiredObjects() {
    constexpr std::size_t maxRetiredObjects = 8;
    if (gRetiredHostSessions.size() > maxRetiredObjects) {
        gRetiredHostSessions.erase(gRetiredHostSessions.begin());
    }
    if (gRetiredPlSessions.size() > maxRetiredObjects) {
        gRetiredPlSessions.erase(gRetiredPlSessions.begin());
    }
}

// Destroys retired native objects once no managed UI callback should run again.
void clearRetiredObjectsForShutdown() {
    gRetiredPlSessions.clear();
    gRetiredHostSessions.clear();
}

// Stops current sessions and moves them aside until callbacks drain.
void retireActiveObjects() {
    if (gHostSession) {
        gHostSession->stop();
        gRetiredHostSessions.push_back(std::move(gHostSession));
    }
    if (gPlSession) {
        gPlSession->stop();
        gRetiredPlSessions.push_back(std::move(gPlSession));
    }
    trimRetiredObjects();
}
}

// Registers the managed event callback used by WinUI.
void CHAT_CALL chat_set_event_callback(chat_event_callback callback, void* user_data) {
    installNativeCrashHandlersOnce();
    std::lock_guard<std::recursive_mutex> lock(gMutex);
    gCallback = callback;
    gUserData = user_data;
}

// Updates the environment table used by the native CRT. C# Environment APIs do
// not reliably update std::getenv's copy on Windows, so WinUI calls this for
// member PKI settings before creating HostSessionCore/ClientSessionCore.
int CHAT_CALL chat_set_environment_variable(const char* name, const char* value) {
    installNativeCrashHandlersOnce();
    const auto key = safeString(name);
    const auto next = safeString(value);
    if (key.empty()) return 0;

#ifdef _WIN32
    return _putenv_s(key.c_str(), next.c_str()) == 0 ? 1 : 0;
#else
    if (next.empty()) {
        return unsetenv(key.c_str()) == 0 ? 1 : 0;
    }
    return setenv(key.c_str(), next.c_str(), 1) == 0 ? 1 : 0;
#endif
}

// Starts a Host participant against an already-running Server.
// Server is the only long-lived listener; Host remains a room member and should
// not open its own signaling listen port.
int CHAT_CALL chat_host_start(const char* server_url, const char* room_id, const char* username, const char* password) {
    installNativeCrashHandlersOnce();

    try {
        initLoggerOnce();
        {
            std::lock_guard<std::recursive_mutex> lock(gMutex);
            retireActiveObjects();
        }

        const std::string serverUrl = safeString(server_url);
        const std::string roomId = safeString(room_id);
        const std::string hostName = safeString(username).empty() ? "host" : safeString(username);
        const std::string roomPassword = safeString(password);
        if (serverUrl.empty()) {
            emitEvent("error", "Server URL is required");
            return 0;
        }
        if (roomPassword.empty()) {
            emitEvent("error", "Room password is required");
            return 0;
        }

        auto hostSession = std::make_shared<HostSessionCore>(
            serverUrl,
            roomId,
            hostName,
            roomPassword);
        {
            std::lock_guard<std::recursive_mutex> lock(gMutex);
            gHostSession = hostSession;
            gHostSession->setCallbacks(makeCallbacks());
        }

        hostSession->start();
        emitEvent("status", "Hosting room through " + serverUrl);
        return 1;
    }
    catch (const std::exception& e) {
        std::lock_guard<std::recursive_mutex> lock(gMutex);
        retireActiveObjects();
        emitEvent("error", e.what());
        return 0;
    }
}

// Starts a client session by connecting to an existing signaling server.
int CHAT_CALL chat_join_start(const char* url, const char* room_id, const char* username, const char* password) {
    installNativeCrashHandlersOnce();
    try {
        initLoggerOnce();
        {
            std::lock_guard<std::recursive_mutex> lock(gMutex);
            retireActiveObjects();
        }

        const std::string roomPassword = safeString(password);
        if (roomPassword.empty()) {
            emitEvent("error", "Room password is required");
            return 0;
        }

        auto plSession = std::make_shared<ClientSessionCore>(
            safeString(url),
            safeString(room_id),
            safeString(username),
            roomPassword);
        {
            std::lock_guard<std::recursive_mutex> lock(gMutex);
            gPlSession = plSession;
            gPlSession->setCallbacks(makeCallbacks());
        }
        plSession->start();
        return 1;
    }
    catch (const std::exception& e) {
        std::lock_guard<std::recursive_mutex> lock(gMutex);
        retireActiveObjects();
        emitEvent("error", e.what());
        return 0;
    }
}

// Sends one text or slash-command line through the active Host/Client session.
int CHAT_CALL chat_send_line(const char* line) {
    installNativeCrashHandlersOnce();
    try {
        const auto text = safeString(line);
        std::shared_ptr<HostSessionCore> hostSession;
        std::shared_ptr<ClientSessionCore> plSession;
        {
            std::lock_guard<std::recursive_mutex> lock(gMutex);
            hostSession = gHostSession;
            plSession = gPlSession;
        }
        if (hostSession && !hostSession->shouldStop()) {
            hostSession->sendLine(text);
            return 1;
        }
        if (plSession && !plSession->shouldStop()) {
            plSession->sendLine(text);
            return 1;
        }
        emitEvent("error", "No active session");
        return 0;
    }
    catch (const std::exception& e) {
        emitEvent("error", e.what());
        return 0;
    }
}

// Sends one text or slash-command line to a selected member. Empty target keeps room broadcast.
int CHAT_CALL chat_send_line_to(const char* target, const char* line) {
    installNativeCrashHandlersOnce();
    try {
        const auto targetText = safeString(target);
        const auto text = safeString(line);
        std::shared_ptr<HostSessionCore> hostSession;
        std::shared_ptr<ClientSessionCore> plSession;
        {
            std::lock_guard<std::recursive_mutex> lock(gMutex);
            hostSession = gHostSession;
            plSession = gPlSession;
        }
        if (hostSession && !hostSession->shouldStop()) {
            hostSession->sendLineTo(targetText, text);
            return 1;
        }
        if (plSession && !plSession->shouldStop()) {
            plSession->sendLineTo(targetText, text);
            return 1;
        }
        emitEvent("error", "No active session");
        return 0;
    }
    catch (const std::exception& e) {
        emitEvent("error", e.what());
        return 0;
    }
}

// Sends an image file through the active Host/Client session.
int CHAT_CALL chat_send_image(const char* file_path) {
    installNativeCrashHandlersOnce();
    try {
        const auto filePath = safeString(file_path);
        std::shared_ptr<HostSessionCore> hostSession;
        std::shared_ptr<ClientSessionCore> plSession;
        {
            std::lock_guard<std::recursive_mutex> lock(gMutex);
            hostSession = gHostSession;
            plSession = gPlSession;
        }
        if (hostSession && !hostSession->shouldStop()) {
            return hostSession->sendImage(filePath) ? 1 : 0;
        }
        if (plSession && !plSession->shouldStop()) {
            return plSession->sendImage(filePath) ? 1 : 0;
        }
        emitEvent("error", "No active session");
        return 0;
    }
    catch (const std::exception& e) {
        emitEvent("error", e.what());
        return 0;
    }
}

// Sends one image file to a selected member display name through the active session.
int CHAT_CALL chat_send_image_to(const char* target, const char* file_path) {
    installNativeCrashHandlersOnce();
    try {
        const auto targetText = safeString(target);
        const auto filePath = safeString(file_path);
        std::shared_ptr<HostSessionCore> hostSession;
        std::shared_ptr<ClientSessionCore> plSession;
        {
            std::lock_guard<std::recursive_mutex> lock(gMutex);
            hostSession = gHostSession;
            plSession = gPlSession;
        }
        if (hostSession && !hostSession->shouldStop()) {
            return hostSession->sendImageTo(targetText, filePath) ? 1 : 0;
        }
        if (plSession && !plSession->shouldStop()) {
            return plSession->sendImageTo(targetText, filePath) ? 1 : 0;
        }
        emitEvent("error", "No active session");
        return 0;
    }
    catch (const std::exception& e) {
        emitEvent("error", e.what());
        return 0;
    }
}

// Sends a text handout file through the active Host/Client session.
int CHAT_CALL chat_send_file(const char* file_path) {
    installNativeCrashHandlersOnce();
    try {
        const auto filePath = safeString(file_path);
        std::shared_ptr<HostSessionCore> hostSession;
        std::shared_ptr<ClientSessionCore> plSession;
        {
            std::lock_guard<std::recursive_mutex> lock(gMutex);
            hostSession = gHostSession;
            plSession = gPlSession;
        }
        if (hostSession && !hostSession->shouldStop()) {
            return hostSession->sendTextFile(filePath) ? 1 : 0;
        }
        if (plSession && !plSession->shouldStop()) {
            return plSession->sendTextFile(filePath) ? 1 : 0;
        }
        emitEvent("error", "No active session");
        return 0;
    }
    catch (const std::exception& e) {
        emitEvent("error", e.what());
        return 0;
    }
}

// Sends one generic text-file attachment to a selected member display name.
int CHAT_CALL chat_send_file_to(const char* target, const char* file_path) {
    installNativeCrashHandlersOnce();
    try {
        const auto targetText = safeString(target);
        const auto filePath = safeString(file_path);
        std::shared_ptr<HostSessionCore> hostSession;
        std::shared_ptr<ClientSessionCore> plSession;
        {
            std::lock_guard<std::recursive_mutex> lock(gMutex);
            hostSession = gHostSession;
            plSession = gPlSession;
        }
        if (hostSession && !hostSession->shouldStop()) {
            return hostSession->sendTextFileTo(targetText, filePath) ? 1 : 0;
        }
        if (plSession && !plSession->shouldStop()) {
            return plSession->sendTextFileTo(targetText, filePath) ? 1 : 0;
        }
        emitEvent("error", "No active session");
        return 0;
    }
    catch (const std::exception& e) {
        emitEvent("error", e.what());
        return 0;
    }
}

// Sends a short voice clip through the active Host/Client session.
int CHAT_CALL chat_send_voice(const char* file_path) {
    installNativeCrashHandlersOnce();
    try {
        const auto filePath = safeString(file_path);
        std::shared_ptr<HostSessionCore> hostSession;
        std::shared_ptr<ClientSessionCore> plSession;
        {
            std::lock_guard<std::recursive_mutex> lock(gMutex);
            hostSession = gHostSession;
            plSession = gPlSession;
        }
        if (hostSession && !hostSession->shouldStop()) {
            return hostSession->sendVoice(filePath) ? 1 : 0;
        }
        if (plSession && !plSession->shouldStop()) {
            return plSession->sendVoice(filePath) ? 1 : 0;
        }
        emitEvent("error", "No active session");
        return 0;
    }
    catch (const std::exception& e) {
        emitEvent("error", e.what());
        return 0;
    }
}

// Sends one voice attachment to a selected member display name.
int CHAT_CALL chat_send_voice_to(const char* target, const char* file_path) {
    installNativeCrashHandlersOnce();
    try {
        const auto targetText = safeString(target);
        const auto filePath = safeString(file_path);
        std::shared_ptr<HostSessionCore> hostSession;
        std::shared_ptr<ClientSessionCore> plSession;
        {
            std::lock_guard<std::recursive_mutex> lock(gMutex);
            hostSession = gHostSession;
            plSession = gPlSession;
        }
        if (hostSession && !hostSession->shouldStop()) {
            return hostSession->sendVoiceTo(targetText, filePath) ? 1 : 0;
        }
        if (plSession && !plSession->shouldStop()) {
            return plSession->sendVoiceTo(targetText, filePath) ? 1 : 0;
        }
        emitEvent("error", "No active session");
        return 0;
    }
    catch (const std::exception& e) {
        emitEvent("error", e.what());
        return 0;
    }
}

// Stops all active native session objects.
void CHAT_CALL chat_stop() {
    installNativeCrashHandlersOnce();
    std::lock_guard<std::recursive_mutex> lock(gMutex);
    retireActiveObjects();
    emitEvent("status", "Session stopped");
}

// Performs final cleanup when the GUI process is closing.
void CHAT_CALL chat_shutdown() {
    installNativeCrashHandlersOnce();
    {
        std::lock_guard<std::recursive_mutex> lock(gMutex);
        gCallback = nullptr;
        gUserData = nullptr;
        retireActiveObjects();
    }

    // WebSocket close callbacks can arrive after stop(). Retired objects stay
    // alive briefly, but cleanup runs off the WinUI close path so clicking the
    // window close button does not freeze the desktop shell.
    if (!gShutdownCleanupQueued.exchange(true)) {
        std::thread([]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(1200));
            std::lock_guard<std::recursive_mutex> lock(gMutex);
            clearRetiredObjectsForShutdown();
            gShutdownCleanupQueued.store(false);
        }).detach();
    }
}
