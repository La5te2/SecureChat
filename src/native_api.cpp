#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <iphlpapi.h>
#include <Windows.h>
#endif

#include "native_api.h"

#include "host_session_core.hpp"
#include "lan_discovery.hpp"
#include "client_session_core.hpp"
#include "signaling_server.hpp"

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
#include <set>
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
std::unique_ptr<SignalingServer> gSignalingServer;
std::unique_ptr<LanRoomDiscoveryResponder> gLanResponder;
std::shared_ptr<HostSessionCore> gHostSession;
std::shared_ptr<ClientSessionCore> gPlSession;
std::vector<std::unique_ptr<SignalingServer>> gRetiredSignalingServers;
std::vector<std::shared_ptr<HostSessionCore>> gRetiredHostSessions;
std::vector<std::shared_ptr<ClientSessionCore>> gRetiredPlSessions;
std::atomic_bool gShutdownCleanupQueued = false;
bool gLoggerInitialized = false;
std::once_flag gCrashHandlerOnce;
thread_local std::string gReturnedString;

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

#ifdef _WIN32
// Filters out loopback, link-local, and unspecified IPv4 addresses.
bool isUsableIpv4(const std::string& address) {
    return address.rfind("127.", 0) != 0 &&
        address.rfind("169.254.", 0) != 0 &&
        address != "0.0.0.0";
}

// Enumerates local IPv4 addresses that Client clients may be able to reach.
std::vector<std::string> getLocalIpv4Addresses() {
    ULONG bufferSize = 15 * 1024;
    std::vector<unsigned char> buffer(bufferSize);
    IP_ADAPTER_ADDRESSES* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

    ULONG result = GetAdaptersAddresses(
        AF_INET,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        nullptr,
        adapters,
        &bufferSize);

    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(bufferSize);
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        result = GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr,
            adapters,
            &bufferSize);
    }

    std::set<std::string> addresses;
    if (result != NO_ERROR) return {};

    for (auto adapter = adapters; adapter; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp) continue;

        for (auto unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
            auto sockaddr = unicast->Address.lpSockaddr;
            if (!sockaddr || sockaddr->sa_family != AF_INET) continue;

            char text[INET_ADDRSTRLEN] = {};
            auto ipv4 = reinterpret_cast<sockaddr_in*>(sockaddr);
            if (!InetNtopA(AF_INET, &ipv4->sin_addr, text, sizeof(text))) continue;

            std::string address(text);
            if (isUsableIpv4(address)) addresses.insert(address);
        }
    }

    return {addresses.begin(), addresses.end()};
}
#else
// Non-Windows builds currently do not advertise local IPv4 join addresses.
std::vector<std::string> getLocalIpv4Addresses() {
    return {};
}
#endif

// Emits same-machine and LAN join endpoints through the native event callback.
void emitJoinAddresses(const std::string& scheme, const std::string& roomId, int port) {
    emitEvent("status", "Clients can join with:");
    emitEvent("status", "client " + scheme + "://127.0.0.1:" + std::to_string(port) + " " + roomId + "  (same machine)");
    for (const auto& address : getLocalIpv4Addresses()) {
        emitEvent("status", "client " + scheme + "://" + address + ":" + std::to_string(port) + " " + roomId);
    }
}

// Keeps a bounded tail of retired sessions alive for in-flight callbacks.
void trimRetiredObjects() {
    constexpr std::size_t maxRetiredObjects = 8;
    if (gRetiredSignalingServers.size() > maxRetiredObjects) {
        gRetiredSignalingServers.erase(gRetiredSignalingServers.begin());
    }
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
    gRetiredSignalingServers.clear();
}

// Stops current sessions and moves them aside until callbacks drain.
void retireActiveObjects() {
    if (gSignalingServer) {
        gSignalingServer->closeAllRooms("host disconnected");
        gSignalingServer->stop();
        gRetiredSignalingServers.push_back(std::move(gSignalingServer));
    }
    if (gLanResponder) {
        gLanResponder->stop();
        gLanResponder.reset();
    }
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

// Starts a host session and its local signaling/LAN responder services.
int CHAT_CALL chat_host_start(const char* room_id, int port, const char* username, const char* password) {
    installNativeCrashHandlersOnce();
    if (port <= 0 || port > 65535) {
        emitEvent("error", "Invalid port");
        return 0;
    }

    try {
        initLoggerOnce();
        {
            std::lock_guard<std::recursive_mutex> lock(gMutex);
            retireActiveObjects();
        }

        const std::string roomId = safeString(room_id);
        const std::string hostName = safeString(username).empty() ? "host" : safeString(username);
        const std::string roomPassword = safeString(password);
        if (roomPassword.empty()) {
            emitEvent("error", "Room password is required");
            return 0;
        }
        if (lanRoomExists(roomId, 700)) {
            emitEvent("error", "Room name already exists on LAN");
            return 0;
        }

        auto signalingServer = std::make_unique<SignalingServer>(static_cast<uint16_t>(port));
        const auto scheme = signalingServer->urlScheme();
        const std::string wsUrl = scheme + "://127.0.0.1:" + std::to_string(signalingServer->port());
        rtc::WebSocket::Configuration loopbackConfig;
        // The embedded Host connects back to the local signaling server. Public
        // certificates normally do not match 127.0.0.1, so only this internal
        // loopback client skips verification when the server is in WSS mode.
        if (scheme == "wss") {
            loopbackConfig.disableTlsVerification = true;
            loopbackConfig.connectionTimeout = std::chrono::seconds(15);
        }
        auto hostSession = std::make_shared<HostSessionCore>(
            wsUrl,
            roomId,
            hostName,
            roomPassword,
            loopbackConfig);
        auto lanResponder = std::make_unique<LanRoomDiscoveryResponder>(roomId, signalingServer->port(), hostName);
        {
            std::lock_guard<std::recursive_mutex> lock(gMutex);
            gSignalingServer = std::move(signalingServer);
            gHostSession = hostSession;
            gLanResponder = std::move(lanResponder);
            gHostSession->setCallbacks(makeCallbacks());
        }

        hostSession->start();
        gLanResponder->start();
        emitEvent("status", "Hosting room on " + wsUrl);
        emitJoinAddresses(scheme, roomId, port);
        return 1;
    }
    catch (const std::exception& e) {
        std::lock_guard<std::recursive_mutex> lock(gMutex);
        retireActiveObjects();
        emitEvent("error", e.what());
        return 0;
    }
}

// Returns discovered LAN rooms as a thread-local UTF-8 JSON string.
const char* CHAT_CALL chat_discover_rooms_json(const char* room_id, int timeout_ms) {
    installNativeCrashHandlersOnce();
    try {
        gReturnedString = lanRoomsJson(discoverLanRooms(safeString(room_id), timeout_ms));
    }
    catch (const std::exception& e) {
        gReturnedString = std::string("{\"error\":\"") + e.what() + "\"}";
    }
    return gReturnedString.c_str();
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

    // libdatachannel may deliver a few close/ICE callbacks after stop(). Retired
    // objects stay alive briefly, but the cleanup runs off the WinUI close path
    // so clicking the window close button does not freeze the desktop shell.
    if (!gShutdownCleanupQueued.exchange(true)) {
        std::thread([]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(1200));
            std::lock_guard<std::recursive_mutex> lock(gMutex);
            clearRetiredObjectsForShutdown();
            gShutdownCleanupQueued.store(false);
        }).detach();
    }
}
