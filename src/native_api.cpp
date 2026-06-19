// WinUI 使用的 native C API 实现。它持有进程级 Host/Client 会话，
// 并把 C++ 回调转换为 C ABI 回调。
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

#include "native_api.h"

#include "cert_generation.hpp"
#include "host_session_core.hpp"
#include "client_session_core.hpp"
#include "pki_application.hpp"

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

// 将可空 C API 字符串转换为安全的 std::string。
std::string safeString(const char* value) {
    return value ? value : "";
}

std::string trimCopy(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

// 向 WinUI 注册的托管回调发送一个事件。
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

// 创建 native 会话回调，将 C++ 事件映射到 C API 事件类型。
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

// 为 native 进程初始化一次 libdatachannel 日志。
void initLoggerOnce() {
    if (!gLoggerInitialized) {
        rtc::InitLogger(rtc::LogLevel::Info);
        gLoggerInitialized = true;
    }
}

// 定位 native.dll 所在目录，用于写入崩溃报告和日志。
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
// 将异常地址解析到包含该地址的已加载模块。
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

// 格式化适合崩溃报告文件名使用的时间戳。
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

// 尽力写入 native 崩溃报告，并避免继续向外抛出异常。
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
// 托管处理器无法捕获 P/Invoke 边界以下的致命故障。
// 在 Windows 终止进程前记录 native 崩溃细节。
// 在普通未处理异常分发前捕获致命 Windows 异常。
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

// 捕获到达进程未处理异常过滤器的致命 Windows 异常。
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

// 在交给进程 abort 前记录未捕获的 C++ 异常。
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

// 每个进程只安装一次 native 崩溃报告 hook。
void installNativeCrashHandlersOnce() {
    std::call_once(gCrashHandlerOnce, []() {
#ifdef _WIN32
        // vectored handler 会先于未处理异常过滤器运行，
        // 因而堆损坏和访问违规更有机会留下报告。
        AddVectoredExceptionHandler(1, nativeVectoredExceptionHandler);
        SetUnhandledExceptionFilter(nativeUnhandledExceptionFilter);
#endif
        std::set_terminate(nativeTerminateHandler);
    });
}

// 保留有限数量的已退役会话，使飞行中的回调仍有有效对象可用。
void trimRetiredObjects() {
    constexpr std::size_t maxRetiredObjects = 8;
    if (gRetiredHostSessions.size() > maxRetiredObjects) {
        gRetiredHostSessions.erase(gRetiredHostSessions.begin());
    }
    if (gRetiredPlSessions.size() > maxRetiredObjects) {
        gRetiredPlSessions.erase(gRetiredPlSessions.begin());
    }
}

// 确认不会再运行托管 UI 回调后，销毁已退役的 native 对象。
void clearRetiredObjectsForShutdown() {
    gRetiredPlSessions.clear();
    gRetiredHostSessions.clear();
}

// 停止当前会话，并把对象移到旁路队列中等待回调排空。
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

// 注册 WinUI 使用的托管事件回调。
void CHAT_CALL chat_set_event_callback(chat_event_callback callback, void* user_data) {
    installNativeCrashHandlersOnce();
    std::lock_guard<std::recursive_mutex> lock(gMutex);
    gCallback = callback;
    gUserData = user_data;
}

// 更新 native CRT 使用的环境变量表。Windows 上 C# Environment API
// 不一定可靠更新 std::getenv 看到的副本，因此 WinUI 会在创建
// HostSessionCore/ClientSessionCore 前用它写入成员 PKI 设置。
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

// 从 room-dir 读取 room token 和房间级 Host PKI，然后创建 Host 会话。
int CHAT_CALL chat_host_start(
    const char* server_url,
    const char* room_dir,
    const char* username,
    const char* key_pass) {
    installNativeCrashHandlersOnce();

    try {
        initLoggerOnce();
        {
            std::lock_guard<std::recursive_mutex> lock(gMutex);
            retireActiveObjects();
        }

        const std::string serverUrl = safeString(server_url);
        const std::string roomDir = safeString(room_dir);
        if (serverUrl.empty()) {
            emitEvent("error", "Server URL is required");
            return 0;
        }
        if (roomDir.empty()) {
            emitEvent("error", "Room certificate directory is required");
            return 0;
        }

        const auto material = chat::certs::loadRoomRuntimeMaterial(
            roomDir,
            safeString(username),
            true);
        auto identity = chat::pki_application::loadFromFiles(
            material.trustStoreFile,
            material.identityCertFile,
            material.identityKeyFile,
            safeString(key_pass));

        auto hostSession = std::make_shared<HostSessionCore>(
            serverUrl,
            material.roomName,
            material.username,
            std::move(identity),
            material.roomInstanceToken,
            roomDir);
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

// WinUI 自动创建房间级证书材料。用户只输入房间名；
// room-dir 和 entrance.scp 路径作为内部实现细节写入 logs/certs/<digest>/。
int CHAT_CALL chat_host_start_auto(
    const char* server_url,
    const char* room_name,
    const char* username,
    const char* key_pass) {
    installNativeCrashHandlersOnce();
    try {
        const auto roomName = trimCopy(safeString(room_name));
        const auto user = trimCopy(safeString(username));
        if (roomName.empty()) {
            emitEvent("error", "Room name is required");
            return 0;
        }
        if (user.empty()) {
            emitEvent("error", "User name is required");
            return 0;
        }

        chat::certs::RoomEntranceCreateOptions options;
        options.roomName = roomName;
        options.roomPhrase = roomName;
        options.hostName = user;
        options.outputRoot = "logs/certs";
        options.memberKeyPassword = safeString(key_pass);
        const auto created = chat::certs::createRoomEntrance(options);
        emitEvent("status", "Entrance created: " + created.entranceFile);
        return chat_host_start(server_url, created.roomDir.c_str(), user.c_str(), key_pass);
    }
    catch (const std::exception& e) {
        emitEvent("error", e.what());
        return 0;
    }
}

// WinUI Host 页“加入房间”：只复用本机已有 Host room-dir。
// 它不会重新创建 entrance.scp，也不会覆盖房间级 Root/Intermediate。
int CHAT_CALL chat_host_join_existing(
    const char* server_url,
    const char* room_name,
    const char* username,
    const char* key_pass) {
    installNativeCrashHandlersOnce();
    try {
        const auto roomDir = chat::certs::findLocalRoomDir(
            safeString(room_name),
            safeString(username),
            "host",
            "logs/certs");
        emitEvent("status", "Local host room loaded: " + roomDir);
        return chat_host_start(server_url, roomDir.c_str(), username, key_pass);
    }
    catch (const std::exception& e) {
        emitEvent("error", e.what());
        return 0;
    }
}

// 从 room-dir 读取 room token 和房间级 Client PKI，
// 然后创建 Client 会话。未安装 Host 签发响应时会明确报缺少链证书。
int CHAT_CALL chat_join_start(
    const char* url,
    const char* room_dir,
    const char* username,
    const char* key_pass) {
    installNativeCrashHandlersOnce();
    try {
        initLoggerOnce();
        {
            std::lock_guard<std::recursive_mutex> lock(gMutex);
            retireActiveObjects();
        }

        const std::string serverUrl = safeString(url);
        const std::string roomDir = safeString(room_dir);
        if (serverUrl.empty()) {
            emitEvent("error", "Server URL is required");
            return 0;
        }
        if (roomDir.empty()) {
            emitEvent("error", "Room certificate directory is required");
            return 0;
        }

        const auto material = chat::certs::loadRoomRuntimeMaterial(
            roomDir,
            safeString(username),
            false,
            false);
        chat::pki_application::IdentityContext identity;
        if (material.identityCertReady) {
            identity = chat::pki_application::loadFromFiles(
                material.trustStoreFile,
                material.identityCertFile,
                material.identityKeyFile,
                safeString(key_pass));
        }

        auto plSession = std::make_shared<ClientSessionCore>(
            serverUrl,
            material.roomName,
            material.username,
            std::move(identity),
            material.roomInstanceToken,
            roomDir,
            safeString(key_pass));
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

// WinUI 自动导入 Host 分发的 entrance.scp。导入后 Client 先进入
// pending join，Host 审批时才收到成员证书链和当前 group key。
int CHAT_CALL chat_join_start_auto(
    const char* url,
    const char* room_name,
    const char* username,
    const char* entrance_file,
    const char* key_pass) {
    installNativeCrashHandlersOnce();
    try {
        const auto roomName = trimCopy(safeString(room_name));
        const auto user = trimCopy(safeString(username));
        const auto entrance = trimCopy(safeString(entrance_file));
        if (roomName.empty()) {
            emitEvent("error", "Room name is required");
            return 0;
        }
        if (user.empty()) {
            emitEvent("error", "User name is required");
            return 0;
        }
        if (entrance.empty()) {
            emitEvent("error", "Entrance file is required");
            return 0;
        }

        const auto roomDir = chat::certs::roomDirForEntrance(entrance, roomName, "logs/certs");
        const auto localRoomDir = std::filesystem::path(roomDir);
        const auto userKeyPath = localRoomDir / (user + "-key.pem");
        if (!std::filesystem::exists(localRoomDir / "room-runtime.json") ||
            !std::filesystem::exists(userKeyPath)) {
            chat::certs::RoomEntranceImportOptions options;
            options.entranceFile = entrance;
            options.roomPhrase = roomName;
            options.username = user;
            options.outputRoot = "logs/certs";
            options.memberKeyPassword = safeString(key_pass);
            const auto imported = chat::certs::importRoomEntrance(options);
            emitEvent("status", "Entrance imported: " + imported.roomDir);
        }
        return chat_join_start(url, roomDir.c_str(), user.c_str(), key_pass);
    }
    catch (const std::exception& e) {
        emitEvent("error", e.what());
        return 0;
    }
}

// WinUI Join 页“加入房间”：只复用本机已有 Client room-dir。
// 如果本机还没有导入 entrance.scp，会明确报错，让用户改点“导入房间”。
int CHAT_CALL chat_join_existing(
    const char* url,
    const char* room_name,
    const char* username,
    const char* key_pass) {
    installNativeCrashHandlersOnce();
    try {
        const auto roomDir = chat::certs::findLocalRoomDir(
            safeString(room_name),
            safeString(username),
            "client",
            "logs/certs");
        emitEvent("status", "Local client room loaded: " + roomDir);
        return chat_join_start(url, roomDir.c_str(), username, key_pass);
    }
    catch (const std::exception& e) {
        emitEvent("error", e.what());
        return 0;
    }
}

// 通过活动 Host/Client 会话发送一行文本或斜杠命令。
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

// 向选定成员发送一行文本或斜杠命令；目标为空时保持房间广播。
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

// 通过活动 Host/Client 会话发送一个图片文件。
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

// 通过活动会话向选定成员显示名发送一个图片文件。
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

// 通过活动 Host/Client 会话发送一个文本资料文件。
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

// 向选定成员显示名发送一个普通文本文件附件。
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

// 通过活动 Host/Client 会话发送一段短语音。
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

// 向选定成员显示名发送一个语音附件。
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

// 停止所有活动 native 会话对象。
void CHAT_CALL chat_stop() {
    installNativeCrashHandlersOnce();
    std::lock_guard<std::recursive_mutex> lock(gMutex);
    retireActiveObjects();
    emitEvent("status", "Session stopped");
}

void CHAT_CALL chat_close_room() {
    installNativeCrashHandlersOnce();
    std::shared_ptr<HostSessionCore> hostSession;
    std::shared_ptr<ClientSessionCore> clientSession;
    {
        std::lock_guard<std::recursive_mutex> lock(gMutex);
        hostSession = gHostSession;
        clientSession = gPlSession;
    }

    if (hostSession && !hostSession->shouldStop()) {
        hostSession->closeRoom();
        return;
    }

    if (clientSession) {
        std::lock_guard<std::recursive_mutex> lock(gMutex);
        retireActiveObjects();
        emitEvent("status", "Session stopped");
        return;
    }

    emitEvent("status", "No active room to close");
}

// GUI 进程关闭时执行最终清理。
void CHAT_CALL chat_shutdown() {
    installNativeCrashHandlersOnce();
    {
        std::lock_guard<std::recursive_mutex> lock(gMutex);
        gCallback = nullptr;
        gUserData = nullptr;
        retireActiveObjects();
    }

    // WebSocket close 回调可能在 stop() 之后到达。
    // 已退役对象会短暂保活，但清理工作离开 WinUI 关闭路径执行，
    // 避免点击窗口关闭按钮时卡住桌面 shell。
    if (!gShutdownCleanupQueued.exchange(true)) {
        std::thread([]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(1200));
            std::lock_guard<std::recursive_mutex> lock(gMutex);
            clearRetiredObjectsForShutdown();
            gShutdownCleanupQueued.store(false);
        }).detach();
    }
}
