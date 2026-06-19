// 命令行 Host 入口。它连接已有 Server，并作为第一个聊天成员创建房间。
#include "console_utils.hpp"
#include "host_session_core.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {
std::atomic_bool gStopRequested = false;

void handleStopSignal(int) {
    // 信号处理器必须保持简单；只设置原子标志，让主循环自行停止。
    gStopRequested.store(true);
}

ChatCallbacks consoleCallbacks() {
    // CLI 前端只打印 native 事件；GUI/Web 前端会安装不同回调。
    ChatCallbacks callbacks;
    callbacks.onLog = [](const std::string& message) { std::cout << "[log] " << message << std::endl; };
    callbacks.onError = [](const std::string& message) { std::cerr << "[error] " << message << std::endl; };
    callbacks.onMessage = [](const std::string& message) { std::cout << "[message] " << message << std::endl; };
    callbacks.onImage = [](const std::string& message) { std::cout << "[image] " << message << std::endl; };
    callbacks.onFile = [](const std::string& message) { std::cout << "[file] " << message << std::endl; };
    callbacks.onVoice = [](const std::string& message) { std::cout << "[voice] " << message << std::endl; };
    callbacks.onStatus = [](const std::string& message) { std::cout << "[status] " << message << std::endl; };
    return callbacks;
}

void printUsage() {
    std::cerr << "Usage:\n";
    std::cerr << "  host --server <wss-url> <room> [username] [--daemon]\n";
    std::cerr << "Password source: SECURECHAT_ROOM_PASSWORD, hidden prompt, or stdin.\n";
    std::cerr << "Commands: /image <path>, /file <path>, /voice <path>, /to <member-name> <text|attachment-command>, /quit\n";
    std::cerr << "Options:\n";
    std::cerr << "  --daemon keeps the room running without reading stdin.\n";
    std::cerr << "  --server connects this Host as a visible group-owner member to an untrusted Server.\n";
}

std::string envValue(const char* name) {
    const char* value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
}

void clearEnvValue(const char* name) {
#ifdef _WIN32
    _putenv_s(name, "");
#else
    unsetenv(name);
#endif
}

std::string roomPasswordFromEnvOrPrompt() {
    // 避免把秘密放入 argv。命令行参数会出现在 shell 历史和进程列表中，
    // 因此只使用环境变量/交互提示来源。
    auto password = envValue("SECURECHAT_ROOM_PASSWORD");
    if (!password.empty()) {
        clearEnvValue("SECURECHAT_ROOM_PASSWORD");
        return password;
    }

    if (readPasswordLineUtf8("Room password: ", password) && !password.empty()) {
        return password;
    }

    // daemon 启动脚本可以通过短生命周期管道传递密码，
    // 避免把秘密保存在子进程环境中。
    if (!isInteractiveInput() && readInputLineUtf8(password) && !password.empty()) {
        return password;
    }

    // 不静默回退到内置密码，也不接受 argv 中的秘密。
    // 非交互 daemon 运行必须使用 stdin 或 SECURECHAT_ROOM_PASSWORD。
    throw std::runtime_error("room password is required");
}

bool hasDaemonFlag(const std::vector<std::string>& args) {
    // Host 默认前台运行；daemon 模式必须显式指定。
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--daemon") return true;
    }
    return false;
}

std::vector<std::string> positionalArgs(const std::vector<std::string>& args) {
    // 移除 --daemon 和 --server <url>，使剩余参数只包含房间/名称。
    std::vector<std::string> positional;
    positional.reserve(args.size());
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--daemon") continue;
        if (args[i] == "--server") {
            ++i;
            continue;
        }
        positional.push_back(args[i]);
    }
    return positional;
}

std::string serverUrlFromArgs(const std::vector<std::string>& args) {
    // Host 必须连接到已经运行的 Server；合并运行模式已移除。
    for (std::size_t i = 1; i + 1 < args.size(); ++i) {
        if (args[i] == "--server") return args[i + 1];
    }
    return "";
}

bool hasServerFlagWithoutValue(const std::vector<std::string>& args) {
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--server" && i + 1 >= args.size()) return true;
    }
    return false;
}

void waitForDaemonStop(const std::shared_ptr<HostSessionCore>& session) {
    // daemon 模式没有 stdin 循环；它会等待信号或会话关闭。
    std::signal(SIGINT, handleStopSignal);
    std::signal(SIGTERM, handleStopSignal);

    std::cout << "Daemon mode enabled. Stop with SIGTERM, SIGINT, or kill <pid>." << std::endl;
    while (!gStopRequested.load() && !session->shouldStop()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
}

void runExternalServerSession(
    const std::shared_ptr<HostSessionCore>& session,
    const std::string& roomId,
    const std::string& wsUrl,
    bool daemonMode) {
    // 前台和 daemon Host 共用的循环。会话对象拥有所有 WebSocket、PKI、
    // group-key 和中继状态。
    session->setCallbacks(consoleCallbacks());
    session->start();

    std::cout << "Hosting " << roomId << " through external Server " << wsUrl << std::endl;
    if (daemonMode) {
        waitForDaemonStop(session);
    }
    else {
        std::string line;
        bool inputClosed = false;
        while (!session->shouldStop()) {
            if (!readInputLineUtf8(line)) {
                inputClosed = true;
                break;
            }
            if (line == "/quit" || line == "/exit") break;
            session->sendLine(line);
        }
        if (inputClosed && !session->shouldStop()) {
            std::cout << "[status] Console input closed; stopping host" << std::endl;
        }
    }

    session->stop();
}
}

int main(int argc, char** argv) {
    // CLI main 只负责连接参数、密码输入、回调和会话循环。
    // 协议工作位于 HostSessionCore 内部。
    configureConsoleUtf8();
    const auto rawArgs = commandLineArgsUtf8(argc, argv);
    const auto daemonMode = hasDaemonFlag(rawArgs);
    if (hasServerFlagWithoutValue(rawArgs)) {
        printUsage();
        return 1;
    }
    const auto serverUrl = serverUrlFromArgs(rawArgs);
    const auto args = positionalArgs(rawArgs);
    if (serverUrl.empty() || args.size() < 2 || args.size() > 3) {
        printUsage();
        return 1;
    }

    try {
        const auto roomId = args[1];
        const auto username = args.size() > 2 && !args[2].empty() ? args[2] : std::string("host");
        const auto password = roomPasswordFromEnvOrPrompt();

        auto session = std::make_shared<HostSessionCore>(serverUrl, roomId, username, password);
        runExternalServerSession(session, roomId, serverUrl, daemonMode);
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "[fatal] " << e.what() << std::endl;
        return 1;
    }
}
