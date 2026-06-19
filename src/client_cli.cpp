// 命令行 Client 入口。它加入已有房间，并把终端输入转发给 ClientSessionCore。
#include "console_utils.hpp"
#include "client_session_core.hpp"

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
    std::cerr << "Usage: client <wss-url> <room> <username> [--daemon]\n";
    std::cerr << "Password source: SECURECHAT_ROOM_PASSWORD, hidden prompt, or stdin.\n";
    std::cerr << "Commands: /image <path>, /file <path>, /voice <path>, /to <member-name> <text|attachment-command>, /quit\n";
    std::cerr << "Options:\n";
    std::cerr << "  --daemon keeps the client connected without reading stdin.\n";
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

    // 非交互 Client 可以通过管道传入一行密码，避免经 argv 暴露。
    // 不可信链路上的信令层仍应使用 WSS。
    if (!isInteractiveInput() && readInputLineUtf8(password) && !password.empty()) {
        return password;
    }

    // 不静默回退到内置密码，也不接受 argv 中的秘密。
    throw std::runtime_error("room password is required");
}

bool hasDaemonFlag(const std::vector<std::string>& args) {
    // Client 默认前台运行；daemon 模式必须显式指定。
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--daemon") return true;
    }
    return false;
}

std::vector<std::string> positionalArgs(const std::vector<std::string>& args) {
    // 去掉选项标志，使 argv 校验只关注 URL、房间和用户名。
    std::vector<std::string> positional;
    positional.reserve(args.size());
    for (const auto& arg : args) {
        if (arg == "--daemon") continue;
        positional.push_back(arg);
    }
    return positional;
}

void waitForDaemonStop(const std::shared_ptr<ClientSessionCore>& session) {
    // daemon 模式没有 stdin 循环；它会等待信号或会话关闭。
    std::signal(SIGINT, handleStopSignal);
    std::signal(SIGTERM, handleStopSignal);

    std::cout << "Daemon mode enabled. Stop with SIGTERM, SIGINT, or kill <pid>." << std::endl;
    while (!gStopRequested.load() && !session->shouldStop()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
}
}

int main(int argc, char** argv) {
    // CLI main 只负责连接参数、密码输入、回调和会话循环。
    // 协议工作位于 ClientSessionCore 内部。
    configureConsoleUtf8();
    const auto rawArgs = commandLineArgsUtf8(argc, argv);
    const auto daemonMode = hasDaemonFlag(rawArgs);
    const auto args = positionalArgs(rawArgs);
    if (args.size() != 4) {
        printUsage();
        return 1;
    }

    try {
        auto session = std::make_shared<ClientSessionCore>(
            args[1],
            args[2],
            args[3],
            roomPasswordFromEnvOrPrompt());
        session->setCallbacks(consoleCallbacks());
        session->start();

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
                std::cout << "[status] Console input closed; stopping client" << std::endl;
            }
        }

        session->stop();
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "[fatal] " << e.what() << std::endl;
        return 1;
    }
}
