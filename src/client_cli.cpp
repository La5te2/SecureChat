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
    gStopRequested.store(true);
}

ChatCallbacks consoleCallbacks() {
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
    std::cerr << "Usage: client <ws-url> <room> <username> [--daemon]\n";
    std::cerr << "Password source: SECURECHAT_ROOM_PASSWORD, hidden prompt, or stdin.\n";
    std::cerr << "Commands: /image <path>, /file <path>, /voice <path>, /quit\n";
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
    // Keep secrets out of argv. Command-line arguments are visible through
    // shell history and process listings, so only env/prompt sources are used.
    auto password = envValue("SECURECHAT_ROOM_PASSWORD");
    if (!password.empty()) {
        clearEnvValue("SECURECHAT_ROOM_PASSWORD");
        return password;
    }

    if (readPasswordLineUtf8("Room password: ", password) && !password.empty()) {
        return password;
    }

    // Non-interactive clients can pipe one password line without exposing it
    // through argv. The signaling layer still requires WSS on untrusted links.
    if (!isInteractiveInput() && readInputLineUtf8(password) && !password.empty()) {
        return password;
    }

    // Do not silently fall back to a built-in password or accept argv secrets.
    throw std::runtime_error("room password is required");
}

bool hasDaemonFlag(const std::vector<std::string>& args) {
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--daemon") return true;
    }
    return false;
}

std::vector<std::string> positionalArgs(const std::vector<std::string>& args) {
    std::vector<std::string> positional;
    positional.reserve(args.size());
    for (const auto& arg : args) {
        if (arg == "--daemon") continue;
        positional.push_back(arg);
    }
    return positional;
}

void waitForDaemonStop(const std::shared_ptr<ClientSessionCore>& session) {
    std::signal(SIGINT, handleStopSignal);
    std::signal(SIGTERM, handleStopSignal);

    std::cout << "Daemon mode enabled. Stop with SIGTERM, SIGINT, or kill <pid>." << std::endl;
    while (!gStopRequested.load() && !session->shouldStop()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
}
}

int main(int argc, char** argv) {
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
            while (!session->shouldStop() && readInputLineUtf8(line)) {
                if (line == "/quit" || line == "/exit") break;
                session->sendLine(line);
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
