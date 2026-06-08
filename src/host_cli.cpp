#include "console_utils.hpp"
#include "host_session_core.hpp"
#include "lan_discovery.hpp"
#include "signaling_server.hpp"

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
    std::cerr << "Usage: host <room> <port> [username] [--daemon]\n";
    std::cerr << "Password source: SECURECHAT_ROOM_PASSWORD, hidden prompt, or stdin.\n";
    std::cerr << "Commands: /image <path>, /file <path>, /voice <path>, /quit\n";
    std::cerr << "Options: --daemon keeps the room running without reading stdin.\n";
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

    // Daemon launch scripts can pass the password through a short-lived pipe.
    // This avoids storing the secret in the child process environment.
    if (!isInteractiveInput() && readInputLineUtf8(password) && !password.empty()) {
        return password;
    }

    // Do not silently fall back to a built-in password or accept argv secrets.
    // Non-interactive daemon runs must use stdin or SECURECHAT_ROOM_PASSWORD.
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
        if (arg != "--daemon") positional.push_back(arg);
    }
    return positional;
}

void waitForDaemonStop(const std::shared_ptr<HostSessionCore>& session) {
    std::signal(SIGINT, handleStopSignal);
    std::signal(SIGTERM, handleStopSignal);

    std::cout << "Daemon mode enabled. Stop with SIGTERM, SIGINT, or kill <pid>." << std::endl;
    while (!gStopRequested.load() && !session->shouldStop()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
}

void runSession(
    const std::shared_ptr<HostSessionCore>& session,
    LanRoomDiscoveryResponder& lan,
    SignalingServer& signaling,
    const std::string& roomId,
    const std::string& wsUrl,
    bool daemonMode) {
    session->setCallbacks(consoleCallbacks());
    session->start();
    lan.start();

    std::cout << "Hosting " << roomId << " on " << wsUrl << std::endl;
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

    lan.stop();
    session->stop();
    signaling.closeAllRooms("host disconnected");
    signaling.stop();
}
}

int main(int argc, char** argv) {
    configureConsoleUtf8();
    const auto rawArgs = commandLineArgsUtf8(argc, argv);
    const auto daemonMode = hasDaemonFlag(rawArgs);
    const auto args = positionalArgs(rawArgs);
    if (args.size() < 3 || args.size() > 4) {
        printUsage();
        return 1;
    }

    try {
        const auto roomId = args[1];
        const auto port = static_cast<uint16_t>(std::stoi(args[2]));
        const auto username = args.size() > 3 && !args[3].empty() ? args[3] : std::string("host");
        const auto password = roomPasswordFromEnvOrPrompt();

        SignalingServer signaling(port);
        const std::string wsUrl = signaling.urlScheme() + "://127.0.0.1:" + std::to_string(signaling.port());
        rtc::WebSocket::Configuration loopbackConfig;
        // The host connects back to its own signaling server. With a public
        // certificate, 127.0.0.1 will not match the certificate hostname, so
        // only this loopback client disables TLS verification.
        if (signaling.urlScheme() == "wss") {
            loopbackConfig.disableTlsVerification = true;
            loopbackConfig.connectionTimeout = std::chrono::seconds(15);
        }
        auto session = std::make_shared<HostSessionCore>(wsUrl, roomId, username, password, loopbackConfig);
        LanRoomDiscoveryResponder lan(roomId, signaling.port(), username);
        runSession(session, lan, signaling, roomId, wsUrl, daemonMode);
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "[fatal] " << e.what() << std::endl;
        return 1;
    }
}
