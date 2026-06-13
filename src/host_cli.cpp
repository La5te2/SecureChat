// Command-line Host entry point. It connects to an existing Server and creates
// one room as the first chat member.
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
    // Signal handlers must stay simple; set an atomic flag and let main loop stop.
    gStopRequested.store(true);
}

ChatCallbacks consoleCallbacks() {
    // CLI frontend just prints native events. GUI/Web frontends install different callbacks.
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
    std::cerr << "  host --server <ws-url> <room> [username] [--daemon]\n";
    std::cerr << "Password source: SECURECHAT_ROOM_PASSWORD, hidden prompt, or stdin.\n";
    std::cerr << "Commands: /image <path>, /file <path>, /voice <path>, /to <member> <text|attachment-command>, /quit\n";
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
    // Host defaults to foreground mode; daemon mode is explicit.
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--daemon") return true;
    }
    return false;
}

std::vector<std::string> positionalArgs(const std::vector<std::string>& args) {
    // Remove --daemon and --server <url> so the remaining arguments are room/name.
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
    // Host must connect to an already running Server. The old combined mode is gone.
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
    // Daemon mode has no stdin loop; it waits until a signal or session shutdown.
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
    // Common loop for foreground and daemon Host. The session object owns all
    // WebSocket, PKI, group-key, and relay state.
    session->setCallbacks(consoleCallbacks());
    session->start();

    std::cout << "Hosting " << roomId << " through external Server " << wsUrl << std::endl;
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
}
}

int main(int argc, char** argv) {
    // CLI main only wires arguments, password input, callbacks, and the session loop.
    // Protocol work lives inside HostSessionCore.
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
