#include "console_utils.hpp"
#include "client_session_core.hpp"

#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <stdexcept>
#include <vector>

namespace {
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
    std::cerr << "Usage: client <ws-url> <room> <username>\n";
    std::cerr << "Password source: SECURECHAT_ROOM_PASSWORD, hidden prompt, or stdin.\n";
    std::cerr << "Commands: /image <path>, /file <path>, /voice <path>, /quit\n";
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
}

int main(int argc, char** argv) {
    configureConsoleUtf8();
    const auto args = commandLineArgsUtf8(argc, argv);
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

        std::string line;
        while (!session->shouldStop() && readInputLineUtf8(line)) {
            if (line == "/quit" || line == "/exit") break;
            session->sendLine(line);
        }

        session->stop();
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "[fatal] " << e.what() << std::endl;
        return 1;
    }
}
