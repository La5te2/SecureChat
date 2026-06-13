// Command-line Server entry point. It starts SignalingServer and keeps it alive
// until a termination signal is received.
#include "console_utils.hpp"
#include "signaling_server.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {
std::atomic_bool gStopRequested = false;

void handleStopSignal(int) {
    // Signal handlers must stay simple; set an atomic flag and let main loop stop.
    gStopRequested.store(true);
}

void printUsage() {
    std::cerr << "Usage: server <port>\n";
    std::cerr << "Environment: SECURECHAT_SIGNALING_TLS=1 plus SECURECHAT_TLS_CERT_FILE and SECURECHAT_TLS_KEY_FILE enables WSS.\n";
    std::cerr << "Environment: SECURECHAT_BIND_ADDRESS=127.0.0.1 keeps a reverse-proxy backend local.\n";
}
}

int main(int argc, char** argv) {
    // Server CLI owns only process lifetime. SignalingServer handles listener,
    // rooms, membership, and relay after construction.
    configureConsoleUtf8();
    const auto args = commandLineArgsUtf8(argc, argv);
    if (args.size() != 2) {
        printUsage();
        return 1;
    }

    try {
        const auto port = static_cast<uint16_t>(std::stoi(args[1]));
        SignalingServer signaling(port);

        std::signal(SIGINT, handleStopSignal);
        std::signal(SIGTERM, handleStopSignal);

        std::cout << "SecureChat Server running on "
                  << signaling.urlScheme() << "://<configured-bind-address>:" << signaling.port() << std::endl;
        std::cout << "This process is an untrusted signaling coordinator, not a visible room member." << std::endl;
        std::cout << "Stop with SIGTERM, SIGINT, or Ctrl+C." << std::endl;

        while (!gStopRequested.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
        }

        // Notify connected members before stopping the WebSocket listener.
        signaling.closeAllRooms("server stopped");
        signaling.stop();
        std::cout << "Server stopped." << std::endl;
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "[fatal] " << e.what() << std::endl;
        return 1;
    }
}
