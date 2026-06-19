// 命令行 Server 入口。它启动 SignalingServer，并保持运行直到收到终止信号。
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
    // 信号处理器必须保持简单；只设置原子标志，让主循环自行停止。
    gStopRequested.store(true);
}

void printUsage() {
    std::cerr << "Usage: server <port>\n";
    std::cerr << "WSS is required. Set SECURECHAT_TLS_CERT_FILE and SECURECHAT_TLS_KEY_FILE to use an existing certificate, or leave both empty to generate a local/LAN certificate.\n";
    std::cerr << "Environment: SECURECHAT_BIND_ADDRESS=127.0.0.1 keeps a reverse-proxy backend local.\n";
}
}

int main(int argc, char** argv) {
    // Server CLI 只负责进程生命周期。SignalingServer 构造后负责监听器、
    // 房间、成员关系和中继。
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

        // 停止 WebSocket 监听器前先通知已连接成员。
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
