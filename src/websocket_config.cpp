// WebSocket TLS option implementation for WSS server certificate trust.
#include "websocket_config.hpp"

#include "common.hpp"

#include <cstdlib>
#include <string>

namespace chat::websocket_config {
namespace {
std::string envValue(const char* name) {
    // Environment variables keep TLS choices out of command-line arguments.
    const char* value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
}
}

void applyClientTlsFromEnvironment(rtc::WebSocket::Configuration& config) {
    // Host/Client call this before opening WSS. Empty variables keep libdatachannel
    // defaults and use the platform trust store.
    // Keep the transport frame cap aligned with the protocol parser budget.
    // Without this, larger PKI-bearing frames such as room_members can close
    // public WSS clients before the application parser sees the message.
    config.maxMessageSize = chat::protocol::MaxSignalingMessageBytes;
    const auto caFile = envValue("SECURECHAT_TLS_CA_FILE");

    if (!caFile.empty()) {
        config.caCertificatePemFile = caFile;
    }
}

}
