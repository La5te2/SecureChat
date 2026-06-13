// WebSocket TLS option implementation for WSS and mTLS client certificates.
#include "websocket_config.hpp"

#include <cstdlib>
#include <stdexcept>
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
    // defaults; partial mTLS configuration is rejected below.
    const auto caFile = envValue("SECURECHAT_TLS_CA_FILE");
    const auto certFile = envValue("SECURECHAT_MTLS_CLIENT_CERT_FILE");
    const auto keyFile = envValue("SECURECHAT_MTLS_CLIENT_KEY_FILE");
    const auto keyPass = envValue("SECURECHAT_MTLS_CLIENT_KEY_PASS");

    if (!caFile.empty()) {
        config.caCertificatePemFile = caFile;
    }

    const bool anyClientCertConfigured = !certFile.empty() || !keyFile.empty() || !keyPass.empty();
    if (!anyClientCertConfigured) return;
    if (certFile.empty() || keyFile.empty()) {
        throw std::runtime_error(
            "mTLS client mode requires SECURECHAT_MTLS_CLIENT_CERT_FILE and SECURECHAT_MTLS_CLIENT_KEY_FILE");
    }

    // These files are presented by Host/Client during the TLS handshake when a
    // reverse proxy such as Nginx requires client certificate authentication.
    config.certificatePemFile = certFile;
    config.keyPemFile = keyFile;
    if (!keyPass.empty()) {
        config.keyPemPass = keyPass;
    }
}

bool hasClientCertificate(const rtc::WebSocket::Configuration& config) {
    // Used by status/logging paths to report whether mTLS client auth is configured.
    return config.certificatePemFile.has_value() && config.keyPemFile.has_value();
}

}
