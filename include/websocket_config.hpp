#pragma once

#include <rtc/rtc.hpp>

namespace chat::websocket_config {

// Applies optional client-side TLS settings used by WSS and mTLS deployments.
// Server-side TLS is configured separately by SignalingServer.
void applyClientTlsFromEnvironment(rtc::WebSocket::Configuration& config);

// Returns true when the WebSocket client will present a certificate during TLS.
bool hasClientCertificate(const rtc::WebSocket::Configuration& config);

}
