// WebSocket client TLS configuration helpers. Host/Client use this when
// connecting to WSS endpoints with a private or self-signed server CA.
#pragma once

#include <rtc/rtc.hpp>

namespace chat::websocket_config {

// Applies optional client-side TLS trust settings used by WSS deployments.
// Server-side TLS is configured separately by SignalingServer.
void applyClientTlsFromEnvironment(rtc::WebSocket::Configuration& config);

}
