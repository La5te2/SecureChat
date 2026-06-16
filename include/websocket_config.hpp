// WebSocket 客户端 TLS 配置工具。Host/Client 连接使用私有或自签名服务器 CA
// 的 WSS 入口时会使用它。
#pragma once

#include <rtc/rtc.hpp>

namespace chat::websocket_config {

// 应用 WSS 部署可选的客户端侧 TLS 信任设置。
// Server 侧 TLS 由 SignalingServer 单独配置。
void applyClientTlsFromEnvironment(rtc::WebSocket::Configuration& config);

}
