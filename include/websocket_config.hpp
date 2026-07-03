// WebSocket 客户端 TLS 配置工具。Host/Client 连接使用私有或自签名服务器 CA
// 的 WSS 入口时会使用它。
#pragma once

#include <rtc/rtc.hpp>

namespace chat::websocket_config {

// 应用 WebSocket 客户端通用配置，例如帧大小上限。
// Server 侧 TLS 由 SignalingServer 单独配置。
void applyClientTlsFromEnvironment(rtc::WebSocket::Configuration& config);

// 为指定 URL 生成客户端配置。
// 本地或局域网 WSS 地址必须显式提供 SECURECHAT_LOCAL_TLS_CA，
// 避免把自动生成的自签名证书当作平台默认可信证书。
rtc::WebSocket::Configuration clientConfigForUrl(
    const rtc::WebSocket::Configuration& base,
    const std::string& url);

}
