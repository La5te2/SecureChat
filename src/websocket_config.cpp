// WSS 服务器证书信任使用的 WebSocket TLS 选项实现。
#include "websocket_config.hpp"

#include "common.hpp"

#include <cstdlib>
#include <string>

namespace chat::websocket_config {
namespace {
std::string envValue(const char* name) {
    // 环境变量让 TLS 选择不进入命令行参数。
    const char* value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
}
}

void applyClientTlsFromEnvironment(rtc::WebSocket::Configuration& config) {
    // Host/Client 打开 WSS 前调用该函数。变量为空时保留 libdatachannel 默认值，
    // 并使用平台信任存储。
    // 保持传输帧上限与协议解析器预算一致。否则带 PKI 的较大帧
    // 例如 room_members 可能在应用解析器看到消息前关闭公网 WSS Client。
    config.maxMessageSize = chat::protocol::MaxSignalingMessageBytes;
    const auto caFile = envValue("SECURECHAT_LOCAL_TLS_CA");

    if (!caFile.empty()) {
        config.caCertificatePemFile = caFile;
    }
}

}
