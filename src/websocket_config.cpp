// WSS 服务器证书信任使用的 WebSocket TLS 选项实现。
#include "websocket_config.hpp"

#include "cert_utils.hpp"
#include "common.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace chat::websocket_config {
namespace {
std::string envValue(const char* name) {
    // 环境变量让 TLS 选择不进入命令行参数。
    const char* value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
}

std::string trimCopy(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n\"'");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n\"'");
    return value.substr(first, last - first + 1);
}

std::vector<std::filesystem::path> localCaFilesFromEnvironment() {
    std::vector<std::filesystem::path> files;
    const auto raw = envValue("SECURECHAT_LOCAL_TLS_CA");
    std::size_t start = 0;
    while (start <= raw.size()) {
        const auto end = raw.find(';', start);
        auto item = trimCopy(raw.substr(start, end == std::string::npos ? std::string::npos : end - start));
        if (!item.empty()) files.emplace_back(item);
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return files;
}

bool parseIpv4(const std::string& host, int parts[4]) {
    std::istringstream in(host);
    std::string item;
    for (int i = 0; i < 4; ++i) {
        if (!std::getline(in, item, '.')) return false;
        if (item.empty() || item.size() > 3) return false;
        int value = 0;
        for (char ch : item) {
            if (ch < '0' || ch > '9') return false;
            value = value * 10 + (ch - '0');
        }
        if (value < 0 || value > 255) return false;
        parts[i] = value;
    }
    return in.eof();
}

std::string lowerHostFromUrl(const std::string& url) {
    const auto scheme = url.find("://");
    if (scheme == std::string::npos) return {};
    auto pos = scheme + 3;
    std::string host;
    if (pos < url.size() && url[pos] == '[') {
        const auto end = url.find(']', pos + 1);
        if (end == std::string::npos) return {};
        host = url.substr(pos + 1, end - pos - 1);
    }
    else {
        const auto end = url.find_first_of(":/?#", pos);
        host = url.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
    }
    while (!host.empty() && host.back() == '.') host.pop_back();
    std::transform(host.begin(), host.end(), host.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return host;
}

bool endsWith(const std::string& value, const std::string& suffix) {
    return value.size() >= suffix.size() &&
        value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool isLocalOrLanWssUrl(const std::string& url) {
    if (url.rfind("wss://", 0) != 0) return false;
    const auto host = lowerHostFromUrl(url);
    if (host.empty()) return false;
    if (host == "localhost" || host == "::1") return true;
    if (endsWith(host, ".local")) return true;
    if (host.find('.') == std::string::npos && host.find(':') == std::string::npos) return true;

    int ip[4] = {};
    if (parseIpv4(host, ip)) {
        if (ip[0] == 10 || ip[0] == 127 || ip[0] == 169 && ip[1] == 254) return true;
        if (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) return true;
        if (ip[0] == 192 && ip[1] == 168) return true;
    }
    if (host.rfind("fc", 0) == 0 || host.rfind("fd", 0) == 0 || host.rfind("fe80", 0) == 0) return true;
    return false;
}

std::string localCaBundlePath(const std::vector<std::filesystem::path>& files) {
    if (files.empty()) return {};
    if (files.size() == 1) {
        if (!std::filesystem::exists(files.front())) {
            throw std::runtime_error("SECURECHAT_LOCAL_TLS_CA file does not exist: " + files.front().u8string());
        }
        return files.front().u8string();
    }

    std::string joined;
    std::string bundle;
    for (const auto& file : files) {
        if (!std::filesystem::exists(file)) {
            throw std::runtime_error("SECURECHAT_LOCAL_TLS_CA file does not exist: " + file.u8string());
        }
        std::ifstream in(file, std::ios::binary);
        if (!in) throw std::runtime_error("failed to read SECURECHAT_LOCAL_TLS_CA file: " + file.u8string());
        std::ostringstream content;
        content << in.rdbuf();
        joined += file.u8string();
        joined.push_back('\n');
        bundle += content.str();
        if (!bundle.empty() && bundle.back() != '\n') bundle.push_back('\n');
    }

    const auto digest = chat::cert_utils::sha256Hex(joined + bundle).substr(0, 16);
    auto path = std::filesystem::temp_directory_path() / ("securechat-local-ca-" + digest + ".pem");
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("failed to create local TLS CA bundle: " + path.u8string());
    out << bundle;
    return path.u8string();
}
}

void applyClientTlsFromEnvironment(rtc::WebSocket::Configuration& config) {
    // 保持传输帧上限与协议解析器预算一致。否则带 PKI 的较大帧
    // 例如 room_members 可能在应用解析器看到消息前关闭公网 WSS Client。
    config.maxMessageSize = chat::protocol::MaxSignalingMessageBytes;
}

rtc::WebSocket::Configuration clientConfigForUrl(
    const rtc::WebSocket::Configuration& base,
    const std::string& url) {
    auto config = base;
    applyClientTlsFromEnvironment(config);
    if (!isLocalOrLanWssUrl(url)) return config;

    auto caFiles = localCaFilesFromEnvironment();
    if (caFiles.empty()) {
        throw std::runtime_error(
            "local/LAN WSS relay requires a matching local TLS-CA");
    }
    config.caCertificatePemFile = localCaBundlePath(caFiles);
    return config;
}

}
