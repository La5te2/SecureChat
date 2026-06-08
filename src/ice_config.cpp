#include "ice_config.hpp"

#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

namespace {
constexpr uint16_t defaultPortBegin = 32768;
constexpr uint16_t defaultPortEnd = 60999;
constexpr const char* defaultIceServers = "stun:stun.cloudflare.com:3478";

std::string envValue(const char* name) {
    const char* value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
}

uint16_t envPort(const char* name, uint16_t fallback) {
    const auto value = envValue(name);
    if (value.empty()) return fallback;

    try {
        const auto parsed = std::stoi(value);
        if (parsed > 0 && parsed <= 65535) {
            return static_cast<uint16_t>(parsed);
        }
    }
    catch (...) {
    }
    return fallback;
}

std::vector<std::string> splitIceServers(std::string value) {
    for (auto& ch : value) {
        if (ch == ';' || ch == '\n' || ch == '\r' || ch == '\t') {
            ch = ',';
        }
    }

    std::vector<std::string> servers;
    std::stringstream input(value);
    std::string item;
    while (std::getline(input, item, ',')) {
        const auto first = item.find_first_not_of(' ');
        if (first == std::string::npos) continue;
        const auto last = item.find_last_not_of(' ');
        servers.push_back(item.substr(first, last - first + 1));
    }
    return servers;
}
}

rtc::Configuration makePeerConfiguration() {
    rtc::Configuration config;
    config.disableAutoNegotiation = true;
    config.portRangeBegin = envPort("SECURECHAT_ICE_PORT_BEGIN", defaultPortBegin);
    config.portRangeEnd = envPort("SECURECHAT_ICE_PORT_END", defaultPortEnd);
    if (config.portRangeBegin > config.portRangeEnd) {
        config.portRangeBegin = defaultPortBegin;
        config.portRangeEnd = defaultPortEnd;
    }

    auto servers = envValue("SECURECHAT_ICE_SERVERS");
    if (servers.empty()) {
        servers = defaultIceServers;
    }

    for (const auto& server : splitIceServers(servers)) {
        try {
            config.iceServers.emplace_back(server);
        }
        catch (...) {
        }
    }

    return config;
}
