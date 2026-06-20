// 本机日志路径实现。这里的目录名只用于用户设备上的文件隔离，
// 不能作为安全认证材料或网络身份使用。
#include "local_paths.hpp"

#include "cert_utils.hpp"

#include <algorithm>
#include <cctype>

namespace chat::local_paths {
namespace {

bool isWindowsReservedName(const std::string& name) {
    std::string lower;
    lower.reserve(name.size());
    for (char ch : name) lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    if (lower == "con" || lower == "prn" || lower == "aux" || lower == "nul") return true;
    if (lower.size() == 4 && (lower.rfind("com", 0) == 0 || lower.rfind("lpt", 0) == 0)) {
        return lower[3] >= '1' && lower[3] <= '9';
    }
    return false;
}

std::string roomTokenDigestPrefix(const std::string& roomToken) {
    // certs 目录已经使用 SHA-256(roomInstanceToken) 的前缀。
    // 附件和文本历史使用同一规则，避免同一房间实例在不同 logs 子目录下出现不同名字。
    return chat::cert_utils::sha256Hex(roomToken).substr(0, 8);
}

} // namespace

std::string sanitizePathComponent(const std::string& value, const std::string& fallback) {
    std::string out;
    out.reserve(value.size());
    for (char ch : value) {
        const auto c = static_cast<unsigned char>(ch);
        if (c < 0x20 || ch == '<' || ch == '>' || ch == ':' || ch == '"' ||
            ch == '/' || ch == '\\' || ch == '|' || ch == '?' || ch == '*' ||
            ch == '.') {
            out.push_back('_');
        }
        else {
            out.push_back(ch == ' ' ? '_' : ch);
        }
    }

    while (!out.empty() && (out.back() == '_' || out.back() == ' ')) out.pop_back();
    if (out.empty() || isWindowsReservedName(out)) out = fallback;
    if (out.size() > 64) out.resize(64);
    return out.empty() ? fallback : out;
}

std::string roomInstanceLabel(const std::string& roomName, const std::string& roomToken) {
    return sanitizePathComponent(roomName, "room") + "_" + roomTokenDigestPrefix(roomToken);
}

std::string userFileStem(const std::string& systemUsername) {
    return sanitizePathComponent(systemUsername, "user");
}

std::filesystem::path logsRoot() {
    return std::filesystem::current_path() / "logs";
}

std::filesystem::path attachmentDirectory(
    const std::string& kind,
    const std::string& roomName,
    const std::string& roomToken) {
    return logsRoot() / kind / roomInstanceLabel(roomName, roomToken);
}

std::filesystem::path textHistoryDatabase(
    const std::string& roomName,
    const std::string& roomToken,
    const std::string& systemUsername) {
    return logsRoot() / "texts" / roomInstanceLabel(roomName, roomToken) / (userFileStem(systemUsername) + ".sqlite3");
}

} // namespace chat::local_paths
