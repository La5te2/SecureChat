// 附件传输实现。它校验本地文件、净化入站名称、分片载荷并保存接收附件缓存。
#include "attachment_transfer.hpp"

#include "local_paths.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iterator>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <vector>

namespace chat::attachment {
namespace {
constexpr std::size_t defaultAttachmentMaxBytes = 100 * 1024 * 1024;
constexpr std::uintmax_t defaultReceiveCacheBytes = 512ull * 1024ull * 1024ull;

std::atomic_uint64_t gTransferCounter = 0;

// 面向 UI 的路径保持 UTF-8，避免 Windows 代码页破坏中文名称。
std::string pathToUtf8(const std::filesystem::path& path) {
    return path.u8string();
}

std::string trimCopy(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::string lowerAscii(std::string value) {
    for (char& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return value;
}

std::string extensionOf(const std::string& name) {
    const auto fileName = fileNameFromPath(name);
    const auto dot = fileName.find_last_of('.');
    if (dot == std::string::npos || dot == 0 || dot + 1 >= fileName.size()) return "";
    return lowerAscii(fileName.substr(dot));
}

bool hasAllowedExtension(const std::string& name, Kind kind) {
    const auto ext = extensionOf(name);
    switch (kind) {
    case Kind::Image:
        return ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".bmp";
    case Kind::Voice:
        return ext == ".wav";
    case Kind::Text:
        // file 是通用附件通道。格式风险交给后续附件分级、隔离和沙箱处理，
        // 传输层只负责大小、名称净化和端到端加密。
        return true;
    }
    return false;
}

const char* extensionError(Kind kind) {
    switch (kind) {
    case Kind::Image: return "image extension must be .png, .jpg, .jpeg, or .bmp";
    case Kind::Voice: return "voice extension must be WAV";
    case Kind::Text: return "";
    }
    return "file extension is not supported";
}

void validateExtensionOrThrow(const std::string& name, Kind kind) {
    if (!hasAllowedExtension(name, kind)) {
        throw std::runtime_error(extensionError(kind));
    }
}

std::string stemOfLowerAscii(const std::string& name) {
    auto fileName = fileNameFromPath(name);
    const auto dot = fileName.find_last_of('.');
    if (dot != std::string::npos) fileName.resize(dot);
    return lowerAscii(fileName);
}

bool isWindowsReservedName(const std::string& name) {
    const auto stem = stemOfLowerAscii(name);
    if (stem == "con" || stem == "prn" || stem == "aux" || stem == "nul") return true;
    if (stem.size() == 4 && (stem.rfind("com", 0) == 0 || stem.rfind("lpt", 0) == 0)) {
        return stem[3] >= '1' && stem[3] <= '9';
    }
    return false;
}

std::uintmax_t receiveCacheLimitBytes() {
    const char* raw = std::getenv("SECURECHAT_LOGS_MAX_BYTES");
    if (!raw || !*raw) return defaultReceiveCacheBytes;

    try {
        const auto parsed = std::stoull(trimCopy(raw));
        return parsed == 0 ? defaultReceiveCacheBytes : static_cast<std::uintmax_t>(parsed);
    }
    catch (...) {
        return defaultReceiveCacheBytes;
    }
}

std::size_t attachmentMaxBytes() {
    const char* raw = std::getenv("SECURECHAT_ATTACHMENT_MAX_BYTES");
    if (!raw || !*raw) return defaultAttachmentMaxBytes;

    try {
        const auto parsed = std::stoull(trimCopy(raw));
        if (parsed == 0 || parsed > static_cast<unsigned long long>(std::numeric_limits<std::size_t>::max())) {
            return defaultAttachmentMaxBytes;
        }
        return static_cast<std::size_t>(parsed);
    }
    catch (...) {
        return defaultAttachmentMaxBytes;
    }
}

std::filesystem::path receiveRootDirectory() {
    return std::filesystem::current_path() / "logs";
}

void ensurePrivateDirectory(const std::filesystem::path& dir) {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        throw std::runtime_error("could not create attachment cache directory");
    }

    // 在 POSIX 上这会让接收附件缓存仅所有者可访问。在 Windows 上标准权限调用
    // 可能是空操作，因此忽略失败。
    std::filesystem::permissions(
        dir,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace,
        ec);
}

struct CacheFile {
    std::filesystem::path path;
    std::uintmax_t size = 0;
    std::filesystem::file_time_type modified{};
};

std::vector<std::filesystem::path> managedReceiveDirectories(const std::filesystem::path& root) {
    return {
        root / "images",
        root / "voice",
        root / "files"
    };
}

std::uintmax_t pruneReceiveCacheFor(std::uintmax_t incomingBytes) {
    const auto limit = receiveCacheLimitBytes();
    if (incomingBytes > limit) {
        throw std::runtime_error("attachment cache limit is smaller than incoming attachment");
    }

    const auto root = receiveRootDirectory();
    ensurePrivateDirectory(root);
    for (const auto& dir : managedReceiveDirectories(root)) {
        ensurePrivateDirectory(dir);
    }

    std::vector<CacheFile> files;
    std::uintmax_t total = 0;
    std::error_code ec;
    for (const auto& dir : managedReceiveDirectories(root)) {
        if (!std::filesystem::exists(dir, ec)) continue;

        for (const auto& entry : std::filesystem::recursive_directory_iterator(dir, ec)) {
            if (ec) break;
            if (!entry.is_regular_file(ec)) continue;
            const auto size = entry.file_size(ec);
            if (ec) continue;
            total += size;
            files.push_back({entry.path(), size, entry.last_write_time(ec)});
            ec.clear();
        }
    }

    if (total + incomingBytes <= limit) return total;

    std::sort(files.begin(), files.end(), [](const CacheFile& lhs, const CacheFile& rhs) {
        return lhs.modified < rhs.modified;
    });

    for (const auto& file : files) {
        std::filesystem::remove(file.path, ec);
        if (ec) {
            ec.clear();
            continue;
        }
        total = file.size > total ? 0 : total - file.size;
        if (total + incomingBytes <= limit) return total;
    }

    throw std::runtime_error("attachment cache is full; clear logs/ or increase SECURECHAT_LOGS_MAX_BYTES");
}

const char* defaultFileName(Kind kind) {
    switch (kind) {
    case Kind::Image: return "image";
    case Kind::Text: return "file";
    case Kind::Voice: return "voice.wav";
    }
    return "file";
}

std::size_t maxBytes(Kind) {
    return attachmentMaxBytes();
}

std::string limitError(Kind) {
    return "attachment file is larger than SECURECHAT_ATTACHMENT_MAX_BYTES";
}

const char* label(Kind kind) {
    switch (kind) {
    case Kind::Image: return "image";
    case Kind::Text: return "file";
    case Kind::Voice: return "voice";
    }
    return "file";
}

bool hasPrefix(const std::vector<unsigned char>& bytes, const std::vector<unsigned char>& magic) {
    return bytes.size() >= magic.size() &&
           std::equal(magic.begin(), magic.end(), bytes.begin());
}

bool hasPngSignature(const std::vector<unsigned char>& bytes) {
    static const std::vector<unsigned char> png = {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a};
    return hasPrefix(bytes, png);
}

bool hasJpegSignature(const std::vector<unsigned char>& bytes) {
    static const std::vector<unsigned char> jpg = {0xff, 0xd8, 0xff};
    return hasPrefix(bytes, jpg);
}

bool hasBmpSignature(const std::vector<unsigned char>& bytes) {
    static const std::vector<unsigned char> bmp = {'B', 'M'};
    return hasPrefix(bytes, bmp);
}

bool hasImageSignatureForName(const std::vector<unsigned char>& bytes, const std::string& name) {
    // 图片通道必须同时满足扩展名和文件头。尤其 .jpg/.jpeg 只能是 JPEG，
    // 避免把其他格式伪装成 JPEG 后进入图片预览路径。
    const auto ext = extensionOf(name);
    if (ext == ".png") return hasPngSignature(bytes);
    if (ext == ".jpg" || ext == ".jpeg") return hasJpegSignature(bytes);
    if (ext == ".bmp") return hasBmpSignature(bytes);
    return false;
}

bool hasWaveSignature(const std::vector<unsigned char>& bytes) {
    return bytes.size() >= 12 &&
           bytes[0] == 'R' && bytes[1] == 'I' && bytes[2] == 'F' && bytes[3] == 'F' &&
           bytes[8] == 'W' && bytes[9] == 'A' && bytes[10] == 'V' && bytes[11] == 'E';
}

bool hasExpectedSignature(const std::vector<unsigned char>& bytes, Kind kind, const std::string& name) {
    switch (kind) {
    case Kind::Image: return hasImageSignatureForName(bytes, name);
    case Kind::Voice: return hasWaveSignature(bytes);
    case Kind::Text: return true;
    }
    return true;
}

const char* signatureError(Kind kind) {
    switch (kind) {
    case Kind::Image: return "image file header does not match its .png/.jpg/.jpeg/.bmp extension";
    case Kind::Voice: return "voice clip header is not WAV";
    case Kind::Text: return "file header is not supported";
    }
    return "file header is not supported";
}

void validateSignatureOrThrow(const std::vector<unsigned char>& bytes, Kind kind, const std::string& name) {
    if (!hasExpectedSignature(bytes, kind, name)) {
        throw std::runtime_error(signatureError(kind));
    }
}

void applyReceivedFileProtection(const std::string& path) {
#ifdef _WIN32
    // Windows Mark-of-the-Web。使用 ADS 标记网络来源，使资源管理器和部分解析器
    // 后续能把该文件视为来自网络区域。文件系统不支持 ADS 时静默降级。
    std::ofstream zone(pathFromUtf8(path + ":Zone.Identifier"), std::ios::binary | std::ios::trunc);
    if (zone) {
        zone << "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=SecureChat\r\n";
    }
#else
    // POSIX 上保守移除执行位，避免收到的脚本/二进制直接变成可执行文件。
    std::error_code ec;
    auto p = pathFromUtf8(path);
    auto perms = std::filesystem::status(p, ec).permissions();
    if (ec) return;
    perms &= ~std::filesystem::perms::owner_exec;
    perms &= ~std::filesystem::perms::group_exec;
    perms &= ~std::filesystem::perms::others_exec;
    std::filesystem::permissions(p, perms, std::filesystem::perm_options::replace, ec);
#endif
}

} // 匿名命名空间

std::filesystem::path pathFromUtf8(const std::string& path) {
    // 将协议/API 的 UTF-8 转为文件系统路径，不使用当前 Windows ANSI 代码页。
    return std::filesystem::u8path(path);
}

std::string fileNameFromPath(const std::string& path) {
    const auto pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

std::string safeTransferName(const std::string& name, const std::string& fallback) {
    // 入站附件名称只是显示元数据，不是可信路径。选择缓存文件名前先剥离
    // 分隔符和保留名。
    const auto trimmed = trimCopy(name);
    const auto candidate = trimmed.empty() ? fallback : fileNameFromPath(trimmed);
    std::string safe;
    safe.reserve(candidate.size());
    for (char ch : candidate) {
        if (ch == '<' || ch == '>' || ch == ':' || ch == '"' || ch == '/' ||
            ch == '\\' || ch == '|' || ch == '?' || ch == '*' ||
            static_cast<unsigned char>(ch) < 32) {
            safe.push_back('_');
        }
        else {
            safe.push_back(ch);
        }
    }
    while (!safe.empty() && (safe.back() == '.' || safe.back() == ' ')) safe.pop_back();
    if (safe.empty() || isWindowsReservedName(safe)) safe = fallback;

    constexpr std::size_t maxSafeFileNameBytes = 120;
    if (safe.size() > maxSafeFileNameBytes) {
        const auto ext = extensionOf(safe);
        const auto keep = ext.size() < maxSafeFileNameBytes ? maxSafeFileNameBytes - ext.size() : maxSafeFileNameBytes;
        safe = safe.substr(0, keep) + ext;
    }
    return safe;
}

std::string receiveDirectory(Kind kind) {
    // 按类型分开放置接收文件，简化 UI 查找和清理。
    const auto leaf = kind == Kind::Image ? "images" : (kind == Kind::Voice ? "voice" : "files");
    const auto root = receiveRootDirectory();
    ensurePrivateDirectory(root);
    auto dir = root / leaf;
    ensurePrivateDirectory(dir);
    return pathToUtf8(dir);
}

std::string receiveDirectory(Kind kind, const std::string& roomName, const std::string& roomToken) {
    if (roomName.empty() || roomToken.empty()) return receiveDirectory(kind);

    // 接收附件按 room instance 二次分层，避免同名文件和同名房间实例互相混淆。
    const auto leaf = kind == Kind::Image ? "images" : (kind == Kind::Voice ? "voice" : "files");
    auto dir = chat::local_paths::attachmentDirectory(leaf, roomName, roomToken);
    ensurePrivateDirectory(dir);
    return pathToUtf8(dir);
}

std::string transferPath(const std::string& directory, const std::string& name, const std::string& fallback) {
    const auto safeName = safeTransferName(name, fallback);
    const auto unique = ++gTransferCounter;
    const auto fileName = std::to_string(std::time(nullptr)) + "_" + std::to_string(unique) + "_" + safeName;
    return pathToUtf8(pathFromUtf8(directory) / pathFromUtf8(fileName));
}

std::string eventKind(Kind kind) {
    switch (kind) {
    case Kind::Image: return "image";
    case Kind::Text: return "file";
    case Kind::Voice: return "voice";
    }
    return "file";
}

std::size_t maxTransferBytes(Kind kind) {
    return maxBytes(kind);
}

std::size_t expectedSizeFromMeta(const Message& msg, Kind kind) {
    // 元数据中的大小用于接收缓存清理和分片完成检查。
    if (!msg.payload.is_object() || !msg.payload.contains("size")) {
        throw std::runtime_error("attachment meta size is missing");
    }

    const auto& rawSize = msg.payload["size"];
    std::uint64_t size = 0;
    if (rawSize.is_number_unsigned()) {
        size = rawSize.get<std::uint64_t>();
    }
    else if (rawSize.is_number_integer()) {
        const auto signedSize = rawSize.get<std::int64_t>();
        if (signedSize <= 0) throw std::runtime_error("attachment meta size must be positive");
        size = static_cast<std::uint64_t>(signedSize);
    }
    else {
        throw std::runtime_error("attachment meta size must be numeric");
    }

    if (size == 0) throw std::runtime_error("attachment meta size must be positive");
    if (size > maxBytes(kind)) throw std::runtime_error(limitError(kind));
    if (size > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
        throw std::runtime_error("attachment meta size is too large");
    }
    return static_cast<std::size_t>(size);
}

std::string transferIdFromMessage(const Message& msg) {
    if (msg.payload.is_object() && msg.payload.contains("transferId")) {
        const auto& value = msg.payload["transferId"];
        if (!value.is_string()) throw std::runtime_error("attachment transfer id must be a string");
        const auto id = trimCopy(value.get<std::string>());
        if (!id.empty()) return id;
    }

    throw std::runtime_error("attachment transfer id is missing");
}

std::string makeTransferId() {
    // transfer id 只需要在当前进程/会话内唯一。
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto counter = ++gTransferCounter;
    std::ostringstream out;
    out << "att_" << std::hex << now << "_" << counter;
    return out.str();
}

void ReceiveStore::setRoomContext(const std::string& roomName, const std::string& roomToken) {
    std::lock_guard<std::mutex> lock(mMutex);
    mRoomName = roomName;
    mRoomToken = roomToken;
}

ReceiveSlot ReceiveStore::stage(
    const std::string& key,
    Kind kind,
    const std::string& transferId,
    const std::string& name,
    std::size_t expectedSize) {
    // 元数据先于分片到达。先暂存净化后的输出路径和预期大小，
    // 防止后续分片自行选择文件系统目标。
    if (transferId.empty()) {
        throw std::runtime_error("attachment transfer id is missing");
    }
    if (expectedSize == 0) {
        throw std::runtime_error("attachment size is missing");
    }
    if (expectedSize > maxBytes(kind)) {
        throw std::runtime_error(limitError(kind));
    }
    validateExtensionOrThrow(name, kind);
    pruneReceiveCacheFor(expectedSize);

    const auto fallback = defaultFileName(kind);
    ReceiveSlot slot;
    slot.kind = kind;
    slot.transferId = transferId;
    slot.name = safeTransferName(name, fallback);
    slot.path = transferPath(receiveDirectory(kind, mRoomName, mRoomToken), slot.name, fallback);
    slot.expectedSize = expectedSize;
    slot.receivedSize = 0;

    std::lock_guard<std::mutex> lock(mMutex);
    if (mSlots.find(key) != mSlots.end()) {
        throw std::runtime_error("another attachment transfer is already pending from this sender");
    }
    mSlots[key] = slot;
    return slot;
}

bool ReceiveStore::has(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mSlots.find(key) != mSlots.end();
}

std::string ReceiveStore::activeTransferId(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mMutex);
    auto pending = mSlots.find(key);
    return pending == mSlots.end() ? "" : pending->second.transferId;
}

void ReceiveStore::clear(const std::string& key) {
    std::lock_guard<std::mutex> lock(mMutex);
    mSlots.erase(key);
}

ReceiveChunkResult ReceiveStore::appendChunk(const std::string& key, const rtc::binary& data) {
    // 为该发送者的活动传输精确追加一个已解密分片。
    // 完成后清空待处理槽位，使下一个附件必须从新元数据开始。
    std::lock_guard<std::mutex> lock(mMutex);
    auto pending = mSlots.find(key);
    if (pending == mSlots.end()) return {};

    auto& slot = pending->second;
    if (slot.receivedSize + data.size() > maxBytes(slot.kind)) {
        const auto cachePath = slot.path;
        mSlots.erase(pending);
        std::filesystem::remove(pathFromUtf8(cachePath));
        throw std::runtime_error(limitError(slot.kind));
    }

    std::ofstream file(
        pathFromUtf8(slot.path),
        slot.receivedSize == 0 ? std::ios::binary : (std::ios::binary | std::ios::app));
    if (!file) {
        throw std::runtime_error("could not open received attachment cache");
    }

    std::vector<unsigned char> bytes;
    bytes.reserve(data.size());
    for (auto byte : data) {
        bytes.push_back(static_cast<unsigned char>(byte));
    }
    // 在 UI 或转发路径把任意字节当作媒体处理前，拒绝伪装图片/语音。
    // 首分片足以立即验证 PNG/JPEG/BMP 和 WAV 文件头。
    if (slot.receivedSize == 0 && slot.kind != Kind::Text) {
        try {
            validateSignatureOrThrow(bytes, slot.kind, slot.name);
        }
        catch (...) {
            const auto cachePath = slot.path;
            mSlots.erase(pending);
            std::filesystem::remove(pathFromUtf8(cachePath));
            throw;
        }
    }
    file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    file.close();

    slot.receivedSize += bytes.size();

    ReceiveChunkResult result;
    result.found = true;
    result.complete = slot.expectedSize == 0 || slot.receivedSize >= slot.expectedSize;
    if (result.complete && slot.kind != Kind::Text) {
        if (!hasExpectedFileSignature(slot.path, slot.kind)) {
            const auto cachePath = slot.path;
            mSlots.erase(pending);
            std::filesystem::remove(pathFromUtf8(cachePath));
            throw std::runtime_error(signatureError(slot.kind));
        }
    }
    if (result.complete) {
        applyReceivedFileProtection(slot.path);
    }
    result.slot = slot;
    if (result.complete) {
        mSlots.erase(pending);
    }
    return result;
}

bool hasExpectedFileSignature(const std::string& filePath, Kind kind) {
    if (kind == Kind::Text) return true;

    std::ifstream file(pathFromUtf8(filePath), std::ios::binary);
    if (!file) return false;

    std::vector<unsigned char> header(16);
    file.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
    header.resize(static_cast<std::size_t>(file.gcount()));
    return hasExpectedSignature(header, kind, filePath);
}

std::vector<unsigned char> readFileBytes(const std::string& filePath, Kind kind) {
    validateExtensionOrThrow(filePath, kind);

    std::ifstream file(pathFromUtf8(filePath), std::ios::binary);
    if (!file) {
        throw std::runtime_error(std::string("could not open ") + label(kind) + " file");
    }

    std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (bytes.empty()) {
        throw std::runtime_error(std::string(label(kind)) + " file is empty");
    }
    if (bytes.size() > maxBytes(kind)) {
        throw std::runtime_error(limitError(kind));
    }
    validateSignatureOrThrow(bytes, kind, filePath);
    return bytes;
}

std::string base64Encode(const unsigned char* data, std::size_t size) {
    if (size == 0) return "";
    std::string out(static_cast<std::size_t>(4 * ((size + 2) / 3)), '\0');
    const int written = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(out.data()),
        data,
        static_cast<int>(size));
    if (written < 0) throw std::runtime_error("attachment base64 encode failed");
    out.resize(static_cast<std::size_t>(written));
    return out;
}

std::string base64Encode(const std::vector<unsigned char>& data, std::size_t offset, std::size_t size) {
    if (offset > data.size()) throw std::runtime_error("attachment chunk offset is out of range");
    const auto available = data.size() - offset;
    if (size > available) throw std::runtime_error("attachment chunk size is out of range");
    return base64Encode(data.data() + offset, size);
}

rtc::binary base64DecodeToRtcBytes(const std::string& value) {
    if (value.empty()) return {};
    std::vector<unsigned char> decoded(static_cast<std::size_t>(3 * value.size() / 4 + 3));
    const int written = EVP_DecodeBlock(
        decoded.data(),
        reinterpret_cast<const unsigned char*>(value.data()),
        static_cast<int>(value.size()));
    if (written < 0) throw std::runtime_error("attachment base64 decode failed");

    std::size_t padding = 0;
    if (!value.empty() && value[value.size() - 1] == '=') ++padding;
    if (value.size() > 1 && value[value.size() - 2] == '=') ++padding;
    decoded.resize(static_cast<std::size_t>(written) - padding);
    rtc::binary out;
    out.reserve(decoded.size());
    for (auto byte : decoded) {
        out.push_back(static_cast<rtc::byte>(byte));
    }
    return out;
}

Message makeBinaryMeta(
    const std::string& type,
    const std::string& from,
    const std::string& filePath,
    const std::string& mime,
    std::size_t size) {
    Message meta;
    meta.type = type;
    meta.from = from;
    meta.name = fileNameFromPath(filePath);
    meta.mime = mime;
    const auto transferId = makeTransferId();
    meta.payload = {
        {"transferId", transferId},
        {"name", meta.name},
        {"mime", meta.mime},
        {"size", static_cast<int>(size)}
    };
    return meta;
}

Message makeTransferCancel(const std::string& from, const std::string& transferId, const std::string& reason) {
    Message cancel;
    cancel.type = "attachment_cancel";
    cancel.from = from;
    cancel.content = reason;
    cancel.payload = {
        {"transferId", transferId},
        {"reason", reason}
    };
    return cancel;
}

} // 命名空间 chat::attachment
