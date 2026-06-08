#include "attachment_transfer.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <iterator>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace chat::attachment {
namespace {
constexpr std::size_t maxImageFileBytes = 10 * 1024 * 1024;
constexpr std::size_t maxTextFileBytes = 50 * 1024 * 1024;
constexpr std::size_t maxVoiceFileBytes = 100 * 1024 * 1024;
constexpr std::size_t transferChunkBytes = 64 * 1024;

std::atomic_uint64_t gTransferCounter = 0;

// Keep UI-facing paths UTF-8 so Windows code pages cannot corrupt Chinese names.
std::string pathToUtf8(const std::filesystem::path& path) {
    return path.u8string();
}

std::string trimCopy(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

const char* defaultFileName(Kind kind) {
    switch (kind) {
    case Kind::Image: return "image";
    case Kind::Text: return "file.txt";
    case Kind::Voice: return "voice.wav";
    }
    return "file";
}

std::size_t maxBytes(Kind kind) {
    switch (kind) {
    case Kind::Image: return maxImageFileBytes;
    case Kind::Text: return maxTextFileBytes;
    case Kind::Voice: return maxVoiceFileBytes;
    }
    return maxTextFileBytes;
}

const char* limitError(Kind kind) {
    switch (kind) {
    case Kind::Image: return "image file is larger than 10 MB";
    case Kind::Text: return "text file is larger than 50 MB";
    case Kind::Voice: return "voice clip is larger than 100 MB";
    }
    return "file is too large";
}

const char* label(Kind kind) {
    switch (kind) {
    case Kind::Image: return "image";
    case Kind::Text: return "text";
    case Kind::Voice: return "voice";
    }
    return "file";
}

bool hasPrefix(const std::vector<unsigned char>& bytes, const std::vector<unsigned char>& magic) {
    return bytes.size() >= magic.size() &&
           std::equal(magic.begin(), magic.end(), bytes.begin());
}

bool hasImageSignature(const std::vector<unsigned char>& bytes) {
    static const std::vector<unsigned char> png = {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a};
    static const std::vector<unsigned char> jpg = {0xff, 0xd8, 0xff};
    static const std::vector<unsigned char> bmp = {'B', 'M'};
    return hasPrefix(bytes, png) || hasPrefix(bytes, jpg) || hasPrefix(bytes, bmp);
}

bool hasWaveSignature(const std::vector<unsigned char>& bytes) {
    return bytes.size() >= 12 &&
           bytes[0] == 'R' && bytes[1] == 'I' && bytes[2] == 'F' && bytes[3] == 'F' &&
           bytes[8] == 'W' && bytes[9] == 'A' && bytes[10] == 'V' && bytes[11] == 'E';
}

bool hasExpectedSignature(const std::vector<unsigned char>& bytes, Kind kind) {
    switch (kind) {
    case Kind::Image: return hasImageSignature(bytes);
    case Kind::Voice: return hasWaveSignature(bytes);
    case Kind::Text: return true;
    }
    return true;
}

const char* signatureError(Kind kind) {
    switch (kind) {
    case Kind::Image: return "image file header is not PNG, JPEG, or BMP";
    case Kind::Voice: return "voice clip header is not WAV";
    case Kind::Text: return "file header is not supported";
    }
    return "file header is not supported";
}

void validateSignatureOrThrow(const std::vector<unsigned char>& bytes, Kind kind) {
    if (!hasExpectedSignature(bytes, kind)) {
        throw std::runtime_error(signatureError(kind));
    }
}

} // namespace

std::filesystem::path pathFromUtf8(const std::string& path) {
    return std::filesystem::u8path(path);
}

std::string fileNameFromPath(const std::string& path) {
    const auto pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

std::string safeTransferName(const std::string& name, const std::string& fallback) {
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
    return safe.empty() ? fallback : safe;
}

std::string receiveDirectory(Kind kind) {
    const auto leaf = kind == Kind::Image ? "images" : (kind == Kind::Voice ? "voice" : "files");
    auto dir = std::filesystem::current_path() / "logs" / leaf;
    std::filesystem::create_directories(dir);
    return pathToUtf8(dir);
}

std::string transferPath(const std::string& directory, const std::string& name, const std::string& fallback) {
    const auto safeName = safeTransferName(name, fallback);
    const auto fileName = std::to_string(std::time(nullptr)) + "_" + safeName;
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
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto counter = ++gTransferCounter;
    std::ostringstream out;
    out << "att_" << std::hex << now << "_" << counter;
    return out.str();
}

ReceiveSlot ReceiveStore::stage(
    const std::string& key,
    Kind kind,
    const std::string& transferId,
    const std::string& name,
    std::size_t expectedSize) {
    if (transferId.empty()) {
        throw std::runtime_error("attachment transfer id is missing");
    }
    if (expectedSize == 0) {
        throw std::runtime_error("attachment size is missing");
    }
    if (expectedSize > maxBytes(kind)) {
        throw std::runtime_error(limitError(kind));
    }

    const auto fallback = defaultFileName(kind);
    ReceiveSlot slot;
    slot.kind = kind;
    slot.transferId = transferId;
    slot.name = safeTransferName(name, fallback);
    slot.path = transferPath(receiveDirectory(kind), slot.name, fallback);
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
    // Reject disguised images/voice before the UI or forwarding path treats
    // arbitrary bytes as media. Normal sends use 64 KB first chunks, enough
    // to verify PNG/JPEG/BMP and WAV headers immediately.
    if (slot.receivedSize == 0 && slot.kind != Kind::Text) {
        try {
            validateSignatureOrThrow(bytes, slot.kind);
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
    return hasExpectedSignature(header, kind);
}

std::vector<unsigned char> readFileBytes(const std::string& filePath, Kind kind) {
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
    validateSignatureOrThrow(bytes, kind);
    return bytes;
}

std::vector<rtc::byte> toRtcBytes(const std::vector<unsigned char>& bytes) {
    std::vector<rtc::byte> raw(bytes.size());
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        raw[i] = static_cast<rtc::byte>(bytes[i]);
    }
    return raw;
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

void sendTransferChunks(
    rtc::DataChannel& channel,
    const std::vector<rtc::byte>& raw,
    const Message& meta,
    const std::string& binaryType,
    const std::string& from) {
    Message binary;
    binary.type = binaryType;
    binary.from = from;
    binary.payload = {
        {"transferId", transferIdFromMessage(meta)},
        {"name", meta.name},
        {"mime", meta.mime},
        {"size", static_cast<int>(raw.size())}
    };
    channel.send(binary.toJson());

    for (std::size_t offset = 0; offset < raw.size(); offset += transferChunkBytes) {
        const auto end = (std::min)(offset + transferChunkBytes, raw.size());
        channel.send(rtc::binary(raw.begin() + static_cast<std::ptrdiff_t>(offset), raw.begin() + static_cast<std::ptrdiff_t>(end)));
    }
}

} // namespace chat::attachment
