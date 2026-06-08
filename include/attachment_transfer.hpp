#pragma once

#include "common.hpp"

#include <rtc/rtc.hpp>

#include <cstddef>
#include <filesystem>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// chat::attachment owns rule-neutral file transport primitives:
// UTF-8 paths, transfer metadata, binary chunking, and receive-side cache state.
namespace chat::attachment {

// Attachment kinds share the same transport path but keep separate limits and UI events.
enum class Kind {
    Image,
    Text,
    Voice
};

// One staged incoming transfer, keyed by the DataChannel sender on Host or by a
// fixed local key on Client. Session code consumes this snapshot to emit UI events.
struct ReceiveSlot {
    Kind kind = Kind::Text;
    std::string transferId;
    std::string name;
    std::string path;
    std::size_t expectedSize = 0;
    std::size_t receivedSize = 0;
};

// Result of appending one binary DataChannel payload into a staged transfer.
struct ReceiveChunkResult {
    bool found = false;
    bool complete = false;
    ReceiveSlot slot;
};

// Tracks pending receive slots and persists their following binary chunks. It
// deliberately knows nothing about Host/Client roles, forwarding, or UI rendering.
class ReceiveStore {
public:
    // Stages metadata from *_meta JSON and chooses the local cache path.
    ReceiveSlot stage(
        const std::string& key,
        Kind kind,
        const std::string& transferId,
        const std::string& name,
        std::size_t expectedSize);
    // Reports whether a sender currently has binary payload expected.
    bool has(const std::string& key) const;
    // Returns the active transfer id for protocol marker validation.
    std::string activeTransferId(const std::string& key) const;
    // Drops any pending transfer for a disconnected sender.
    void clear(const std::string& key);
    // Appends one binary chunk to disk and clears the slot once the transfer is complete.
    ReceiveChunkResult appendChunk(const std::string& key, const rtc::binary& data);

private:
    mutable std::mutex mMutex;
    std::unordered_map<std::string, ReceiveSlot> mSlots;
};

// Builds a filesystem path from UTF-8 text supplied by the C API or protocol layer.
std::filesystem::path pathFromUtf8(const std::string& path);

// Extracts the display file name from a Windows or POSIX path.
std::string fileNameFromPath(const std::string& path);

// Removes path separators and other Windows-invalid characters from incoming metadata.
std::string safeTransferName(const std::string& name, const std::string& fallback);

// Returns the local receive cache directory for one attachment kind.
std::string receiveDirectory(Kind kind);

// Adds a timestamp to avoid overwriting received attachments with the same name.
std::string transferPath(const std::string& directory, const std::string& name, const std::string& fallback);

// Returns the UI/native event kind that corresponds to one attachment kind.
std::string eventKind(Kind kind);

// Returns the maximum transfer size accepted for one attachment kind.
std::size_t maxTransferBytes(Kind kind);

// Extracts and validates the expected binary size from a *_meta payload.
std::size_t expectedSizeFromMeta(const Message& msg, Kind kind);

// Extracts and validates the transfer id from protocol payload.
std::string transferIdFromMessage(const Message& msg);

// Creates a compact id for matching *_meta, *_binary marker, and cancel messages.
std::string makeTransferId();

// Checks whether bytes on disk match the header required by the declared kind.
bool hasExpectedFileSignature(const std::string& filePath, Kind kind);

// Reads a local attachment and enforces the per-kind transfer limit.
std::vector<unsigned char> readFileBytes(const std::string& filePath, Kind kind);

// Converts file bytes into libdatachannel's binary byte container.
std::vector<rtc::byte> toRtcBytes(const std::vector<unsigned char>& bytes);

// Builds the JSON metadata message that must be sent before binary payload chunks.
Message makeBinaryMeta(
    const std::string& type,
    const std::string& from,
    const std::string& filePath,
    const std::string& mime,
    std::size_t size);

// Builds a failure/cancel message so receivers can clear pending transfer UI/state.
Message makeTransferCancel(const std::string& from, const std::string& transferId, const std::string& reason);

// Sends the JSON binary marker followed by fixed-size binary chunks.
void sendTransferChunks(
    rtc::DataChannel& channel,
    const std::vector<rtc::byte>& raw,
    const Message& meta,
    const std::string& binaryType,
    const std::string& from);

} // namespace chat::attachment
