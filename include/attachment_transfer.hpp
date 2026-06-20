// 附件传输声明：本地文件校验、安全接收路径、二进制分片元数据和接收端缓存状态。
#pragma once

#include "common.hpp"

#include <rtc/rtc.hpp>

#include <cstddef>
#include <filesystem>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// chat::attachment 管理与角色无关的文件传输基础能力：
// UTF-8 路径、传输元数据、二进制分片和接收端缓存状态。
namespace chat::attachment {

inline constexpr std::size_t RelayChunkBytes = 192 * 1024;

// 不同附件类型共用同一传输路径，但保留独立限制和 UI 事件类型。
enum class Kind {
    Image,
    Text,
    Voice
};

// 一个已暂存的入站传输，以加密中继发送者 actor id 为键。
// 会话代码读取该快照后向 UI 发出事件。
struct ReceiveSlot {
    Kind kind = Kind::Text;
    std::string transferId;
    std::string name;
    std::string path;
    std::size_t expectedSize = 0;
    std::size_t receivedSize = 0;
};

// 向暂存传输追加一个已解密二进制中继分片后的结果。
struct ReceiveChunkResult {
    bool found = false;
    bool complete = false;
    ReceiveSlot slot;
};

// 跟踪待接收槽位，并把后续二进制分片写入磁盘。
// 该类不感知 Host/Client 角色、转发逻辑或 UI 渲染。
class ReceiveStore {
public:
    // 绑定当前 room instance，使接收附件落入 logs/<kind>/<room>_<roomInstanceTokenDigest前8>/。
    void setRoomContext(const std::string& roomName, const std::string& roomToken);
    // 暂存 *_meta JSON 中的元数据，并选择本地缓存路径。
    ReceiveSlot stage(
        const std::string& key,
        Kind kind,
        const std::string& transferId,
        const std::string& name,
        std::size_t expectedSize);
    // 返回某个发送者当前是否还有待接收的二进制载荷。
    bool has(const std::string& key) const;
    // 返回活动传输 id，用于校验协议标记。
    std::string activeTransferId(const std::string& key) const;
    // 清除断连发送者的所有待接收传输。
    void clear(const std::string& key);
    // 向磁盘追加一个二进制分片；传输完成后清空槽位。
    ReceiveChunkResult appendChunk(const std::string& key, const rtc::binary& data);

private:
    mutable std::mutex mMutex;
    std::string mRoomName;
    std::string mRoomToken;
    std::unordered_map<std::string, ReceiveSlot> mSlots;
};

// 根据 C API 或协议层传入的 UTF-8 文本构造文件系统路径。
std::filesystem::path pathFromUtf8(const std::string& path);

// 从 Windows 或 POSIX 路径中提取用于显示的文件名。
std::string fileNameFromPath(const std::string& path);

// 从入站元数据中移除路径分隔符和 Windows 非法字符。
std::string safeTransferName(const std::string& name, const std::string& fallback);

// 返回某类附件对应的本地接收缓存目录。
std::string receiveDirectory(Kind kind);
std::string receiveDirectory(Kind kind, const std::string& roomName, const std::string& roomToken);

// 添加时间戳，避免同名接收附件互相覆盖。
std::string transferPath(const std::string& directory, const std::string& name, const std::string& fallback);

// 返回某类附件对应的 UI/native 事件类型。
std::string eventKind(Kind kind);

// 返回某类附件允许的最大传输大小。
std::size_t maxTransferBytes(Kind kind);

// 从 *_meta 载荷中提取并校验预期二进制大小。
std::size_t expectedSizeFromMeta(const Message& msg, Kind kind);

// 从协议载荷中提取并校验传输 id。
std::string transferIdFromMessage(const Message& msg);

// 创建紧凑 id，用于匹配 *_meta、*_binary 标记和取消消息。
std::string makeTransferId();

// 检查磁盘文件字节是否符合声明类型要求的文件头。
bool hasExpectedFileSignature(const std::string& filePath, Kind kind);

// 读取本地附件，并执行对应类型的传输大小限制。
std::vector<unsigned char> readFileBytes(const std::string& filePath, Kind kind);

// 为加密中继中的附件分片编码二进制数据。
std::string base64Encode(const unsigned char* data, std::size_t size);
std::string base64Encode(const std::vector<unsigned char>& data, std::size_t offset, std::size_t size);
rtc::binary base64DecodeToRtcBytes(const std::string& value);

// 构造必须先于二进制载荷分片发送的 JSON 元数据消息。
Message makeBinaryMeta(
    const std::string& type,
    const std::string& from,
    const std::string& filePath,
    const std::string& mime,
    std::size_t size);

// 构造失败/取消消息，使接收端清理待传输 UI 和状态。
Message makeTransferCancel(const std::string& from, const std::string& transferId, const std::string& reason);

} // 命名空间 chat::attachment
