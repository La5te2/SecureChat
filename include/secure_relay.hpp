// 加密中继声明：room token 路由、贡献式 GKA、房间消息加密和 pairwise 私发加密。
#pragma once

#include "common.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace chat::secure_relay {

// 当前中继密码学：
// - 每个成员为一个 GKA epoch 签名新的随机贡献值。
// - 成员从签名贡献值集合中派生房间群密钥。
// - 每个成员都有临时 X25519 密钥对，用于接收 GKA 状态和双方私发消息。
// - Server 只转发 JSON 封装，永远看不到明文密钥。
inline constexpr const char* EnvelopeType = "encrypted_relay";
inline constexpr const char* GroupKeyType = "group_key";
inline constexpr const char* PairwisePrivateType = "pairwise_private";
inline constexpr const char* GkaContributionType = "gka_contribution";
inline constexpr const char* GkaRequestType = "gka_request";
inline constexpr std::size_t GroupKeyBytes = 32;

struct MemberKeyPair {
    // 原始 X25519 私钥字节保留在本地；publicKey 使用 base64 以便写入 JSON。
    std::vector<unsigned char> privateKey;
    std::string publicKey;
};

// 生成成员 X25519 密钥对。公钥通过信令发送；私钥留在本地 Host/Client 进程中。
MemberKeyPair generateMemberKeyPair();

// 为一个 GKA epoch 生成 base64 编码的 32 字节成员贡献值。
std::string generateGroupContribution();

// 返回群密钥大小是否符合中继加密要求。
bool hasUsableGroupKey(const std::vector<unsigned char>& key);

// 从已验证贡献值数组派生 \(K_G\)。每个 contribution 对象必须包含
// memberId、publicKey、fingerprint 和 contribution。
std::vector<unsigned char> deriveGroupKeyFromContributions(
    const std::string& roomId,
    std::uint64_t epoch,
    const json& contributions);

// 用 Host 的 X25519 公钥加密一个已签名贡献值。Server 按连接状态路由，
// 不能读取贡献值 secret。
json encryptGkaContributionForHost(
    const json& contribution,
    const std::string& roomId,
    const std::string& senderId,
    const std::string& hostPublicKey,
    std::uint64_t epoch);

// 打开一个加密给 Host 的 Client 贡献值。
json decryptGkaContributionForHost(
    const json& envelope,
    const std::string& roomId,
    const std::string& expectedSenderId,
    const std::vector<unsigned char>& hostPrivateKey);

// 使用协商出的房间群密钥加密一个应用协议 Message。
json encryptMessageWithGroupKey(
    const Message& message,
    const std::string& roomId,
    const std::string& senderId,
    const std::string& senderName,
    const std::string& senderKind,
    const std::string& targetId,
    std::uint64_t epoch,
    const std::vector<unsigned char>& groupKey);

// 使用协商出的房间群密钥解密一个中继封装。
Message decryptMessageWithGroupKey(
    const json& envelope,
    const std::string& roomId,
    const std::vector<unsigned char>& groupKey);

// 构造一个双方私发内层消息。结果仍通过外层房间 encrypted_relay 发送，
// 但只有目标成员能解密该正文。
Message encryptMessageForPairwise(
    const Message& message,
    const std::string& roomId,
    const std::string& senderId,
    const std::string& targetId,
    const std::string& targetPublicKey,
    const std::string& senderFingerprint,
    const std::string& targetFingerprint);

// 使用本地 X25519 私钥和此前验证过的发送者/目标证书指纹解密双方私发消息。
Message decryptMessageFromPairwise(
    const Message& wrapper,
    const std::string& roomId,
    const std::string& expectedSenderId,
    const std::string& expectedTargetId,
    const std::vector<unsigned char>& localPrivateKey,
    const std::string& expectedSenderFingerprint,
    const std::string& expectedTargetFingerprint);

// 返回本地重放缓存使用的紧凑 key。它不是秘密值，由已认证封装元数据和
// AEAD nonce/tag 组合而成。
std::string replayIdForEnvelope(const json& envelope);

// 使用某个成员公钥封装已验证 GKA 贡献值集合。Server 只能看到
// 该不透明封装，并转发给目标成员。
json encryptGroupStateForMember(
    const json& groupState,
    const std::string& roomId,
    const std::string& targetId,
    const std::string& targetPublicKey,
    std::uint64_t epoch);

// 使用本成员 X25519 私钥解封装 Host 分发的 GKA 贡献值集合。
// 调用方在派生 \(K_G\) 前验证 contribution 签名。
json decryptGroupStateForMember(
    const json& envelope,
    const std::string& roomId,
    const std::string& clientId,
    const std::vector<unsigned char>& privateKey);

}
