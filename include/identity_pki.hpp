// 应用层 PKI 声明。Host/Client 使用这些 API 将身份证书绑定到
// GKA 公钥和 group-key 封装。
#pragma once

#include "common.hpp"

#include <cstdint>
#include <memory>
#include <string>

namespace chat::identity_pki {

// 成员证书链和身份签名验证通过后的返回结果。
// UI 使用指纹进行显示/复制，它不是秘密值。
struct VerifiedIdentity {
    std::string subject;
    std::string fingerprint;
};

// 应用层 PKI 上下文。它认证 GKA 使用的临时 X25519 密钥，
// 与 TLS 传输证书相互独立。
class IdentityContext {
public:
    IdentityContext();

    // 返回该上下文是否已加载证书、私钥和信任根。
    bool enabled() const;

    // 用于日志/UI 的本地证书可读 subject 和 SHA-256 指纹。
    std::string subject() const;
    std::string fingerprint() const;

    // 签名 Client join 帧，把身份绑定到临时 X25519 密钥。
    json signJoinRoom(
        const std::string& roomId,
        const std::string& username,
        const std::string& publicKey) const;

    // 使用受信任 CA bundle 验证 Client join identity 对象。
    VerifiedIdentity verifyJoinRoom(
        const std::string& roomId,
        const std::string& username,
        const std::string& publicKey,
        const json& identity) const;

    // 为一个贡献式 GKA epoch 签名成员 contribution。
    json signGkaContribution(
        const std::string& roomId,
        std::uint64_t epoch,
        const std::string& memberId,
        const std::string& username,
        const std::string& publicKey,
        const std::string& contribution) const;

    // 验证 contribution 是否由声明的成员身份签名。
    VerifiedIdentity verifyGkaContribution(
        const std::string& roomId,
        std::uint64_t epoch,
        const std::string& memberId,
        const std::string& username,
        const std::string& publicKey,
        const std::string& contribution,
        const json& identity) const;

    // 向 group_key 封装添加 Host identity 和签名。
    void signGroupKeyEnvelope(json& envelope) const;

    // 在解封装 group_key 封装前验证 Host 签名。
    VerifiedIdentity verifyGroupKeyEnvelope(const json& envelope) const;

private:
    struct Data;
    explicit IdentityContext(std::shared_ptr<Data> data);

    std::shared_ptr<Data> mData;

    friend IdentityContext loadFromEnvironment();
};

// 从 SECURECHAT_* 环境变量加载必需的 PKI 身份配置。
IdentityContext loadFromEnvironment();

}
