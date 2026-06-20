// 证书生成和证书材料解析工具。
// 当前先提供 Server 本地/局域网 WSS 证书生成；后续可继续承载 entrance.scp、
// 房间 Root/Intermediate、成员 CSR 和成员证书签发等证书相关能力。
#pragma once

#include "common.hpp"

#include <string>
#include <vector>

namespace chat::certs {

struct ServerTlsMaterial {
    // libdatachannel WebSocketServer 使用的证书链和私钥 PEM 路径。
    std::string certFile;
    std::string keyFile;
    // 自动生成本地证书时暴露给 Host/Client 信任的本地 CA 路径。
    std::string caFile;
    bool generatedLocal = false;
    bool reusedLocal = false;
};

// 优先使用 SECURECHAT_TLS_CERT_FILE/SECURECHAT_TLS_KEY_FILE 指定的正式证书。
// 两者都为空时，生成或复用 certs/ 下的本地/局域网开发证书。
ServerTlsMaterial resolveServerTlsMaterial();

struct RoomEntranceCreateOptions {
    std::string roomName;
    std::string roomPhrase;
    std::string hostName = "host";
    std::string outputRoot = "logs/certs";
    std::string memberKeyPassword;
};

struct RoomEntranceCreateResult {
    std::string roomDir;
    std::string entranceFile;
    std::string rootCaFile;
    std::string intermediateCaFile;
    std::string hostCertChainFile;
    std::string hostKeyFile;
    std::string roomInstanceTokenDigest;
    std::string rootFingerprint;
    std::string intermediateFingerprint;
    std::string hostFingerprint;
};

struct RoomEntranceImportOptions {
    std::string entranceFile;
    std::string roomPhrase;
    std::string username;
    std::string outputRoot = "logs/certs";
    std::string memberKeyPassword;
};

struct RoomEntranceImportResult {
    std::string roomDir;
    std::string rootCaFile;
    std::string intermediateCaFile;
    std::string memberKeyFile;
    std::string memberCsrFile;
    std::string memberCsrBundleFile;
    std::string roomInstanceTokenDigest;
    std::string rootFingerprint;
    std::string intermediateFingerprint;
};

struct RoomMemberSignOptions {
    std::string roomDir;
    std::string csrFile;
    std::string memberName;
};

struct RoomMemberSignResult {
    std::string memberCertFile;
    std::string memberChainFile;
    std::string signResponseFile;
    std::string memberFingerprint;
};

struct RoomMemberInstallOptions {
    std::string roomDir;
    std::string signResponseFile;
    std::string memberName;
};

struct RoomMemberInstallResult {
    std::string memberCertFile;
    std::string memberChainFile;
    std::string memberFingerprint;
};

struct RoomRuntimeMaterial {
    std::string roomName;
    std::string canonicalRoomName;
    // baseUsername 是用户在 CLI/WinUI 输入的原始名字。
    // username 是房间内部唯一身份名：baseUsername + "_" + PKI 公钥指纹短码。
    std::string baseUsername;
    std::string username;
    std::string roomInstanceToken;
    std::string roomInstanceTokenDigest;
    // 从 entrance.scp 中取出的准入 secret。仅保存在本机 room-runtime，
    // 用于加密 pending CSR 和签发响应，不发送给 Server。
    std::string admissionSecret;
    std::string trustStoreFile;
    std::string identityCertFile;
    std::string identityKeyFile;
    std::string memberCsrBundleFile;
    bool identityCertReady = false;
};

struct LocalRoomDirInfo {
    std::string roomDir;
    std::string roomName;
    std::string roomInstanceTokenDigest;
    long long modifiedTimeUnixMs = 0;
};

// 生成 Host 的房间级 Root/Intermediate、Host 成员证书和加密 entrance.scp。
RoomEntranceCreateResult createRoomEntrance(const RoomEntranceCreateOptions& options);

// 解密 entrance.scp 并返回规范化 JSON 文本，供 CLI 或 UI 展示核验。
std::string inspectRoomEntrance(const std::string& entranceFile, const std::string& roomPhrase);

// 只解密 entrance.scp 并计算该 room instance 的本地 room-dir。
// WinUI 使用它隐藏真实路径，同时避免重复导入覆盖已有成员私钥。
std::string roomDirForEntrance(
    const std::string& entranceFile,
    const std::string& roomPhrase,
    const std::string& outputRoot = "logs/certs");

// 列出所有匹配房间名、用户名和角色的本机 room-dir。WinUI 总是让用户
// 显式选择 room instance，即使只有一个候选项，也避免同名房间自动选错。
std::vector<LocalRoomDirInfo> listLocalRoomDirs(
    const std::string& roomName,
    const std::string& username,
    const std::string& role,
    const std::string& outputRoot = "logs/certs");

// Client 导入 entrance.scp 后，在本机生成成员私钥和 CSR。私钥不会发给 Host。
RoomEntranceImportResult importRoomEntrance(const RoomEntranceImportOptions& options);

// Client 在尚未拿到成员证书链时，用本地 CSR 私钥证明“该 CSR 和本次
// join_room 的临时 X25519 公钥属于同一台机器”。
json makePendingJoinProof(
    const std::string& roomDir,
    const std::string& username,
    const std::string& publicKey,
    const std::string& keyPassword = {});

// 用 entrance.scp 内 admission secret 派生准入信令密钥。
// CSR bundle、pending join proof 和成员证书签发响应走这个 envelope，
// Server 只能转发密文，看不到 CSR PEM、设备声明或签发响应内容。
json encryptAdmissionPayload(
    const std::string& roomDir,
    const std::string& purpose,
    const json& payload);
json decryptAdmissionPayload(
    const std::string& roomDir,
    const std::string& purpose,
    const json& envelope);

// Host 验证 pending join 中携带的 CSR bundle 和 join proof。
// 返回 CSR 公钥指纹，供 UI 显示和当前房间内拒绝列表使用。
std::string verifyPendingJoinRequest(
    const std::string& roomDir,
    const json& csrBundle,
    const json& joinProof,
    const std::string& username,
    const std::string& publicKey);

// Host 批准 pending join 时签发成员证书，并把签发响应交给 Server 转发。
RoomMemberSignResult signPendingRoomMemberCertificate(
    const std::string& roomDir,
    const json& csrBundle,
    const json& joinProof,
    const std::string& username,
    const std::string& publicKey);

// Host 使用房间级 Intermediate CA 签发某个 Client CSR。
RoomMemberSignResult signRoomMemberCertificate(const RoomMemberSignOptions& options);

// Client 验证 Host 的签发响应，并把自己的成员证书链安装到本机房间目录。
RoomMemberInstallResult installRoomMemberCertificate(const RoomMemberInstallOptions& options);
RoomMemberInstallResult installRoomMemberCertificateJson(
    const std::string& roomDir,
    const json& signResponse,
    const std::string& memberName);

// 从 Host 或 Client 的房间证书目录读取运行会话需要的 room token 和 PKI 文件。
RoomRuntimeMaterial loadRoomRuntimeMaterial(
    const std::string& roomDir,
    const std::string& username,
    bool host,
    bool requireIdentityCert = true);

}
