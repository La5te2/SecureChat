// 证书生成和证书材料解析工具。
// 当前先提供 Server 本地/局域网 WSS 证书生成；后续可继续承载 entrance.scp、
// 房间 Root/Intermediate、成员 CSR 和成员证书签发等证书相关能力。
#pragma once

#include <string>

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

}
