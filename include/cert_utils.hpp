// 证书和 PKI 运行时共用的小工具。
// 这里不放房间、GKA 或 Server 状态语义，只提供 Base64、SHA-256、
// 随机数、canonical 字段拼接和签名验签等基础能力。
#pragma once

#include <openssl/evp.h>

#include <cstddef>
#include <string>
#include <vector>

namespace chat::cert_utils {

std::vector<unsigned char> randomBytes(std::size_t size);

std::string base64Encode(const unsigned char* data, std::size_t size);
std::string base64Encode(const std::vector<unsigned char>& data);
std::vector<unsigned char> base64Decode(const std::string& value);

std::string hexEncode(const unsigned char* data, std::size_t size);
std::string sha256Hex(const std::string& value);
std::string sha256Hex(const unsigned char* data, std::size_t size);

void appendCanonicalField(std::string& out, const std::string& name, const std::string& value);

std::vector<unsigned char> signBytes(EVP_PKEY* key, const std::string& message);
bool verifyBytes(EVP_PKEY* key, const std::string& message, const std::vector<unsigned char>& signature);

}
