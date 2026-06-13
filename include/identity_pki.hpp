#pragma once

#include "common.hpp"

#include <memory>
#include <string>

namespace chat::identity_pki {

// Holds the local identity certificate, signing key, trust store, and optional
// revocation list used to authenticate GKA public keys.
class IdentityContext {
public:
    IdentityContext();

    // Returns true when SECURECHAT_PKI_TRUST_STORE, SECURECHAT_IDENTITY_CERT_FILE,
    // and SECURECHAT_IDENTITY_KEY_FILE are all configured and loaded.
    bool enabled() const;

    // Human-readable local certificate subject and SHA-256 fingerprint for logs/UI.
    std::string subject() const;
    std::string fingerprint() const;

    // Signs the Client join frame, binding identity to the temporary X25519 key.
    json signJoinRoom(
        const std::string& roomId,
        const std::string& username,
        const std::string& publicKey) const;

    // Verifies a Client join identity object against the trusted CA bundle.
    void verifyJoinRoom(
        const std::string& roomId,
        const std::string& username,
        const std::string& publicKey,
        const json& identity) const;

    // Adds Host identity and signature to a group_key envelope.
    void signGroupKeyEnvelope(json& envelope) const;

    // Verifies the Host signature on a group_key envelope before unwrapping it.
    void verifyGroupKeyEnvelope(const json& envelope) const;

private:
    struct Data;
    explicit IdentityContext(std::shared_ptr<Data> data);

    std::shared_ptr<Data> mData;

    friend IdentityContext loadFromEnvironment();
};

// Loads optional PKI identity configuration from SECURECHAT_* environment variables.
IdentityContext loadFromEnvironment();

}
