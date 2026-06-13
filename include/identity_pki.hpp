// Application-layer PKI declarations. Host/Client use these APIs to bind
// identity certificates to GKA public keys and group-key envelopes.
#pragma once

#include "common.hpp"

#include <cstdint>
#include <memory>
#include <string>

namespace chat::identity_pki {

// Result returned after a member certificate chain and identity signature pass
// verification. UI uses the fingerprint for display/copy, not as a secret.
struct VerifiedIdentity {
    std::string subject;
    std::string fingerprint;
};

// Application-layer PKI context. This authenticates the temporary X25519 keys
// used by GKA; it is separate from TLS/mTLS transport certificates.
class IdentityContext {
public:
    IdentityContext();

    // Reports whether this context holds a loaded certificate, key, and trust store.
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
    VerifiedIdentity verifyJoinRoom(
        const std::string& roomId,
        const std::string& username,
        const std::string& publicKey,
        const json& identity) const;

    // Signs one member contribution for a contributory GKA epoch.
    json signGkaContribution(
        const std::string& roomId,
        std::uint64_t epoch,
        const std::string& memberId,
        const std::string& username,
        const std::string& publicKey,
        const std::string& contribution) const;

    // Verifies that a contribution was signed by the claimed member identity.
    VerifiedIdentity verifyGkaContribution(
        const std::string& roomId,
        std::uint64_t epoch,
        const std::string& memberId,
        const std::string& username,
        const std::string& publicKey,
        const std::string& contribution,
        const json& identity) const;

    // Adds Host identity and signature to a group_key envelope.
    void signGroupKeyEnvelope(json& envelope) const;

    // Verifies the Host signature on a group_key envelope before unwrapping it.
    VerifiedIdentity verifyGroupKeyEnvelope(const json& envelope) const;

private:
    struct Data;
    explicit IdentityContext(std::shared_ptr<Data> data);

    std::shared_ptr<Data> mData;

    friend IdentityContext loadFromEnvironment();
};

// Loads mandatory PKI identity configuration from SECURECHAT_* environment variables.
IdentityContext loadFromEnvironment();

}
