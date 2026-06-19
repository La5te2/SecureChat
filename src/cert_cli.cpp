// 房间级 PKI 和 entrance.scp 命令行入口。
// 该文件只解析命令行；证书、CSR 和 entrance 容器逻辑位于 cert_generation.cpp。
#include "cert_generation.hpp"
#include "console_utils.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

void printUsage() {
    std::cerr << "Usage:\n";
    std::cerr << "  cert create-entrance --room <room> --phrase <phrase> --host <name> [--out <dir>] [--key-pass <pass>]\n";
    std::cerr << "  cert inspect-entrance --entrance <path> --phrase <phrase>\n";
    std::cerr << "  cert import-entrance --entrance <path> --phrase <phrase> --user <name> [--out <dir>] [--key-pass <pass>]\n";
    std::cerr << "  cert sign-csr --room-dir <dir> --csr <path> --user <name>\n";
    std::cerr << "  cert install-sign-response --room-dir <dir> --response <path> --user <name>\n";
    std::cerr << "  cert room-runtime --room-dir <dir> --user <name> --role <host|client>\n";
}

std::unordered_map<std::string, std::string> parseOptions(const std::vector<std::string>& args, std::size_t start) {
    std::unordered_map<std::string, std::string> options;
    for (std::size_t i = start; i < args.size(); ++i) {
        const auto& key = args[i];
        if (key.rfind("--", 0) != 0 || i + 1 >= args.size()) {
            throw std::runtime_error("invalid option: " + key);
        }
        options[key] = args[++i];
    }
    return options;
}

std::string requireOption(const std::unordered_map<std::string, std::string>& options, const std::string& key) {
    auto it = options.find(key);
    if (it == options.end() || it->second.empty()) {
        throw std::runtime_error("missing option: " + key);
    }
    return it->second;
}

std::string optionOr(const std::unordered_map<std::string, std::string>& options, const std::string& key, const std::string& fallback) {
    auto it = options.find(key);
    return it == options.end() ? fallback : it->second;
}

}

int main(int argc, char** argv) {
    configureConsoleUtf8();
    const auto args = commandLineArgsUtf8(argc, argv);
    if (args.size() < 2) {
        printUsage();
        return 1;
    }

    try {
        const auto command = args[1];
        const auto options = parseOptions(args, 2);

        if (command == "create-entrance") {
            chat::certs::RoomEntranceCreateOptions create;
            create.roomName = requireOption(options, "--room");
            create.roomPhrase = requireOption(options, "--phrase");
            create.hostName = optionOr(options, "--host", "host");
            create.outputRoot = optionOr(options, "--out", "logs/certs");
            create.memberKeyPassword = optionOr(options, "--key-pass", "");
            const auto result = chat::certs::createRoomEntrance(create);
            std::cout << "entrance: " << result.entranceFile << "\n";
            std::cout << "roomDir: " << result.roomDir << "\n";
            std::cout << "rootFingerprint: " << result.rootFingerprint << "\n";
            std::cout << "intermediateFingerprint: " << result.intermediateFingerprint << "\n";
            std::cout << "hostFingerprint: " << result.hostFingerprint << "\n";
            std::cout << "roomInstanceTokenDigest: " << result.roomInstanceTokenDigest << "\n";
            return 0;
        }

        if (command == "inspect-entrance") {
            std::cout << chat::certs::inspectRoomEntrance(
                requireOption(options, "--entrance"),
                requireOption(options, "--phrase")) << "\n";
            return 0;
        }

        if (command == "import-entrance") {
            chat::certs::RoomEntranceImportOptions import;
            import.entranceFile = requireOption(options, "--entrance");
            import.roomPhrase = requireOption(options, "--phrase");
            import.username = requireOption(options, "--user");
            import.outputRoot = optionOr(options, "--out", "logs/certs");
            import.memberKeyPassword = optionOr(options, "--key-pass", "");
            const auto result = chat::certs::importRoomEntrance(import);
            std::cout << "roomDir: " << result.roomDir << "\n";
            std::cout << "memberKey: " << result.memberKeyFile << "\n";
            std::cout << "memberCsr: " << result.memberCsrFile << "\n";
            std::cout << "memberCsrBundle: " << result.memberCsrBundleFile << "\n";
            std::cout << "rootFingerprint: " << result.rootFingerprint << "\n";
            std::cout << "intermediateFingerprint: " << result.intermediateFingerprint << "\n";
            return 0;
        }

        if (command == "sign-csr") {
            chat::certs::RoomMemberSignOptions sign;
            sign.roomDir = requireOption(options, "--room-dir");
            sign.csrFile = requireOption(options, "--csr");
            sign.memberName = requireOption(options, "--user");
            const auto result = chat::certs::signRoomMemberCertificate(sign);
            std::cout << "memberCert: " << result.memberCertFile << "\n";
            std::cout << "memberChain: " << result.memberChainFile << "\n";
            std::cout << "signResponse: " << result.signResponseFile << "\n";
            std::cout << "memberFingerprint: " << result.memberFingerprint << "\n";
            return 0;
        }

        if (command == "install-sign-response") {
            chat::certs::RoomMemberInstallOptions install;
            install.roomDir = requireOption(options, "--room-dir");
            install.signResponseFile = requireOption(options, "--response");
            install.memberName = requireOption(options, "--user");
            const auto result = chat::certs::installRoomMemberCertificate(install);
            std::cout << "memberCert: " << result.memberCertFile << "\n";
            std::cout << "memberChain: " << result.memberChainFile << "\n";
            std::cout << "memberFingerprint: " << result.memberFingerprint << "\n";
            return 0;
        }

        if (command == "room-runtime") {
            const auto role = requireOption(options, "--role");
            const bool host = role == "host";
            if (!host && role != "client") {
                throw std::runtime_error("--role must be host or client");
            }
            const auto material = chat::certs::loadRoomRuntimeMaterial(
                requireOption(options, "--room-dir"),
                requireOption(options, "--user"),
                host);
            std::cout << "roomName: " << material.roomName << "\n";
            std::cout << "canonicalRoomName: " << material.canonicalRoomName << "\n";
            std::cout << "username: " << material.username << "\n";
            std::cout << "roomInstanceTokenDigest: " << material.roomInstanceTokenDigest << "\n";
            std::cout << "trustStore: " << material.trustStoreFile << "\n";
            std::cout << "identityCert: " << material.identityCertFile << "\n";
            std::cout << "identityKey: " << material.identityKeyFile << "\n";
            return 0;
        }

        printUsage();
        return 1;
    }
    catch (const std::exception& e) {
        std::cerr << "[fatal] " << e.what() << "\n";
        return 1;
    }
}
