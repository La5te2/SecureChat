#pragma once

#include <nlohmann/json.hpp>
#include <rtc/rtc.hpp>

#include <fstream>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <vector>

using json = nlohmann::json;

namespace chat::protocol {
inline constexpr const char* HostActorId = "host";
inline constexpr const char* ClientActorKind = "participant";
inline constexpr const char* HostActorKind = "host";
inline constexpr const char* ControlledActorKind = "controlled";

inline constexpr std::size_t MaxDataChannelTextMessageBytes = 1024 * 1024;
inline constexpr std::size_t MaxSignalingMessageBytes = 512 * 1024;
inline constexpr std::size_t MaxJsonPayloadDepth = 16;
inline constexpr std::size_t MaxJsonPayloadNodes = 4096;
inline constexpr std::size_t MaxJsonStringBytes = 512 * 1024;

inline void validateJsonBudget(
    const json& value,
    std::size_t depth = 0,
    std::size_t* nodes = nullptr) {
    std::size_t localNodes = 0;
    if (!nodes) nodes = &localNodes;
    if (++(*nodes) > MaxJsonPayloadNodes) {
        throw std::runtime_error("protocol JSON payload is too large");
    }
    if (depth > MaxJsonPayloadDepth) {
        throw std::runtime_error("protocol JSON payload is too deep");
    }
    if (value.is_string() && value.get_ref<const std::string&>().size() > MaxJsonStringBytes) {
        throw std::runtime_error("protocol JSON string is too large");
    }
    if (value.is_array()) {
        for (const auto& item : value) validateJsonBudget(item, depth + 1, nodes);
    }
    else if (value.is_object()) {
        for (const auto& item : value.items()) {
            if (item.key().size() > 256) {
                throw std::runtime_error("protocol JSON field name is too large");
            }
            validateJsonBudget(item.value(), depth + 1, nodes);
        }
    }
}

inline json parseJsonObjectWithBudget(
    const std::string& jsonStr,
    std::size_t maxBytes,
    const char* label) {
    if (jsonStr.size() > maxBytes) {
        throw std::runtime_error(std::string(label) + " is too large");
    }
    auto value = json::parse(jsonStr);
    if (!value.is_object()) {
        throw std::runtime_error(std::string(label) + " must be a JSON object");
    }
    validateJsonBudget(value);
    return value;
}

inline bool isAllowedMessageField(const std::string& key) {
    return key == "type" ||
        key == "from" ||
        key == "to" ||
        key == "visibility" ||
        key == "command" ||
        key == "result" ||
        key == "content" ||
        key == "name" ||
        key == "mime" ||
        key == "data" ||
        key == "payload";
}

inline void validateMessageSchema(const json& object) {
    for (const auto& item : object.items()) {
        const auto& key = item.key();
        const auto& value = item.value();
        if (!isAllowedMessageField(key)) {
            throw std::runtime_error("protocol message has unknown field: " + key);
        }
        if (key == "result") {
            if (!value.is_number_integer()) {
                throw std::runtime_error("protocol message result must be an integer");
            }
        }
        else if (key == "payload") {
            if (!value.is_object()) {
                throw std::runtime_error("protocol message payload must be an object");
            }
        }
        else if (!value.is_string()) {
            throw std::runtime_error("protocol message field must be a string: " + key);
        }
    }
}
}

// Message payload exchanged over WebRTC data channels.
struct Message {
    std::string type;
    std::string from;
    std::string to;
    std::string visibility;
    std::string command;
    int result = 0;
    std::string content;
    std::string name;
    std::string mime;
    std::string data;
    json payload = json::object();

    // Parses a protocol message from its JSON wire representation.
    static Message fromJson(const std::string& jsonStr) {
        auto j = chat::protocol::parseJsonObjectWithBudget(
            jsonStr,
            chat::protocol::MaxDataChannelTextMessageBytes,
            "protocol message");
        chat::protocol::validateMessageSchema(j);
        Message msg;
        msg.type = j.value("type", "");
        msg.from = j.value("from", "");
        msg.to = j.value("to", "");
        msg.visibility = j.value("visibility", "");
        msg.command = j.value("command", "");
        msg.result = j.value("result", 0);
        msg.content = j.value("content", "");
        msg.name = j.value("name", "");
        msg.mime = j.value("mime", "");
        msg.data = j.value("data", "");
        if (j.contains("payload")) msg.payload = j["payload"];
        return msg;
    }

    // Serializes a protocol message to its compact JSON wire representation.
    std::string toJson() const {
        json j;
        j["type"] = type;
        if (!from.empty()) j["from"] = from;
        if (!to.empty()) j["to"] = to;
        if (!visibility.empty()) j["visibility"] = visibility;
        if (!command.empty()) j["command"] = command;
        if (result != 0) j["result"] = result;
        if (!content.empty()) j["content"] = content;
        if (!name.empty()) j["name"] = name;
        if (!mime.empty()) j["mime"] = mime;
        if (!data.empty()) j["data"] = data;
        if (!payload.empty()) j["payload"] = payload;
        return j.dump();
    }
};

// Converts libdatachannel string or binary message variants to std::string.
inline std::string rtcMessageToString(const rtc::message_variant& data) {
    if (auto str = std::get_if<std::string>(&data)) return *str;
    if (auto bin = std::get_if<rtc::binary>(&data)) {
        return std::string(reinterpret_cast<const char*>(bin->data()), bin->size());
    }

    return "";
}

// Builds a plain chat message.
inline Message makeTextMessage(const std::string& from, const std::string& content) {
    Message msg;
    msg.type = "text";
    msg.from = from;
    msg.content = content;
    return msg;
}
