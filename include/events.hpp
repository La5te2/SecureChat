// 回调集合，用于把 C++ 会话逻辑与 CLI/WinUI 解耦。
#pragma once

#include <functional>
#include <string>

struct ChatCallbacks {
    // 每个前端只提供自己关心的回调。CLI 会打印事件，
    // WinUI 会渲染事件，CLI 仍把它们输出到 stdout。
    std::function<void(const std::string&)> onLog;
    std::function<void(const std::string&)> onError;
    std::function<void(const std::string&)> onMessage;
    std::function<void(const std::string&)> onStatus;
    std::function<void(const std::string&)> onRelayStatus;
    std::function<void(const std::string&)> onImage;
    std::function<void(const std::string&)> onFile;
    std::function<void(const std::string&)> onVoice;
};

// 仅在嵌入层提供回调时发送事件。
inline void chatEmit(const std::function<void(const std::string&)>& callback, const std::string& text) {
    if (callback) callback(text);
}
