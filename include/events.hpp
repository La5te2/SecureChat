#pragma once

#include <functional>
#include <string>

struct ChatCallbacks {
    std::function<void(const std::string&)> onLog;
    std::function<void(const std::string&)> onError;
    std::function<void(const std::string&)> onMessage;
    std::function<void(const std::string&)> onStatus;
    std::function<void(const std::string&)> onImage;
    std::function<void(const std::string&)> onFile;
    std::function<void(const std::string&)> onVoice;
};

// Emits an event only when the embedding layer supplied a callback.
inline void chatEmit(const std::function<void(const std::string&)>& callback, const std::string& text) {
    if (callback) callback(text);
}
