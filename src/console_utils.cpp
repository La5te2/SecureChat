// Console utility implementation for UTF-8 terminal IO and hidden password input.
#include "console_utils.hpp"

#include <iostream>
#include <iterator>
#include <string>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <Shellapi.h>
#include <io.h>
#else
#include <cstdio>
#include <termios.h>
#include <unistd.h>
#endif

void configureConsoleUtf8() {
#ifdef _WIN32
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
#endif
}

bool readInputLineUtf8(std::string& line) {
#ifdef _WIN32
    if (_isatty(_fileno(stdin))) {
        HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
        if (input != INVALID_HANDLE_VALUE && input != nullptr) {
            std::wstring wide;
            wchar_t buffer[1024];

            while (true) {
                DWORD charsRead = 0;
                if (!ReadConsoleW(input, buffer, static_cast<DWORD>(std::size(buffer)), &charsRead, nullptr)) {
                    return false;
                }

                if (charsRead == 0) return false;

                wide.append(buffer, buffer + charsRead);
                if (!wide.empty() && wide.back() == L'\n') break;
            }

            while (!wide.empty() && (wide.back() == L'\n' || wide.back() == L'\r')) {
                wide.pop_back();
            }

            if (wide.empty()) {
                line.clear();
                return true;
            }

            int bytes = WideCharToMultiByte(
                CP_UTF8,
                0,
                wide.data(),
                static_cast<int>(wide.size()),
                nullptr,
                0,
                nullptr,
                nullptr);
            if (bytes <= 0) return false;

            line.assign(static_cast<size_t>(bytes), '\0');
            WideCharToMultiByte(
                CP_UTF8,
                0,
                wide.data(),
                static_cast<int>(wide.size()),
                line.data(),
                bytes,
                nullptr,
                nullptr);
            return true;
        }
    }
#endif

    return static_cast<bool>(std::getline(std::cin, line));
}

bool isInteractiveInput() {
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(fileno(stdin)) != 0;
#endif
}

bool readPasswordLineUtf8(const std::string& prompt, std::string& line) {
    if (!isInteractiveInput()) return false;

    std::cerr << prompt;
#ifdef _WIN32
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    if (input == INVALID_HANDLE_VALUE || input == nullptr) return false;

    DWORD originalMode = 0;
    if (!GetConsoleMode(input, &originalMode)) return false;

    // Disable terminal echo so room passwords do not land in screenshots,
    // terminal scrollback, command history, or process listings.
    const DWORD hiddenMode = originalMode & ~ENABLE_ECHO_INPUT;
    if (!SetConsoleMode(input, hiddenMode)) return false;

    const bool ok = readInputLineUtf8(line);
    SetConsoleMode(input, originalMode);
    std::cerr << std::endl;
    return ok;
#else
    termios originalMode{};
    if (tcgetattr(STDIN_FILENO, &originalMode) != 0) return false;

    auto hiddenMode = originalMode;
    hiddenMode.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hiddenMode) != 0) return false;

    const bool ok = static_cast<bool>(std::getline(std::cin, line));
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &originalMode);
    std::cerr << std::endl;
    return ok;
#endif
}

void wakeConsoleInput() {
#ifdef _WIN32
    if (!_isatty(_fileno(stdin))) return;

    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    if (input == INVALID_HANDLE_VALUE || input == nullptr) return;

    INPUT_RECORD records[2] = {};
    records[0].EventType = KEY_EVENT;
    records[0].Event.KeyEvent.bKeyDown = TRUE;
    records[0].Event.KeyEvent.wRepeatCount = 1;
    records[0].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
    records[0].Event.KeyEvent.wVirtualScanCode = 0x1c;
    records[0].Event.KeyEvent.uChar.UnicodeChar = L'\r';

    records[1] = records[0];
    records[1].Event.KeyEvent.bKeyDown = FALSE;

    DWORD written = 0;
    WriteConsoleInputW(input, records, static_cast<DWORD>(std::size(records)), &written);
#endif
}

std::string wideToUtf8(const wchar_t* text) {
#ifdef _WIN32
    if (!text) return {};
    const int bytes = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (bytes <= 1) return {};

    std::string result(static_cast<std::size_t>(bytes - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, result.data(), bytes, nullptr, nullptr);
    return result;
#else
    (void)text;
    return {};
#endif
}

std::vector<std::string> commandLineArgsUtf8(int argc, char** argv) {
#ifdef _WIN32
    int wideArgc = 0;
    wchar_t** wideArgv = CommandLineToArgvW(GetCommandLineW(), &wideArgc);
    if (!wideArgv) return {};

    std::vector<std::string> args;
    args.reserve(static_cast<std::size_t>(wideArgc));
    for (int i = 0; i < wideArgc; ++i) {
        args.push_back(wideToUtf8(wideArgv[i]));
    }

    LocalFree(wideArgv);
    return args;
#else
    std::vector<std::string> args;
    args.reserve(static_cast<std::size_t>(argc));
    for (int i = 0; i < argc; ++i) args.emplace_back(argv[i]);
    return args;
#endif
}
