// Cross-platform console helpers for UTF-8 input, hidden password prompts,
// signal wakeups, and Windows command-line conversion.
#pragma once

#include <string>
#include <vector>

// Configures Windows console input/output code pages for UTF-8 text.
void configureConsoleUtf8();

// Reads one console line as UTF-8, including Unicode input on Windows terminals.
bool readInputLineUtf8(std::string& line);

// Returns true when stdin is an interactive terminal instead of a pipe/service.
bool isInteractiveInput();

// Reads a UTF-8 password without echoing it on an interactive terminal.
bool readPasswordLineUtf8(const std::string& prompt, std::string& line);

// Wakes a thread blocked in readInputLineUtf8() on an interactive Windows console.
// Used by CLI shutdown paths so input reader threads can be joined instead of detached.
void wakeConsoleInput();

// Converts a Windows wide string to UTF-8. Returns an empty string on platforms
// without wide Windows command-line APIs.
std::string wideToUtf8(const wchar_t* text);

// Returns command-line arguments as UTF-8 strings on every supported platform.
std::vector<std::string> commandLineArgsUtf8(int argc, char** argv);
