// 跨平台控制台工具：UTF-8 输入、隐藏密码提示、信号唤醒和 Windows 命令行转换。
#pragma once

#include <string>
#include <vector>

// 将 Windows 控制台输入/输出代码页配置为 UTF-8。
void configureConsoleUtf8();

// 以 UTF-8 读取一行控制台输入，包括 Windows 终端中的 Unicode 输入。
bool readInputLineUtf8(std::string& line);

// 当 stdin 是交互式终端而非管道/服务时返回 true。
bool isInteractiveInput();

// 在交互式终端中读取 UTF-8 密码且不回显。
bool readPasswordLineUtf8(const std::string& prompt, std::string& line);

// 唤醒在交互式 Windows 控制台中阻塞于 readInputLineUtf8() 的线程。
// CLI 关闭路径使用它，使输入读取线程可以 join 而不是 detach。
void wakeConsoleInput();

// 将 Windows 宽字符串转换为 UTF-8。在没有 Windows 宽命令行 API 的平台上返回空字符串。
std::string wideToUtf8(const wchar_t* text);

// 在所有支持平台上以 UTF-8 字符串形式返回命令行参数。
std::vector<std::string> commandLineArgsUtf8(int argc, char** argv);
