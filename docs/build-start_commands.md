# SecureChat 构建和启动命令

本文档记录 Windows 和 Linux 下的手动构建、脚本构建和启动命令。命令默认在项目根目录执行。

Windows 项目根目录示例：

```bat
D:
cd D:\Programming\CyberSecurity\Lessons\Experiment\SecureChat
```

Linux 项目根目录示例：

```bash
cd ~/SecureChat
```

## Windows C++

脚本构建：

```bat
set VCPKG_ROOT=C:\src\vcpkg
build.bat
```

手动构建：

```bat
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=x64
set VCPKG_ROOT=C:\src\vcpkg
cmake --preset x64-release -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake"
cmake --build out\build\x64-release --config Release
```

启动 WSS Server：

```bat
set SECURECHAT_SIGNALING_TLS=1
set SECURECHAT_TLS_CERT_FILE=certs\fullchain.pem
set SECURECHAT_TLS_KEY_FILE=certs\privkey.pem
out\build\x64-release\server.exe 25566
```

启动 WS Server：

```bat
set SECURECHAT_SIGNALING_TLS=
set SECURECHAT_TLS_CERT_FILE=
set SECURECHAT_TLS_KEY_FILE=
out\build\x64-release\server.exe 25566
```

启动 Client：

```bat
out\build\x64-release\client.exe ws://127.0.0.1:25566 secure-room user1
```

启动不可信 Server：

```bat
out\build\x64-release\server.exe 25566
```

群主 Host 作为可见成员连接 Server：

```bat
out\build\x64-release\host.exe --server ws://127.0.0.1:25566 secure-room host
```

## Windows WinUI Chat

脚本构建：

```bat
set VCPKG_ROOT=C:\src\vcpkg
build_win.bat
```

手动构建：

```bat
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=x64
set VCPKG_ROOT=C:\src\vcpkg
cmake --preset x64-release -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake"
cmake --build out\build\x64-release --config Release
dotnet build app\chat\chat.csproj -c Release -p:Platform=x64
```

启动 WinUI Chat：

```bat
app\chat\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\SecureChat.exe
```

WinUI Host/Client 连接 WSS Server：

1. 先独立启动 Server，并在 Server 进程上配置 WSS 证书。
2. 启动 WinUI；GKA v2 会在 Host/Client 加入房间时自动分发 room group key，不需要设置共享 E2EE 口令。
3. 在 Host 或 Join 页的 Server URL 中填写：

```text
wss://chat.la5te2.online:25566
```

证书 PEM 和私钥 PEM 不再由 Host UI 配置；Host 现在只是连接外部 Server 的可见群成员。

## Windows Web

脚本构建：

```bat
set VCPKG_ROOT=C:\src\vcpkg
build_web.bat
```

手动构建：

```bat
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=x64
set VCPKG_ROOT=C:\src\vcpkg
cmake --preset x64-release -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake"
cmake --build out\build\x64-release --config Release
dotnet build app\web\SecureChat.Web.csproj -c Release -r win-x64 --self-contained false
```

启动 Windows Web：

```bat
dotnet app\web\bin\Release\net10.0\win-x64\SecureChat.Web.dll --urls http://127.0.0.1:5188
```

浏览器打开：

```text
http://127.0.0.1:5188
```

Windows Web Host/Client 连接 WSS Server：

1. 先独立启动 Server，并在 Server 进程上配置 WSS 证书。
2. 启动 Web 进程：

```bat
dotnet app\web\bin\Release\net10.0\win-x64\SecureChat.Web.dll --urls http://127.0.0.1:5188
```

3. 浏览器 Host 或 Join 面板的 Server URL 填写：

```text
wss://chat.la5te2.online:25566
```

Web Host 不再配置证书路径；WSS 证书属于独立 Server 进程。

## Linux C++

脚本构建：

```bash
cd ~/SecureChat
export VCPKG_ROOT="$HOME/vcpkg"
chmod +x build.sh
./build.sh
```

手动构建：

```bash
cd ~/SecureChat
export VCPKG_ROOT="$HOME/vcpkg"
cmake --preset x64-linux-release
cmake --build out/build/x64-linux-release --config Release
```

启动不可信 Server：

```bash
./out/build/x64-linux-release/server 25566
```

群主 Host 作为可见成员连接 Server：

```bash
./out/build/x64-linux-release/host --server ws://127.0.0.1:25566 secure-room host
```

启动 WSS Server：

```bash
export SECURECHAT_SIGNALING_TLS=1
export SECURECHAT_TLS_CERT_FILE=certs/fullchain.pem
export SECURECHAT_TLS_KEY_FILE=certs/privkey.pem
./out/build/x64-linux-release/server 25566
```

启动 WS Server：

```bash
unset SECURECHAT_SIGNALING_TLS
unset SECURECHAT_TLS_CERT_FILE
unset SECURECHAT_TLS_KEY_FILE
./out/build/x64-linux-release/server 25566
```

启动 Client：

```bash
./out/build/x64-linux-release/client ws://124.70.71.65:25566 secure-room user1
```

daemon 启动 Server：

```bash
chmod +x start_server.sh stop_server.sh start_host.sh stop_host.sh start_client.sh stop_client.sh
./start_server.sh --mode wss
```

daemon 以 WS 启动 Server：

```bash
./start_server.sh --mode ws
```

等价写法：

```bash
./start_server.sh --mode insecure
./start_server.sh --mode 0
```

停止 daemon Server：

```bash
./stop_server.sh
```

Host 和 Client 默认前台运行，作为可见成员连接 Server：

```bash
./start_host.sh --server wss://chat.la5te2.online:25566
./start_client.sh --server wss://chat.la5te2.online:25566
```

如需把 Host 或 Client 后台运行，显式加 `--daemon`：

```bash
printf '%s\n' 'your-password' | ./start_host.sh --server wss://chat.la5te2.online:25566 --daemon
printf '%s\n' 'your-password' | ./start_client.sh --server wss://chat.la5te2.online:25566 --daemon
```

停止后台 Host 或 Client：

```bash
./stop_host.sh
./stop_client.sh
```

启用 WSS Server 的等价写法：

```bash
./start_server.sh --mode secure
./start_server.sh --mode 1
```

`--mode wss` 默认使用项目内证书：

```text
certs/fullchain.pem
certs/privkey.pem
```

如需使用其他证书路径，可以在启动前覆盖：

```bash
export SECURECHAT_TLS_CERT_FILE=certs/fullchain.pem
export SECURECHAT_TLS_KEY_FILE=certs/privkey.pem
./start_server.sh --mode wss
```

WSS Client：

```bash
./out/build/x64-linux-release/client wss://chat.la5te2.online:25566 secure-room user1
```

## Linux Web

Linux Web 用于非 Host Linux 端时，可以直接用 `build_web.sh` 构建 C++ native 和 Web UI。

脚本构建：

```bash
cd ~/SecureChat
chmod +x build_web.sh
./build_web.sh
```

手动构建：

```bash
cd ~/SecureChat
export VCPKG_ROOT="$HOME/vcpkg"
bash ./build.sh
dotnet build app/web/SecureChat.Web.csproj -c Release -r linux-x64 --self-contained false
```

启动 Linux Web：

```bash
dotnet app/web/bin/Release/net10.0/linux-x64/SecureChat.Web.dll --urls http://127.0.0.1:5188
```

浏览器打开：

```text
http://127.0.0.1:5188
```

Linux Web Host/Client 连接 WSS Server：

1. 先独立启动 Server，并在 Server 进程上配置 WSS 证书。
2. 启动 Web 进程：

```bash
dotnet app/web/bin/Release/net10.0/linux-x64/SecureChat.Web.dll --urls http://127.0.0.1:5188
```

3. 浏览器 Host 或 Join 面板的 Server URL 填写：

```text
wss://chat.la5te2.online:25566
```

Web Host 不再配置证书路径；WSS 证书属于独立 Server 进程。

## 平台说明

- Linux 没有 WinUI Chat 构建路径；`app/chat` 是 Windows WinUI。
- Windows Web 和 Linux Web 都依赖 C++ native 输出，所以 Web 构建前必须先完成对应平台的 C++ 构建。
- `ws://` 是 insecure mode，配置简单但信令明文；公网安全连接应使用 `wss://` secure mode。
- 文本和附件 E2EE 使用 GKA v2 自动分发 room group key；Host/Client/Web/WinUI 不再需要设置共享 E2EE 口令。
- 接收附件会写入 `logs/images`、`logs/voice`、`logs/files`。默认缓存总量上限为 512 MB，可用 `SECURECHAT_LOGS_MAX_BYTES` 覆盖，例如 `export SECURECHAT_LOGS_MAX_BYTES=1073741824`。
- `./stop_server.sh`、`./stop_host.sh`、`./stop_client.sh` 会清理各自脚本进程内的 SecureChat 运行时环境变量。普通 stop 脚本不能修改父 shell 中已经 `export` 的变量；如果确实要清理当前 SSH 窗口，可执行对应的 `source ./stop_*.sh` 或手动 `unset`。
- 公网 Server 部署加固、非 root 用户、可选 systemd 模板、SIGTERM 验证、日志清理和安全组来源 IP 收敛步骤见 `docs/deployment-hardening.md`。

- 所有 `SECURECHAT_*` 环境变量的完整说明见 `docs/environment-variables.md`。
