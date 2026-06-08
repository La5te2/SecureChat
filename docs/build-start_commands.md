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

启动 Host：

```bat
out\build\x64-release\host.exe secure-room 25566 host
```

启动 WSS Host：

```bat
set SECURECHAT_SIGNALING_TLS=1
set SECURECHAT_TLS_CERT_FILE=certs\fullchain.pem
set SECURECHAT_TLS_KEY_FILE=certs\privkey.pem
out\build\x64-release\host.exe secure-room 25566 host
```

切回 WS：

```bat
set SECURECHAT_SIGNALING_TLS=
set SECURECHAT_TLS_CERT_FILE=
set SECURECHAT_TLS_KEY_FILE=
out\build\x64-release\host.exe secure-room 25566 host
```

也可以显式指定 WS：

```bat
set SECURECHAT_SIGNALING_TLS=0
out\build\x64-release\host.exe secure-room 25566 host
```

启动 Client：

```bat
out\build\x64-release\client.exe ws://127.0.0.1:25566 secure-room user1
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

WinUI Host 使用 WSS：

1. 打开右侧设置面板。
2. 打开 `WSS` 开关。
3. 填写证书 PEM、私钥 PEM 和可选私钥密码：

```text
Certificate PEM: D:\Programming\CyberSecurity\Lessons\Experiment\SecureChat\certs\fullchain.pem
Private key PEM: D:\Programming\CyberSecurity\Lessons\Experiment\SecureChat\certs\privkey.pem
```

4. 回到 Host 页启动房间。

Join 页连接 WSS 房间时，在 URL 中填写：

```text
wss://chat.la5te2.online:25566
```

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

Windows Web Host 使用 WSS：

1. 打开浏览器中的 Host 面板。
2. 打开 `WSS` 开关。
3. 填写证书 PEM、私钥 PEM 和可选私钥密码：

```text
Certificate PEM: D:\Programming\CyberSecurity\Lessons\Experiment\SecureChat\certs\fullchain.pem
Private key PEM: D:\Programming\CyberSecurity\Lessons\Experiment\SecureChat\certs\privkey.pem
```

4. 点击 `Start Hosting`。

Join 面板连接 WSS 房间时，在 URL 中填写：

```text
wss://chat.la5te2.online:25566
```

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

启动 Host：

```bash
./out/build/x64-linux-release/host secure-room 25566 host
```

启动 WSS Host：

```bash
export SECURECHAT_SIGNALING_TLS=1
export SECURECHAT_TLS_CERT_FILE=certs/fullchain.pem
export SECURECHAT_TLS_KEY_FILE=certs/privkey.pem
./out/build/x64-linux-release/host secure-room 25566 host
```

切回 WS：

```bash
unset SECURECHAT_SIGNALING_TLS
unset SECURECHAT_TLS_CERT_FILE
unset SECURECHAT_TLS_KEY_FILE
./out/build/x64-linux-release/host secure-room 25566 host
```

也可以显式指定 WS：

```bash
export SECURECHAT_SIGNALING_TLS=0
./out/build/x64-linux-release/host secure-room 25566 host
```

启动 Client：

```bash
./out/build/x64-linux-release/client ws://124.70.71.65:25566 secure-room user1
```

daemon 启动 Host：

```bash
chmod +x start.sh stop.sh
./start.sh
```

daemon 以 WS 启动 Host：

```bash
./start.sh --mode ws
```

等价写法：

```bash
./start.sh --mode insecure
./start.sh --mode 0
```

停止 daemon Host：

```bash
./stop.sh
```

启用 WSS Host：

```bash
./start.sh --mode wss
```

等价写法：

```bash
./start.sh --mode secure
./start.sh --mode 1
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
./start.sh --mode wss
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

Linux Web Host 使用 WSS：

1. 打开浏览器中的 Host 面板。
2. 打开 `WSS` 开关。
3. 填写证书 PEM、私钥 PEM 和可选私钥密码：

```text
Certificate PEM: certs/fullchain.pem
Private key PEM: certs/privkey.pem
```

4. 点击 `Start Hosting`。

Join 面板连接 WSS 房间时，在 URL 中填写：

```text
wss://chat.la5te2.online:25566
```

如果不通过 Web UI 开关，而是在启动 Web 进程前固定使用 WSS，也可以先设置环境变量：

```bash
export SECURECHAT_SIGNALING_TLS=1
export SECURECHAT_TLS_CERT_FILE=certs/fullchain.pem
export SECURECHAT_TLS_KEY_FILE=certs/privkey.pem
dotnet app/web/bin/Release/net10.0/linux-x64/SecureChat.Web.dll --urls http://127.0.0.1:5188
```

启动 Web 进程前显式指定 WS：

```bash
export SECURECHAT_SIGNALING_TLS=0
dotnet app/web/bin/Release/net10.0/linux-x64/SecureChat.Web.dll --urls http://127.0.0.1:5188
```

## 平台说明

- Linux 没有 WinUI Chat 构建路径；`app/chat` 是 Windows WinUI。
- Windows Web 和 Linux Web 都依赖 C++ native 输出，所以 Web 构建前必须先完成对应平台的 C++ 构建。
- `ws://` 是 insecure mode，配置简单但信令明文；公网安全连接应使用 `wss://` secure mode。
- `./stop.sh` 会清理脚本进程内的 SecureChat 运行时环境变量，包括 room、port、log、ICE、密码和 TLS 相关变量。普通 `./stop.sh` 不能修改父 shell 中已经 `export` 的变量；如果确实要清理当前 SSH 窗口，可执行 `source ./stop.sh` 或手动 `unset`。
