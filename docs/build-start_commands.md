# SecureChat 构建和启动命令

本文档记录 Windows 和 Linux 下的手动构建、脚本构建和启动命令。命令默认在项目根目录执行。

如果只想知道怎么启动 Server、Host、Client，请优先看 `docs/startup-guide.md`。那里按 Windows/Linux 和 WS/WSS/mTLS 分开写了完整步骤。

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

### Windows CLI 启动顺序

下面只给最小本机 WS 测试命令。完整 PKI、WSS、WinUI 和局域网步骤见 `docs/startup-guide.md`。

窗口 1：启动 Server。

```bat
out\build\x64-release\server.exe 25566
```

窗口 2：配置 Host 的成员 PKI，然后创建房间。

```powershell
$env:SECURECHAT_PKI_TRUST_STORE="certs\pki\root-ca.pem"
$env:SECURECHAT_IDENTITY_CERT_FILE="certs\pki\alice-chain.pem"
$env:SECURECHAT_IDENTITY_KEY_FILE="certs\pki\alice-key.pem"
$env:SECURECHAT_PKI_REVOCATION_FILE="certs\pki\revoked.txt"
out\build\x64-release\host.exe --server ws://127.0.0.1:25566 secure-room alice
```

窗口 3：配置 Client 的成员 PKI，然后加入同一个房间。

```powershell
$env:SECURECHAT_PKI_TRUST_STORE="certs\pki\root-ca.pem"
$env:SECURECHAT_IDENTITY_CERT_FILE="certs\pki\bob-chain.pem"
$env:SECURECHAT_IDENTITY_KEY_FILE="certs\pki\bob-key.pem"
$env:SECURECHAT_PKI_REVOCATION_FILE="certs\pki\revoked.txt"
out\build\x64-release\client.exe ws://127.0.0.1:25566 secure-room bob
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

启动 WinUI Chat。普通用户可以在文件资源管理器里双击这个 exe；下面的命令只是等价的命令行启动方式：

```bat
app\chat\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\SecureChat.exe
```

WinUI Host/Client 连接 WSS Server：

1. 先独立启动 Server，并在 Server 进程上配置 WSS 证书。
2. 双击启动 WinUI，点击右侧齿轮，在“成员 PKI”区域选择信任根、成员证书链、成员私钥和可选吊销列表。
3. 在 Host 或 Join 页的 Server URL 中填写：

```text
wss://chat.la5te2.online:25566
```

GKA v3 会在 Host/Client 加入房间时自动协商 room group key，不需要设置共享 E2EE 口令。

Server 的 TLS 证书和私钥不在 WinUI 中配置；WinUI 只配置当前聊天成员自己的应用层 PKI 身份。Host 现在只是连接外部 Server 的可见群成员和房间管理者。

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

## 必需 PKI 成员身份认证

PKI 成员身份认证配置在 Host/Client/Web/WinUI 进程上，不配置在 Server 上。Host/Client 没有完整 PKI 配置会启动失败；Server 只要求并转发 `identity` 对象，不验证证书。

Windows PowerShell 示例：

```powershell
$env:SECURECHAT_PKI_TRUST_STORE="certs\pki\root-ca.pem"
$env:SECURECHAT_IDENTITY_CERT_FILE="certs\pki\alice-chain.pem"
$env:SECURECHAT_IDENTITY_KEY_FILE="certs\pki\alice-key.pem"
$env:SECURECHAT_PKI_REVOCATION_FILE="certs\pki\revoked.txt"
```

Linux 示例：

```bash
export SECURECHAT_PKI_TRUST_STORE=certs/pki/root-ca.pem
export SECURECHAT_IDENTITY_CERT_FILE=certs/pki/alice-chain.pem
export SECURECHAT_IDENTITY_KEY_FILE=certs/pki/alice-key.pem
export SECURECHAT_PKI_REVOCATION_FILE=certs/pki/revoked.txt
```

每个成员机器使用自己的 `SECURECHAT_IDENTITY_CERT_FILE` 和 `SECURECHAT_IDENTITY_KEY_FILE`。同一房间内的成员应信任同一个 CA bundle。详细证书生成和字段说明见 `docs/pki-identity.md`。

## 可选 mTLS 反向代理启动

mTLS 由 Nginx 处理，SecureChat Server 作为本机 backend 运行。公网只暴露 Nginx 的 `25566`，backend 只监听本机 `25567`。

Nginx 需要安装在服务器系统上，不是仓库里的可执行文件。Ubuntu/Debian 示例：

```bash
sudo apt update
sudo apt install -y nginx openssl
sudo systemctl enable --now nginx
```

mTLS 入口至少需要：

- Nginx 服务器 TLS 证书：`/opt/SecureChat/certs/fullchain.pem`、`/opt/SecureChat/certs/privkey.pem`；
- 用来验证客户端 TLS 证书的 CA：`/opt/SecureChat/certs/pki/root-ca.pem`；
- 每台 Host/Client 自己持有的客户端 TLS 证书和私钥，例如 `certs/pki/alice-mtls-chain.pem`、`certs/pki/alice-mtls-key.pem`。

不使用 systemd 时，用脚本启动 backend。`start_server.sh` 默认后台运行：

```bash
sudo -u securechat -H bash -lc 'cd /opt/SecureChat && \
  SECURECHAT_BIND_ADDRESS=127.0.0.1 \
  SECURECHAT_PORT=25567 \
  SECURECHAT_SERVER_PID_FILE=server-mtls-backend.pid \
  ./start_server.sh --mode ws'
```

安装 Nginx 配置：

```bash
sudo cp /opt/SecureChat/deploy/securechat-nginx-mtls.conf /etc/nginx/conf.d/securechat-mtls.conf
sudo nginx -t
sudo systemctl reload nginx
```

如果系统不用 systemd 管理 Nginx，也可以：

```bash
sudo nginx -t
sudo nginx
sudo nginx -s reload
```

使用 systemd backend 模板：

```bash
sudo cp /opt/SecureChat/deploy/securechat-server-mtls-backend.service /etc/systemd/system/securechat-server-mtls-backend.service
sudo systemctl daemon-reload
sudo systemctl enable --now securechat-server-mtls-backend.service
```

Host/Client 连接外部入口：

```bash
export SECURECHAT_MTLS_CLIENT_CERT_FILE=certs/pki/alice-mtls-chain.pem
export SECURECHAT_MTLS_CLIENT_KEY_FILE=certs/pki/alice-mtls-key.pem
```

如果入口服务器证书不是系统信任 CA 签发，再设置：

```bash
export SECURECHAT_TLS_CA_FILE=certs/pki/root-ca.pem
```

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

### Linux CLI 启动顺序

下面只给最小本机 WS 测试命令。完整 PKI、WSS、脚本和 mTLS 步骤见 `docs/startup-guide.md`。

终端 1：启动 Server。

```bash
./out/build/x64-linux-release/server 25566
```

终端 2：配置 Host 的成员 PKI，然后创建房间。

```bash
export SECURECHAT_PKI_TRUST_STORE=certs/pki/root-ca.pem
export SECURECHAT_IDENTITY_CERT_FILE=certs/pki/alice-chain.pem
export SECURECHAT_IDENTITY_KEY_FILE=certs/pki/alice-key.pem
export SECURECHAT_PKI_REVOCATION_FILE=certs/pki/revoked.txt
./out/build/x64-linux-release/host --server ws://127.0.0.1:25566 secure-room alice
```

终端 3：配置 Client 的成员 PKI，然后加入同一个房间。

```bash
export SECURECHAT_PKI_TRUST_STORE=certs/pki/root-ca.pem
export SECURECHAT_IDENTITY_CERT_FILE=certs/pki/bob-chain.pem
export SECURECHAT_IDENTITY_KEY_FILE=certs/pki/bob-key.pem
export SECURECHAT_PKI_REVOCATION_FILE=certs/pki/revoked.txt
./out/build/x64-linux-release/client ws://127.0.0.1:25566 secure-room bob
```

WSS Server：

```bash
export SECURECHAT_SIGNALING_TLS=1
export SECURECHAT_TLS_CERT_FILE=certs/fullchain.pem
export SECURECHAT_TLS_KEY_FILE=certs/privkey.pem
./out/build/x64-linux-release/server 25566
```

脚本启动 Server。Server 默认后台运行：

```bash
chmod +x start_server.sh stop_server.sh start_host.sh stop_host.sh start_client.sh stop_client.sh
./start_server.sh --mode wss
```

脚本以 WS 启动 Server：

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

脚本启动 Host 和 Client。Host/Client 默认前台运行，启动前仍要配置成员 PKI：

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
- 文本和附件 E2EE 使用 GKA v3 自动协商 room group key；Host/Client/Web/WinUI 不再需要设置共享 E2EE 口令。
- 接收附件会写入 `logs/images`、`logs/voice`、`logs/files`。默认缓存总量上限为 512 MB，可用 `SECURECHAT_LOGS_MAX_BYTES` 覆盖，例如 `export SECURECHAT_LOGS_MAX_BYTES=1073741824`。
- `./stop_server.sh`、`./stop_host.sh`、`./stop_client.sh` 会清理各自脚本进程内的 SecureChat 运行时环境变量。普通 stop 脚本不能修改父 shell 中已经 `export` 的变量；如果确实要清理当前 SSH 窗口，可执行对应的 `source ./stop_*.sh` 或手动 `unset`。
- 公网 Server 部署加固、非 root 用户、可选 systemd 模板、SIGTERM 验证、日志清理和安全组来源 IP 收敛步骤见 `docs/deployment-hardening.md`。

- 所有 `SECURECHAT_*` 环境变量的完整说明见 `docs/environment-variables.md`。
