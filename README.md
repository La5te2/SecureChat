# SecureChat

SecureChat 是一个双向通信实验项目，包含共享 C++ 核心、Windows WinUI 桌面端、命令行 Host/Client 工具，以及跨平台 ASP.NET Core Web UI。

## 组件

- `src/` 和 `include/`：C++ 信令服务器、WebSocket encrypted relay 数据通路、附件传输、CLI 和 native API。
- `app/chat/`：Windows WinUI 桌面客户端。
- `app/web/`：Windows/Linux 可用的 ASP.NET Core Web UI。
- `build.bat`：Windows 上只构建 C++。
- `build_win.bat`：Windows 上构建 C++ 和 WinUI。
- `build_web.bat`：Windows 上构建 C++ 和 Web UI。
- `build.sh`：Linux 上（云服务器）只构建 C++。
- `build_web.sh`：Linux 上（非云服务器）构建 C++ 和 Web UI。

说明：当前仍依赖 libdatachannel，是因为项目使用它的 WebSocket/WebSocketServer 实现；Host/Client 不再建立 WebRTC PeerConnection/DataChannel。

## 安全说明

SecureChat 当前更适合作为课程/论文实验系统，而不是已经完成加固的公网生产服务。

公网 Server 常开时，主要暴露面是：

- TCP `25566`：WebSocket 信令和 opaque encrypted relay 端口，用于创建/加入房间、维护成员状态，以及转发密文 envelope。

需要明确：

- 信令支持 `ws://` insecure mode 和 `wss://` secure mode。`ws://` 配置简单、便于本地或无证书场景使用，但传输不加密；真实公网部署应使用 `wss://`。
- 文本消息和附件 metadata/chunk 已走应用层 AES-256-GCM encrypted relay：Server 只转发 opaque envelope，不能解密应用内容。
- Host/Client 使用 GKA v2：Client 加入时提交临时 X25519 public key，Host 生成 room group key，并为每个成员封装分发；文本和附件使用该 group key 做 AES-256-GCM。
- 成员加入或离开时，Host 会轮换新的 room group key 并重新分发给当前成员。当前仍未实现长期身份密钥/指纹校验，因此恶意或被攻破的 Server 仍可能尝试公钥替换攻击；公网应使用 `wss://` 降低信令篡改风险。
- 房间密码能阻止普通误入，但不能替代 TLS、限速、防火墙和强认证。
- 能限制安全组来源 IP 时，不建议长期使用 `0.0.0.0/0`。
- 不建议把 Web UI 端口 `5188` 直接暴露到公网。
- 长期运行时应尽量使用普通用户，不要用 `root`。
- `start_server.sh` 默认把 Server 作为 daemon 常驻，且默认不保存 `server.log`。日志可能包含 room id、用户名和连接状态，只在临时排障时显式启用。
- `start_host.sh` 和 `start_client.sh` 默认前台运行；只有显式 `--daemon` 时才后台运行，并通过短生命周期本地管道传递房间密码。
- 接收附件会写入 `logs/`，需要定期清理并避免直接信任未知文件。

信令和 relay 数据通路安全细节见：

```text
docs/signaling-security.md
docs/relay-attachment-security.md
```

## Windows 构建

只构建 C++：

```bat
build.bat
```

构建 WinUI：

```bat
build_win.bat
```

构建 Web UI：

```bat
build_web.bat
```

运行 Windows Web UI：

```bat
dotnet app\web\bin\Release\net10.0\win-x64\SecureChat.Web.dll --urls http://127.0.0.1:5188
```

浏览器打开：

```text
http://127.0.0.1:5188
```

## Linux 环境配置

安装基础工具：

```bash
sudo apt update
sudo apt install -y build-essential ninja-build git curl wget zip unzip tar pkg-config ca-certificates
```

如果系统 CMake 太旧，可以安装新版：

```bash
sudo snap install cmake --classic
hash -r
cmake --version
```

如果需要 Web UI，安装 .NET：

```bash
wget --no-check-certificate https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh
chmod +x dotnet-install.sh
./dotnet-install.sh --channel 10.0 --install-dir "$HOME/.dotnet"

echo 'export DOTNET_ROOT="$HOME/.dotnet"' >> ~/.bashrc
echo 'export PATH="$HOME/.dotnet:$PATH"' >> ~/.bashrc
source ~/.bashrc

dotnet --info
```

安装 vcpkg：

```bash
cd ~
git clone --depth 1 https://github.com/microsoft/vcpkg.git
cd ~/vcpkg
./bootstrap-vcpkg.sh

echo 'export VCPKG_ROOT="$HOME/vcpkg"' >> ~/.bashrc
source ~/.bashrc
```

安装 C++ 依赖：

```bash
$VCPKG_ROOT/vcpkg install libdatachannel openssl nlohmann-json --triplet x64-linux
```

## Linux 构建

只构建 C++：

```bash
cd /SecureChat
chmod +x build.sh
./build.sh
```

成功后应生成：

```text
out/build/x64-linux-release/host
out/build/x64-linux-release/client
out/build/x64-linux-release/server
out/build/x64-linux-release/libnative.so
```

构建 Web UI：

```bash
cd /SecureChat
chmod +x build_web.sh
./build_web.sh
```

## Host 和 Join

Web UI 端口 `5188` 只是浏览器界面端口，不是聊天室端口。

聊天室信令端口示例为：

```text
25566
```

启动不可信 Server：

```bash
./out/build/x64-linux-release/server 25566
```

群主 Host 作为可见成员连接 Server：

```bash
./out/build/x64-linux-release/host --server ws://127.0.0.1:25566 secure-room host
```

其他机器加入：

```text
ws://HOST_IP:25566
```

华为云示例：

```text
ws://124.70.71.65:25566
```

上面的 `ws://` 是 insecure mode，配置简单但信令明文。公网安全连接应改用 WSS，例如：

```text
wss://your-domain.example:25566
```

Linux CLI 加入：

```bash
./out/build/x64-linux-release/client ws://124.70.71.65:25566 secure-room user1
```

## 公网云服务器部署

华为云安全组至少需要放行：

```text
TCP 25566
```

Ubuntu 防火墙：

```bash
sudo ufw allow 25566/tcp
sudo ufw status
```

检查 Server 是否监听：

```bash
ss -lntp | grep ':25566'
```

Windows 测试公网 TCP：

```powershell
Test-NetConnection 124.70.71.65 -Port 25566
```

聊天文本和附件的应用数据都走 TCP `25566` 上的 WebSocket encrypted relay；当前代码不再建立 WebRTC/DataChannel，也不需要 STUN 或 UDP 候选端口。

## 运行 Server、Host 和 Client

阶段 3 起推荐把不可信转发者和群成员拆开：`server` 是公网常驻的不可信协调者，不是群成员，不会显示在成员列表中；Host 和 Client 都是需要输入房间密码的可见参与者。

同一个 Server 实例可以承载多个不同 `roomId`，但同一个 Server 实例内 `roomId` 不能重复；不同 Server 或不同端口上的房间名可以重复。一台机器可以启动多个 Server，只要监听端口不同。

Host 创建 roomId 后成为第一个群成员和群管理者。Client 加入时把临时 X25519 public key 发给 Server，Server 只转交给 Host；Host 生成/轮换 room group key，并把 group key 用每个 Client 的 public key 单独封装后交给 Server 转发。Server 不生成群密钥，不解密 group key envelope，也不参与密钥协商语义。

公网 Server 默认用 daemon 脚本后台运行：

```bash
cd /SecureChat
chmod +x start_server.sh stop_server.sh start_host.sh stop_host.sh start_client.sh stop_client.sh
./start_server.sh --mode wss
```

`--mode wss` 默认使用：

```text
certs/fullchain.pem
certs/privkey.pem
```

本地或无证书环境可以显式使用 WS：

```bash
./start_server.sh --mode ws
```

群主 Host 默认前台运行，作为可见成员连接 Server：

```bash
./start_host.sh --server wss://chat.la5te2.online:25566
```

其他成员用 Client 加入：

```bash
./start_client.sh --server wss://chat.la5te2.online:25566
```

`start_host.sh` 和 `start_client.sh` 会由底层 CLI 隐藏提示房间密码；前台模式可继续从终端发送消息和文件命令。

当前阶段文本消息和附件命令 `/image`、`/file`、`/voice` 都通过 Server relay 转发密文；附件 metadata 和二进制 chunk 会在发送端加密，接收端解密后写入本地附件缓存。代码层不再建立 WebRTC/DataChannel。

如果 Host 或 Client 确实要后台运行，必须显式加 `--daemon`，并从 stdin 或环境变量提供房间密码：

```bash
printf '%s\n' 'your-password' | ./start_host.sh --server wss://chat.la5te2.online:25566 --daemon
printf '%s\n' 'your-password' | ./start_client.sh --server wss://chat.la5te2.online:25566 --daemon
```

查看和停止：

```bash
cat server.pid
ss -lntp | grep ':25566'
./stop_server.sh
./stop_host.sh
./stop_client.sh
```

默认不保存日志。需要临时排障时显式启用：

```bash
export SECURECHAT_SERVER_LOG_FILE=server.log
./start_server.sh --mode wss
tail -f server.log
```

排障后建议删除日志，不要长期保存房间运行信息。

`ws://` 和 `wss://` 不能在同一个端口同时开启。需要同时保留 insecure mode 和 secure mode 时，分别用不同端口运行，或停止后切换模式重启。

## 附件

支持并校验：

- 图片：PNG、JPEG、BMP
- 语音：WAV
- 普通文件：TXT、MD、LOG、CSV、JSON、XML、YAML、INI、CONF、CFG 等文本类文件

大小限制：

- 图片：10 MB
- 文件：50 MB
- 语音：100 MB

接收文件保存到当前工作目录下：

```text
logs/images
logs/voice
logs/files
```

附件缓存默认总量上限为 512 MB。可通过环境变量覆盖：

```bash
export SECURECHAT_LOGS_MAX_BYTES=1073741824
```

接收端会清理最旧的受管理附件缓存文件，但只清理 `logs/images`、`logs/voice`、`logs/files`。文件扩展名和文件头校验只能降低误传/伪装风险，不等于杀毒。

因此建议总是从项目根目录启动：

```bash
cd /SecureChat
./out/build/x64-linux-release/host --server ws://127.0.0.1:25566 secure-room host
```

## 常见问题

端口被占用：

```bash
ss -lntp | grep ':25566'
kill PID
```

公网 TCP 不通：

```powershell
Test-NetConnection 124.70.71.65 -Port 25566
```

如果 `TcpTestSucceeded` 是 `False`，检查云安全组和 `ufw`。

进入房间但不能发送：

```text
Waiting for room group key
```

检查 Host 是否仍在线、Server 是否能把 `group_key` envelope 转发给 Client，以及 Client 是否已经完成 joined 流程。若需要日志，先用 `SECURECHAT_SERVER_LOG_FILE=server.log ./start_server.sh --mode wss` 临时启用 Server 日志；Host 端可用 `SECURECHAT_LOG_FILE=host.log ./start_host.sh --server wss://chat.la5te2.online:25566 --daemon` 临时排障：

```bash
sudo ufw status
ss -lntp | grep ':25566'
```

Server 仍然监听但新连接 timeout：

```bash
ss -lntp | grep ':25566'
```

可先重启 Server，并重新启动 Host：

```bash
cd /SecureChat
./stop_server.sh
./start_server.sh --mode wss
./start_host.sh --server wss://chat.la5te2.online:25566
```

## 代理说明

Linux 本机有代理：

```bash
export HTTP_PROXY=http://127.0.0.1:7897
export HTTPS_PROXY=http://127.0.0.1:7897
export http_proxy=http://127.0.0.1:7897
export https_proxy=http://127.0.0.1:7897
```

代理在 Windows，本机通过 SSH 连接服务器：

```powershell
ssh -R 7897:127.0.0.1:7897 MS
```

然后服务器上：

```bash
export HTTP_PROXY=http://127.0.0.1:7897
export HTTPS_PROXY=http://127.0.0.1:7897
export http_proxy=http://127.0.0.1:7897
export https_proxy=http://127.0.0.1:7897
```
