# SecureChat

SecureChat 是一个双向通信实验项目，包含共享 C++ 核心、Windows WinUI 桌面端、命令行 Host/Client 工具，以及跨平台 ASP.NET Core Web UI。

## 组件

- `src/` 和 `include/`：C++ 信令服务器、WebRTC DataChannel 会话、附件传输、CLI 和 native API。
- `app/chat/`：Windows WinUI 桌面客户端。
- `app/web/`：Windows/Linux 可用的 ASP.NET Core Web UI。
- `build.bat`：Windows 上只构建 C++。
- `build_win.bat`：Windows 上构建 C++ 和 WinUI。
- `build_web.bat`：Windows 上构建 C++ 和 Web UI。
- `build.sh`：Linux 上（云服务器）只构建 C++。
- `build_web.sh`：Linux 上（非云服务器）构建 C++ 和 Web UI。

## 安全说明

SecureChat 当前更适合作为课程/论文实验系统，而不是已经完成加固的公网生产服务。

公网 Host 常开时，主要暴露面是：

- TCP `25566`：WebSocket 信令端口，用于创建/加入房间，以及交换 SDP/ICE。
- UDP `32768-60999`：WebRTC ICE/DataChannel 候选端口。

需要明确：

- 信令支持 `ws://` insecure mode 和 `wss://` secure mode。`ws://` 配置简单、便于本地或无证书场景使用，但传输不加密；真实公网部署应使用 `wss://`。
- WebRTC DataChannel 本身有传输层加密，但这不等于严格端到端群聊加密。
- 如果云服务器运行的是聊天 Host，它在应用层能看到消息和附件内容。
- STUN 只解决公网/NAT 可达性，不提供保密性。
- 房间密码能阻止普通误入，但不能替代 TLS、限速、防火墙和强认证。
- 能限制安全组来源 IP 时，不建议长期使用 `0.0.0.0/0`。
- 不建议把 Web UI 端口 `5188` 直接暴露到公网。
- 长期运行时应尽量使用普通用户，不要用 `root`。
- `start.sh` 默认不保存 `host.log`。Host 输出可能包含 room id、用户名、ICE 和连接状态，只在临时排障时显式启用日志。
- `start.sh` 默认隐藏读取房间密码，并通过短生命周期本地管道传给 Host，避免密码出现在命令行或 Host 进程环境变量中。
- 接收附件会写入 `logs/`，需要定期清理并避免直接信任未知文件。

信令安全细节见：

```text
docs/signaling-security.md
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

启动 Host：

```bash
cd /SecureChat
./out/build/x64-linux-release/host secure-room 25566 host
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

华为云安全组需要放行：

```text
TCP 25566
UDP 32768-60999
```

Ubuntu 防火墙：

```bash
sudo ufw allow 25566/tcp
sudo ufw allow 32768:60999/udp
sudo ufw status
```

检查 Host 是否监听：

```bash
ss -lntp | grep ':25566'
```

Windows 测试公网 TCP：

```powershell
Test-NetConnection 124.70.71.65 -Port 25566
```

## STUN 和 ICE

TCP `25566` 只能表示能进入信令服务器。真正聊天需要 WebRTC DataChannel 打开。

云服务器常见情况是：服务器网卡只有内网 IP，公网 IP 由云厂商 NAT 映射。如果没有 STUN，WebRTC 可能把内网 ICE 地址发给客户端，导致：

```text
Data channel is not open yet
Peer connection ended
```

推荐公网 Host 启动前设置：

```bash
export SECURECHAT_ICE_SERVERS="stun:stun.cloudflare.com:3478"
```

写入 `~/.bashrc` 可长期生效：

```bash
echo 'export SECURECHAT_ICE_SERVERS="stun:stun.cloudflare.com:3478"' >> ~/.bashrc
source ~/.bashrc
```

## 后台运行 Host

如果 Host 需要自己输入消息，使用 `tmux`：

```bash
tmux new -s securechat
cd /SecureChat
export SECURECHAT_ICE_SERVERS="stun:stun.cloudflare.com:3478"
./out/build/x64-linux-release/host secure-room 25566 host
```

挂起但保持运行：

```text
Ctrl+B
D
```

重新进入：

```bash
tmux attach -t securechat
```

关闭会话：

```bash
tmux kill-session -t securechat
```

如果 Host 只需要常驻，不需要从终端发消息，用 `start.sh`：

```bash
cd /SecureChat
export SECURECHAT_ICE_SERVERS="stun:stun.cloudflare.com:3478"
./start.sh
```

`start.sh` 会提示输入房间密码，输入时不会回显。

非交互启动可以从 stdin 传入密码：

```bash
printf '%s\n' 'your-password' | ./start.sh
```

`SECURECHAT_ROOM_PASSWORD` 仍可用于自动化兼容，但交互使用时不推荐把密码写入 shell 命令或 `.bashrc`。

启用 WSS：

```bash
cd /SecureChat
export SECURECHAT_SIGNALING_TLS=1
export SECURECHAT_TLS_CERT_FILE=/path/fullchain.pem
export SECURECHAT_TLS_KEY_FILE=/path/privkey.pem
./start.sh
```

客户端连接：

```text
wss://your-domain.example:25566
```

`ws://` 和 `wss://` 不能在同一个端口同时开启。需要同时保留 insecure mode 和 secure mode 时，分别用不同端口运行，或停止后切换模式重启。

查看：

```bash
cat host.pid
ss -lntp | grep ':25566'
```

默认不保存日志。需要临时排障时显式启用：

```bash
export SECURECHAT_LOG_FILE=host.log
./start.sh
tail -f host.log
```

排障后建议删除 `host.log`，不要长期保存房间运行信息。

关闭：

```bash
./stop.sh
```

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

因此建议总是从项目根目录启动：

```bash
cd /SecureChat
./out/build/x64-linux-release/host secure-room 25566 host
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
Data channel is not open yet
Peer connection ended
```

检查 STUN、UDP 端口。若需要日志，先用 `SECURECHAT_LOG_FILE=host.log ./start.sh` 临时启用：

```bash
echo "$SECURECHAT_ICE_SERVERS"
sudo ufw status
ss -lntp | grep ':25566'
```

Host 仍然监听但新连接 timeout：

```bash
ss -lntp | grep ':25566'
```

可先重启 Host：

```bash
cd /SecureChat
./stop.sh
./start.sh
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
