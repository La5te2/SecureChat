# SecureChat 启动手册

本文档回答：在 Windows 和 Linux 上怎样启动 Server、Host、Client。

## 角色说明

- Server：监听端口、注册房间、转发密文，只配置监听和传输层相关参数。
- Host：创建房间，是第一个群成员。Host 必须配置成员 PKI，启动后输入房间密码。
- Client：加入房间，是普通群成员。Client 必须配置成员 PKI，启动后输入房间密码。

同一个房间的 Host 和 Client 必须使用相同的：

- Server URL，例如 `ws://127.0.0.1:25566`；
- Room，例如 `secure-room`；
- Room password，在程序提示 `Room password:` 时输入；
- PKI 信任根，也就是同一个 `root-ca.pem`。证书生成步骤见 `docs/pki-identity.md`，其中已经分别给出 Windows PowerShell 和 Linux Bash 命令，并使用 Intermediate CA 签发成员证书。

## Windows：准备工作

在 PowerShell 进入项目根目录：

```powershell
D:
cd D:\Programming\CyberSecurity\Lessons\Experiment\SecureChat
```

构建 C++/WinUI：

```powershell
cmd /c build_win.bat
```

C++ 可执行文件位置：

```text
out\build\x64-release\server.exe
out\build\x64-release\host.exe
out\build\x64-release\client.exe
```

WinUI 可执行文件位置：

```text
app\chat\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\SecureChat.exe
```

## Windows：配置 Host/Client PKI

Server 不需要下面这些变量。每一个要运行 Host 或 Client 的 PowerShell 窗口都要设置：

```powershell
$env:SECURECHAT_PKI_TRUST_STORE="certs\pki\root-ca.pem"
$env:SECURECHAT_IDENTITY_CERT_FILE="certs\pki\alice-chain.pem"
$env:SECURECHAT_IDENTITY_KEY_FILE="certs\pki\alice-key.pem"
```

换另一个成员时，把 `alice-chain.pem` 和 `alice-key.pem` 换成该成员自己的证书和私钥，例如 `bob-chain.pem`、`bob-key.pem`。

## Windows：本机 WS 测试

本机测试不使用 TLS，URL 是 `ws://127.0.0.1:25566`。需要开三个 PowerShell 窗口。

窗口 1：启动 Server。

```powershell
out\build\x64-release\server.exe 25566
```

窗口 2：配置 Host 的 PKI，然后创建房间。

```powershell
$env:SECURECHAT_PKI_TRUST_STORE="certs\pki\root-ca.pem"
$env:SECURECHAT_IDENTITY_CERT_FILE="certs\pki\alice-chain.pem"
$env:SECURECHAT_IDENTITY_KEY_FILE="certs\pki\alice-key.pem"

out\build\x64-release\host.exe --server ws://127.0.0.1:25566 secure-room alice
```

看到 `Room password:` 后输入房间密码。输入时不会显示字符。

窗口 3：配置 Client 的 PKI，然后加入同一个房间。

```powershell
$env:SECURECHAT_PKI_TRUST_STORE="certs\pki\root-ca.pem"
$env:SECURECHAT_IDENTITY_CERT_FILE="certs\pki\bob-chain.pem"
$env:SECURECHAT_IDENTITY_KEY_FILE="certs\pki\bob-key.pem"

out\build\x64-release\client.exe ws://127.0.0.1:25566 secure-room bob
```

看到 `Room password:` 后输入和 Host 相同的房间密码。

## Windows：局域网 WS 测试

Server 所在机器启动：

```powershell
out\build\x64-release\server.exe 25566
```

其他电脑连接时，把 `127.0.0.1` 改成 Server 电脑的局域网 IP。例如 Server 电脑 IP 是 `192.168.1.20`：

```powershell
out\build\x64-release\host.exe --server ws://192.168.1.20:25566 secure-room alice
out\build\x64-release\client.exe ws://192.168.1.20:25566 secure-room bob
```

Windows 防火墙需要允许 Server 机器入站 TCP `25566`。

## Windows：WSS 测试

WSS 需要服务器 TLS 证书：

```text
certs\fullchain.pem
certs\privkey.pem
```

Server 窗口：

```powershell
$env:SECURECHAT_SIGNALING_TLS="1"
$env:SECURECHAT_TLS_CERT_FILE="certs\fullchain.pem"
$env:SECURECHAT_TLS_KEY_FILE="certs\privkey.pem"
out\build\x64-release\server.exe 25566
```

Host/Client 连接时使用 `wss://`：

```powershell
out\build\x64-release\host.exe --server wss://chat.la5te2.online:25566 secure-room alice
out\build\x64-release\client.exe wss://chat.la5te2.online:25566 secure-room bob
```

证书通常签给域名，所以 WSS 推荐用 `chat.la5te2.online`，不要用公网 IP 直接连。

## Windows：WinUI

WinUI 是桌面客户端，普通用户直接双击运行即可。可执行文件位置：

```text
app\chat\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\SecureChat.exe
```

WinUI 不启动 Server。使用 WinUI 前，必须先有一个正在监听的 Server，例如在 PowerShell 中启动本机 Server：

```powershell
out\build\x64-release\server.exe 25566
```

第一次使用 WinUI 时，先点右侧齿轮进入设置面板，在“成员 PKI”区域选择当前成员的身份文件：

- Trust store / 信任根：选择 `root-ca.pem`；
- Identity cert chain / 成员证书链：Host 选择 `alice-chain.pem`，Client 选择 `bob-chain.pem`；
- Identity private key / 成员私钥：Host 选择 `alice-key.pem`，Client 选择 `bob-key.pem`；
- Identity key passphrase / 成员私钥口令：如果私钥加密，启动本次会话前填写；这个口令不会保存到配置文件。

这些路径会保存到 WinUI 同目录的 `config.yml`。Host 和 Join 启动前，WinUI 会把这些设置写入当前进程的 `SECURECHAT_PKI_TRUST_STORE`、`SECURECHAT_IDENTITY_CERT_FILE` 和 `SECURECHAT_IDENTITY_KEY_FILE`，因此不需要为了普通双击启动而提前打开 PowerShell 设置临时环境变量。

WinUI 不配置 Server 端 TLS 证书。是否使用 TLS 由 Server URL 决定：本地可填 `ws://127.0.0.1:25566`，公网 TLS 入口填 `wss://chat.la5te2.online:25566`。如果入口证书是系统已信任 CA 签发，WinUI 不需要额外证书设置；自签证书场景建议先把 CA 导入操作系统信任存储。

Host 页：

- Room：填写房间名，例如 `secure-room`；
- User：填写用户名，例如 `alice`；
- Server URL：填写 `ws://127.0.0.1:25566` 或 `wss://chat.la5te2.online:25566`；
- Password：填写房间密码；
- 点击 Host/Create。

Join 页：

- Room：填写 Host 创建的同一个房间名；
- User：填写当前成员名，例如 `bob`；
- Server URL：填写同一个 Server URL；
- Password：填写同一个房间密码；
- 点击 Join。

如果要在同一台 Windows 机器上测试两个 WinUI 成员，可以复制一份 WinUI 输出目录，或者分别在两份运行目录的设置面板里选择不同的成员证书和私钥。单个 WinUI 进程一次只代表一个成员身份。

## Linux：准备工作

进入项目根目录：

```bash
cd ~/SecureChat
```

构建：

```bash
export VCPKG_ROOT="$HOME/vcpkg"
chmod +x build.sh
./build.sh
```

构建成功后应存在：

```text
out/build/x64-linux-release/server
out/build/x64-linux-release/host
out/build/x64-linux-release/client
```

## Linux：配置 Host/Client PKI

Server 不需要下面这些变量。每一个要运行 Host 或 Client 的终端都要设置：

```bash
export SECURECHAT_PKI_TRUST_STORE=certs/pki/root-ca.pem
export SECURECHAT_IDENTITY_CERT_FILE=certs/pki/alice-chain.pem
export SECURECHAT_IDENTITY_KEY_FILE=certs/pki/alice-key.pem
```

换另一个成员时，把证书和私钥换成该成员自己的文件。

## Linux：本机 WS 测试

需要开三个终端。

终端 1：启动 Server。

```bash
cd ~/SecureChat
./out/build/x64-linux-release/server 25566
```

终端 2：配置 Host 的 PKI，然后创建房间。

```bash
cd ~/SecureChat
export SECURECHAT_PKI_TRUST_STORE=certs/pki/root-ca.pem
export SECURECHAT_IDENTITY_CERT_FILE=certs/pki/alice-chain.pem
export SECURECHAT_IDENTITY_KEY_FILE=certs/pki/alice-key.pem

./out/build/x64-linux-release/host --server ws://127.0.0.1:25566 secure-room alice
```

看到 `Room password:` 后输入房间密码。

终端 3：配置 Client 的 PKI，然后加入同一个房间。

```bash
cd ~/SecureChat
export SECURECHAT_PKI_TRUST_STORE=certs/pki/root-ca.pem
export SECURECHAT_IDENTITY_CERT_FILE=certs/pki/bob-chain.pem
export SECURECHAT_IDENTITY_KEY_FILE=certs/pki/bob-key.pem

./out/build/x64-linux-release/client ws://127.0.0.1:25566 secure-room bob
```

看到 `Room password:` 后输入和 Host 相同的房间密码。

## Linux：脚本启动

脚本会使用环境变量里的默认房间名和用户名。

Server 默认后台运行：

```bash
cd ~/SecureChat
chmod +x start_server.sh stop_server.sh
./start_server.sh --mode ws
```

Host 默认前台运行：

```bash
cd ~/SecureChat
export SECURECHAT_ROOM=secure-room
export SECURECHAT_USER=alice
export SECURECHAT_PKI_TRUST_STORE=certs/pki/root-ca.pem
export SECURECHAT_IDENTITY_CERT_FILE=certs/pki/alice-chain.pem
export SECURECHAT_IDENTITY_KEY_FILE=certs/pki/alice-key.pem

./start_host.sh --server ws://127.0.0.1:25566
```

Client 默认前台运行：

```bash
cd ~/SecureChat
export SECURECHAT_ROOM=secure-room
export SECURECHAT_USER=bob
export SECURECHAT_PKI_TRUST_STORE=certs/pki/root-ca.pem
export SECURECHAT_IDENTITY_CERT_FILE=certs/pki/bob-chain.pem
export SECURECHAT_IDENTITY_KEY_FILE=certs/pki/bob-key.pem

./start_client.sh --server ws://127.0.0.1:25566
```

停止脚本启动的进程：

```bash
./stop_server.sh
./stop_host.sh
./stop_client.sh
```

## Linux：WSS

Server 使用 WSS：

```bash
cd ~/SecureChat
export SECURECHAT_TLS_CERT_FILE=certs/fullchain.pem
export SECURECHAT_TLS_KEY_FILE=certs/privkey.pem
./start_server.sh --mode wss
```

Host/Client 连接：

```bash
./start_host.sh --server wss://chat.la5te2.online:25566
./start_client.sh --server wss://chat.la5te2.online:25566
```

如果证书是自签名或私有 CA 签发，Host/Client 还要设置：

```bash
export SECURECHAT_TLS_CA_FILE=certs/pki/root-ca.pem
```

## Linux：Nginx TLS 反向代理，不使用 systemd

Nginx 对外提供普通 `wss://` TLS 入口，SecureChat Server 只做本机 backend。

拓扑：

```text
Host/Client -- wss --> Nginx:25566 -- ws --> SecureChat Server 127.0.0.1:25567
```

安装 Nginx：

```bash
sudo apt update
sudo apt install -y nginx openssl
sudo nginx -v
```

复制 Nginx 配置：

```bash
sudo cp /opt/SecureChat/deploy/securechat-nginx-tls.conf /etc/nginx/conf.d/securechat-tls.conf
sudo editor /etc/nginx/conf.d/securechat-tls.conf
sudo nginx -t
sudo nginx -s reload
```

启动 SecureChat backend。注意这里是 `ws`，因为它只监听本机 `127.0.0.1:25567`，外部 TLS 已由 Nginx 处理：

```bash
sudo -u securechat -H bash -lc 'cd /opt/SecureChat && \
  SECURECHAT_BIND_ADDRESS=127.0.0.1 \
  SECURECHAT_PORT=25567 \
  SECURECHAT_SERVER_PID_FILE=server-backend.pid \
  ./start_server.sh --mode ws'
```

Host/Client 直接连接 Nginx 的 `wss://` 入口，仍然只需要应用层成员 PKI：

```bash
./start_host.sh --server wss://chat.la5te2.online:25566
```

Client 同理，使用自己的成员 PKI 后连接同一个 `wss://` URL。

停止 backend：

```bash
sudo -u securechat -H bash -lc 'cd /opt/SecureChat && \
  SECURECHAT_PORT=25567 \
  SECURECHAT_SERVER_PID_FILE=server-backend.pid \
  ./stop_server.sh'
```

## 常用聊天命令

群发文本：直接输入文本。

私发文本：

```text
/to <成员名或成员id> <消息>
```

发送附件：

```text
/image <path>
/voice <path>
/file <path>
```

私发附件：

```text
/to <成员名或成员id> /image <path>
/to <成员名或成员id> /voice <path>
/to <成员名或成员id> /file <path>
```

Host 管理命令：

```text
/silence <成员名或成员id>
/unsilence <成员名或成员id>
/evict <成员名或成员id>
/ban <成员名或成员id>
```
