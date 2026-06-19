# SecureChat 启动手册

本文档说明 Windows 和 Linux 上启动 Server、Host、Client 的最小流程。当前信令入口使用 WSS，也就是 WebSocket over TLS；Host、Client 和 WinUI 的 Server URL 都必须以 `wss://` 开头。

## 共同前提

同一个房间的 Host 和 Client 需要使用相同的：

- Server URL，例如 `wss://127.0.0.1:25566` 或 `wss://chat.example.com:25566`；
- Room，例如 `secure-room`；
- Room password，在程序提示 `Room password:` 时输入；
- 成员 PKI 信任根，也就是同一个 `root-ca.pem`。

Server 只需要 TLS 证书和监听参数，不需要成员 PKI。Host 和 Client 必须配置成员 PKI，否则会启动失败。

## Server TLS 证书选择

C++ `server` 不写死证书路径。手动启动 Server 时可以设置：

```bash
SECURECHAT_TLS_CERT_FILE
SECURECHAT_TLS_KEY_FILE
```

TLS 证书选择分为两种入口：

1. 手动运行 `server` 或 `server.exe` 时，可以不设置 `SECURECHAT_TLS_CERT_FILE` 和 `SECURECHAT_TLS_KEY_FILE`。C++ Server 会自动生成本地/局域网开发证书。
2. Linux `start_server.sh` 用于云端或长期部署。如果环境变量没设置，脚本会直接使用 `certs/fullchain.pem` 和 `certs/privkey.pem`。

`certs/fullchain.pem` 和 `certs/privkey.pem` 适合放 Certbot 签发的正式域名证书。它们通常只适合证书覆盖的域名，例如 `wss://chat.example.com:25566`，不能直接用于 `wss://127.0.0.1:25566` 或局域网 IP。

自动生成的开发证书会产生类似这些文件：

```text
certs/local-root-ca.pem
certs/local-root-ca-key.pem
certs/server-chain.pem
certs/server-key.pem
```

CLI Host/Client 连接自动生成的开发证书时，需要设置 `SECURECHAT_LOCAL_TLS_CA=certs/local-root-ca.pem`。WinUI 连接自动生成的开发证书时，在设置面板的 `Local Server TLS CA / 本地服务器 TLS 信任根` 中选择 `local-root-ca.pem`。

## Windows：构建

在 PowerShell 进入项目根目录：

```powershell
D:
cd D:\Programming\CyberSecurity\Lessons\Experiment\SecureChat
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

## Windows：启动 Server

Windows 手动启动 Server 时，如果要做本机/局域网测试，保持 TLS 路径环境变量为空：

```powershell
Remove-Item Env:SECURECHAT_TLS_CERT_FILE -ErrorAction SilentlyContinue
Remove-Item Env:SECURECHAT_TLS_KEY_FILE -ErrorAction SilentlyContinue
.\out\build\x64-release\server.exe 25566
```

Server 会自动生成 `certs/server-chain.pem`、`certs/server-key.pem` 和 `certs/local-root-ca.pem`。如果要使用正式域名证书，可以显式设置 `SECURECHAT_TLS_CERT_FILE` 和 `SECURECHAT_TLS_KEY_FILE`。

## Windows：启动 Host

新开一个 PowerShell 窗口，配置 Host 的成员 PKI：

```powershell
$env:SECURECHAT_PKI_TRUST_STORE="certs\pki\root-ca.pem"
$env:SECURECHAT_IDENTITY_CERT_FILE="certs\pki\alice-chain.pem"
$env:SECURECHAT_IDENTITY_KEY_FILE="certs\pki\alice-key.pem"
```

如果 Server 使用私有 CA 或自动生成的开发 TLS 证书，CLI 还需要信任对应 Server CA：

```powershell
$env:SECURECHAT_LOCAL_TLS_CA="certs\local-root-ca.pem"
```

创建房间：

```powershell
.\out\build\x64-release\host.exe --server wss://127.0.0.1:25566 secure-room alice
```

看到 `Room password:` 后输入房间密码。输入时不会显示字符。

## Windows：启动 Client

新开一个 PowerShell 窗口，配置 Client 的成员 PKI：

```powershell
$env:SECURECHAT_PKI_TRUST_STORE="certs\pki\root-ca.pem"
$env:SECURECHAT_IDENTITY_CERT_FILE="certs\pki\bob-chain.pem"
$env:SECURECHAT_IDENTITY_KEY_FILE="certs\pki\bob-key.pem"
```

如果 Server 使用私有 CA 或自动生成的开发 TLS 证书，同样设置：

```powershell
$env:SECURECHAT_LOCAL_TLS_CA="certs\local-root-ca.pem"
```

加入房间：

```powershell
.\out\build\x64-release\client.exe wss://127.0.0.1:25566 secure-room bob
```

看到 `Room password:` 后输入和 Host 相同的房间密码。

## Windows：WinUI

WinUI 不启动 Server，也不配置 Server 私钥。使用 WinUI 前，需要先启动一个正在监听的 WSS Server。

双击运行：

```text
app\chat\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\SecureChat.exe
```

第一次使用时，点击设置面板，选择当前成员的应用层 PKI 文件：

- Trust store / 信任根：`root-ca.pem`；
- Identity cert chain / 成员证书链：例如 `alice-chain.pem` 或 `bob-chain.pem`；
- Identity private key / 成员私钥：例如 `alice-key.pem` 或 `bob-key.pem`；
- Identity key passphrase / 成员私钥口令：只有私钥加密时填写，且不会保存到配置文件。

WinUI 的 Server URL 必须填写 `wss://...`。如果 Server 使用 Certbot 等系统信任 CA 签发的证书，WinUI 不需要额外配置 Server CA。如果 Server 使用自动生成的开发证书，在设置面板的 `Local Server TLS CA / 本地服务器 TLS 信任根` 中选择 `certs/local-root-ca.pem`。

Host 页填写 Room、User、Server URL、Password 后点击 Host/Create。Join 页填写同一个 Room、当前 User、同一个 Server URL、同一个 Password 后点击 Join。

## Linux：构建

```bash
cd ~/SecureChat
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

## Linux：启动 Server

本机/局域网测试推荐直接运行 Server 可执行文件，并保持 TLS 路径环境变量为空：

```bash
cd ~/SecureChat
unset SECURECHAT_TLS_CERT_FILE SECURECHAT_TLS_KEY_FILE
./out/build/x64-linux-release/server 25566
```

Server 会自动生成本地/局域网开发证书，并输出类似：

```text
generated local WSS certificate:
  cert: certs/server-chain.pem
  key:  certs/server-key.pem
  CA:   certs/local-root-ca.pem
```

云端或长期部署推荐使用脚本启动：

```bash
cd ~/SecureChat
chmod +x start_server.sh stop_server.sh
./start_server.sh
```

脚本会把空的 TLS 路径环境变量设置为 `certs/fullchain.pem` 和 `certs/privkey.pem`。云服务器上可以把 Certbot 证书复制或软链接到这两个路径。

停止脚本启动的 Server：

```bash
./stop_server.sh
```

## Linux：启动 Host

新开终端，配置 Host 的成员 PKI：

```bash
cd ~/SecureChat
export SECURECHAT_PKI_TRUST_STORE=certs/pki/root-ca.pem
export SECURECHAT_IDENTITY_CERT_FILE=certs/pki/alice-chain.pem
export SECURECHAT_IDENTITY_KEY_FILE=certs/pki/alice-key.pem
```

如果 Server 使用自动生成的开发证书，设置：

```bash
export SECURECHAT_LOCAL_TLS_CA=certs/local-root-ca.pem
```

创建房间：

```bash
./out/build/x64-linux-release/host --server wss://127.0.0.1:25566 secure-room alice
```

看到 `Room password:` 后输入房间密码。

## Linux：启动 Client

新开终端，配置 Client 的成员 PKI：

```bash
cd ~/SecureChat
export SECURECHAT_PKI_TRUST_STORE=certs/pki/root-ca.pem
export SECURECHAT_IDENTITY_CERT_FILE=certs/pki/bob-chain.pem
export SECURECHAT_IDENTITY_KEY_FILE=certs/pki/bob-key.pem
```

如果 Server 使用自动生成的开发证书，设置：

```bash
export SECURECHAT_LOCAL_TLS_CA=certs/local-root-ca.pem
```

加入房间：

```bash
./out/build/x64-linux-release/client wss://127.0.0.1:25566 secure-room bob
```

看到 `Room password:` 后输入和 Host 相同的房间密码。

## Linux：局域网

Server 机器运行：

```bash
unset SECURECHAT_TLS_CERT_FILE SECURECHAT_TLS_KEY_FILE
./out/build/x64-linux-release/server 25566
```

自动生成开发证书时，Server 会把当前主机名、`localhost`、`127.0.0.1` 和探测到的局域网 IP 写入证书的 Subject Alternative Name。自动生成路径只用于本机和局域网测试，不生成公网域名证书；公网域名证书应使用 Certbot 等外部工具获取，并通过 `SECURECHAT_TLS_CERT_FILE` 和 `SECURECHAT_TLS_KEY_FILE` 显式传入。

其他机器连接时使用证书覆盖的名称或 IP，并把 `certs/local-root-ca.pem` 通过可信渠道复制到客户端机器。CLI 设置 `SECURECHAT_LOCAL_TLS_CA`，WinUI 在设置面板选择该 CA 文件。

## Linux：Nginx TLS 反向代理

公网可使用 Nginx 监听 WSS 入口，SecureChat Server 只监听本机 backend。

拓扑：

```text
Host/Client -- wss --> Nginx:25566 -- wss --> SecureChat Server 127.0.0.1:25567
```

安装 Nginx：

```bash
sudo apt update
sudo apt install -y nginx openssl certbot python3-certbot-nginx
```

申请域名证书：

```bash
sudo certbot certonly --nginx -d chat.example.com
```

启动本机 backend：

```bash
cd /opt/SecureChat
export SECURECHAT_BIND_ADDRESS=127.0.0.1
export SECURECHAT_PORT=25567
export SECURECHAT_SERVER_PID_FILE=server-backend.pid
export SECURECHAT_SERVER_LOG_FILE=server-backend.log
./start_server.sh
```

Nginx 配置示例：

```nginx
server {
    listen 25566 ssl;
    server_name chat.example.com;

    ssl_certificate     /etc/letsencrypt/live/chat.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chat.example.com/privkey.pem;

    location / {
        proxy_pass https://127.0.0.1:25567;
        proxy_ssl_verify off;

        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

检查并加载配置：

```bash
sudo nginx -t
sudo nginx -s reload
```

Host/Client 连接 Nginx 入口：

```bash
./out/build/x64-linux-release/host --server wss://chat.example.com:25566 secure-room alice
./out/build/x64-linux-release/client wss://chat.example.com:25566 secure-room bob
```

## 常用聊天命令

群发文本：直接输入文本。

私发文本：

```text
/to <成员名> <消息>
```

发送附件：

```text
/image <path>
/voice <path>
/file <path>
```

私发附件：

```text
/to <成员名> /image <path>
/to <成员名> /voice <path>
/to <成员名> /file <path>
```

Host 管理命令：

```text
/silence <成员名>
/unsilence <成员名>
/evict <成员名>
/ban <成员名>
```

