# SecureChat 启动手册

本文档说明 Windows 和 Linux 上启动 Server、Host、Client 的最小流程。当前对外信令入口使用 WSS，也就是 WebSocket over TLS。Host、Client 和 WinUI 从房间目录中的 relay pool 读取连接入口；WinUI 创建房间时从本地 `config.yml` 的 `[pool]` 段读取原始候选 pool。

## 共同前提

同一个房间的 Host 和 Client 需要使用相同的：

- relay pool，也就是一组 `wss://host:port` relay 入口；
- room instance，也就是同一个 `logs/<hosts|clients>/<systemUsername>/<原始房间名>_<digest前8位>` 房间目录；
- 本地/局域网自动 TLS 证书场景下，还需要同一个 `local-root-ca.pem`。

Server 只需要 TLS 证书和监听参数，不需要成员 PKI。Host 和 Client 使用 `--room-dir` 时会从房间目录自动读取 trust store、成员证书链、成员私钥、room instance token 和 relay pool。

relay pool 可以只有一个入口，也可以有多个入口。多个入口时，每行写一个 `wss://host:port`。Host 创建房间时会先对候选入口去重，再用 600ms 默认探测超时筛出当前可连接 relay，并通过 `relay_probe` 返回的 `relayInstanceId` 合并同一 Server backend 的多条访问路径，最后选择最多 4 个 relay 写入 `entrance.scp` 和本机 `relay-pool.sqlite3`。Host 只在这组房间实际 relay set 上创建同一个 room instance；Client 获批后会连接同一组 relay。pool 地址集合在 room instance 生命周期内固定，运行时不新增地址；每次发送时从当前可用子集 `M(t)` 中选择 relay。pending join 使用 admission secret 选择 relay，GKA 完成后的文本和附件分片使用 room group key 选择 relay。

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
out\build\x64-release\cert.exe
```

WinUI 可执行文件位置：

```text
app\winui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\SecureChat.exe
```

## Windows：启动 Server

Windows 手动启动 Server 时，如果要做本机/局域网运行，保持 TLS 路径环境变量为空：

```powershell
Remove-Item Env:SECURECHAT_TLS_CERT_FILE -ErrorAction SilentlyContinue
Remove-Item Env:SECURECHAT_TLS_KEY_FILE -ErrorAction SilentlyContinue
.\out\build\x64-release\server.exe 25566
```

Server 会自动生成 `certs/server-chain.pem`、`certs/server-key.pem` 和 `certs/local-root-ca.pem`。如果要使用正式域名证书，可以显式设置 `SECURECHAT_TLS_CERT_FILE` 和 `SECURECHAT_TLS_KEY_FILE`。

## Windows：准备房间证书目录

在项目根目录执行。`create-entrance` 输出 Host 的房间目录；Client 使用 Host 分发的 `entrance.scp` 执行 `import-entrance` 后，会在本机生成成员私钥和加密运行材料。`roomDir` 末级目录名形如 `<原始房间名>_<digest前8位>`。成员证书由后续联机 `/approve` 自动签发，不需要普通用户手动运行 `sign-csr`。

```powershell
Set-Content -Encoding UTF8 relay-pool.txt "wss://127.0.0.1:25566"
.\out\build\x64-release\cert.exe create-entrance --room secure-room --phrase "use-a-long-random-room-phrase" --host alice --pool relay-pool.txt --out logs
.\out\build\x64-release\cert.exe import-entrance --entrance <host-room-dir>\certs\entrance.scp --phrase "use-a-long-random-room-phrase" --user bob --out logs
```

## Windows：启动 Host

新开一个 PowerShell 窗口。如果 Server 使用私有 CA 或自动生成的开发 TLS 证书，先信任对应 Server CA：

```powershell
$env:SECURECHAT_LOCAL_TLS_CA="certs\local-root-ca.pem"
```

创建房间：

```powershell
.\out\build\x64-release\host.exe --room-dir <host-room-dir> alice
```

## Windows：启动 Client

新开一个 PowerShell 窗口。如果 Server 使用私有 CA 或自动生成的开发 TLS 证书，同样设置：

```powershell
$env:SECURECHAT_LOCAL_TLS_CA="certs\local-root-ca.pem"
```

加入房间：

```powershell
.\out\build\x64-release\client.exe --room-dir <client-room-dir> bob
```

Client 会进入 pending join。回到 Host 窗口先查看 pending requestId，再审批：

```powershell
/list
/approve <requestId>
```

## Windows：WinUI

WinUI 作为 Host/Client 前端运行，Server 由独立进程提供。使用 WinUI 前，需要先启动一个正在监听的 Server。公网和跨主机场景使用 WSS Server；外层代理或隧道后端可以使用 loopback WS Server。

双击运行：

```text
app\winui\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\SecureChat.exe
```

WinUI 的 Host/Join 主界面显示 Room、User 和房间操作按钮。Host 创建房间时从 `config.yml` 的 `[pool]` 段读取 relay pool，每行一个 `wss://host:port`。如果 Server 使用 Certbot 等系统信任 CA 签发的证书，WinUI 可以直接使用系统信任链。如果 Server 使用自动生成的开发证书，在设置面板的 `Local Server TLS CA / 本地服务器 TLS 信任根` 中选择 `certs/local-root-ca.pem`。

Host 页填写 Room 和 User 后点击创建房间，WinUI 会自动生成 `logs/hosts/<systemUsername>/<原始房间名>_<digest前8位>/certs/entrance.scp`。同一个 Host 可以创建多个同名房间，每次创建都会生成新的 room instance 和新的本地 room-dir。Host 页或 Join 页点击“加入房间”时只需要填写 User，WinUI 会弹出该身份下所有本地房间实例；用户确认具体实例后才会连接。Join 页首次加入时填写同一个 Room 和当前 User，点击“导入房间”，并在弹出的文件选择器中选择 Host 分发的 `entrance.scp`。Client 导入后会在 `logs/clients/<systemUsername>/<原始房间名>_<digest前8位>/certs/entrance.scp` 保存准入副本。Client 进入 pending join 后，Host 可以左键灰色 pending 成员卡片允许加入，右键灰色 pending 成员卡片会拒绝该申请。WinUI 不显示 pending requestId。

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
out/build/x64-linux-release/cert
```

## Linux：启动 Server

本机/局域网运行推荐直接运行 Server 可执行文件，并保持 TLS 路径环境变量为空：

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

## Linux：准备房间证书目录

在项目根目录执行。`create-entrance` 输出 Host 的房间目录；Client 使用 Host 分发的 `entrance.scp` 执行 `import-entrance` 后，会在本机生成成员私钥和加密运行材料。`roomDir` 末级目录名形如 `<原始房间名>_<digest前8位>`。成员证书由后续联机 `/approve` 自动签发，不需要普通用户手动运行 `sign-csr`。

```bash
cd ~/SecureChat
printf '%s\n' 'wss://127.0.0.1:25566' > relay-pool.txt
./out/build/x64-linux-release/cert create-entrance --room secure-room --phrase "use-a-long-random-room-phrase" --host alice --pool relay-pool.txt --out logs
./out/build/x64-linux-release/cert import-entrance --entrance <host-room-dir>/certs/entrance.scp --phrase "use-a-long-random-room-phrase" --user bob --out logs
```

## Linux：启动 Host

新开终端。如果 Server 使用自动生成的开发证书，设置：

```bash
cd ~/SecureChat
export SECURECHAT_LOCAL_TLS_CA=certs/local-root-ca.pem
```

创建房间：

```bash
./out/build/x64-linux-release/host --room-dir <host-room-dir> alice
```

## Linux：启动 Client

新开终端。如果 Server 使用自动生成的开发证书，设置：

```bash
cd ~/SecureChat
export SECURECHAT_LOCAL_TLS_CA=certs/local-root-ca.pem
```

加入房间：

```bash
./out/build/x64-linux-release/client --room-dir <client-room-dir> bob
```

Client 会进入 pending join。回到 Host 终端先查看 pending requestId，再审批：

```bash
/list
/approve <requestId>
```

## Linux：局域网

Server 机器运行：

```bash
unset SECURECHAT_TLS_CERT_FILE SECURECHAT_TLS_KEY_FILE
./out/build/x64-linux-release/server 25566
```

自动生成本地证书时，Server 会把当前主机名、`localhost`、`127.0.0.1` 和探测到的局域网 IP 写入证书的 Subject Alternative Name。自动生成路径只用于本机和局域网运行，不生成公网域名证书；公网域名证书应使用 Certbot 等外部工具获取，并通过 `SECURECHAT_TLS_CERT_FILE` 和 `SECURECHAT_TLS_KEY_FILE` 显式传入。

其他机器连接时使用证书覆盖的名称或 IP，并把 `certs/local-root-ca.pem` 通过可信渠道复制到客户端机器。CLI 设置 `SECURECHAT_LOCAL_TLS_CA`，WinUI 在设置面板选择该 CA 文件。

## Linux：Nginx TLS 反向代理

公网可使用 Nginx 监听 WSS 入口，SecureChat Server 监听本机回环 WS backend。

拓扑：

```text
Host/Client -- wss --> Nginx:25566 -- ws --> SecureChat Server 127.0.0.1:25567
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

启动本机回环 backend：

```bash
cd /opt/SecureChat
export SECURECHAT_BIND_ADDRESS=127.0.0.1
export SECURECHAT_PORT=25567
export SECURECHAT_SERVER_PID_FILE=server-backend.pid
./start_server.sh --mode ws
```

Nginx 配置示例：

```nginx
server {
    listen 25566 ssl;
    server_name chat.example.com;

    ssl_certificate     /etc/letsencrypt/live/chat.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chat.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:25567;

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
printf '%s\n' 'wss://chat.example.com:25566' > relay-pool.txt
./out/build/x64-linux-release/cert create-entrance --room secure-room --phrase "use-a-long-random-room-phrase" --host alice --pool relay-pool.txt --out logs
./out/build/x64-linux-release/host --room-dir <host-room-dir> alice
./out/build/x64-linux-release/client --room-dir <client-room-dir> bob
```

## 常用聊天命令

群发文本：直接输入文本。

修改显示昵称：

```text
/nickname <昵称>
/nickname
```

`/nickname <昵称>` 会在当前房间内更新自己的显示昵称；单独输入 `/nickname` 会清除运行时昵称并回退显示 base username。昵称只用于成员列表和消息展示，不用于私发目标、审批、禁言或驱逐匹配。昵称更新经过房间密钥加密，Server 不能读取昵称明文。

私发文本：

```text
/to <fingerprint-prefix> <消息>
```

`fingerprint-prefix` 至少 8 位十六进制字符。WinUI 左键成员卡片会复制该成员证书指纹前 8 位。

发送附件：

```text
/image <path>
/file <path>
```

私发附件：

```text
/to <fingerprint-prefix> /image <path>
/to <fingerprint-prefix> /file <path>
```

`/file` 可发送任意格式文件。CLI 不提供 `/voice <path>`；音频文件如果需要发送，也按普通文件通过 `/file` 发送。WinUI 的 Voice 模式使用按住录音，不选择本地音频文件。

Host 管理命令：

```text
/silence <fingerprint-prefix>
/unsilence <fingerprint-prefix>
/evict <fingerprint-prefix>
```

