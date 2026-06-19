# SecureChat WSS 证书方法

本文档说明当前 WSS 服务器证书的获取和使用方式。这里的 WSS 服务器证书只用于保护 Host/Client 到 Server 的传输通道；成员 PKI 证书用于应用层身份签名，说明见 `docs/pki-identity.md`。

## 文件命名

Linux `start_server.sh` 默认读取：

```text
certs/fullchain.pem
certs/privkey.pem
```

这组文件适合保存 Certbot 或其他 ACME 客户端签发的正式域名证书。

手动运行 `server` 或 `server.exe` 且 TLS 路径环境变量为空时，C++ Server 会生成：

```text
certs/local-root-ca.pem
certs/local-root-ca-key.pem
certs/server-chain.pem
certs/server-key.pem
certs/server-cert.pem
```

这组文件适合本机和局域网测试。CLI Host/Client 连接该证书时设置 `SECURECHAT_LOCAL_TLS_CA=certs/local-root-ca.pem`。WinUI 在设置面板的 `Local Server TLS CA / 本地服务器 TLS 信任根` 中选择 `local-root-ca.pem`。

## Linux：使用 Certbot 申请域名证书

前提：

- 域名已经解析到服务器公网地址；
- 服务器安全组和防火墙允许验证所需端口；
- 证书中的域名和客户端连接 URL 一致。

安装 Certbot：

```bash
sudo apt update
sudo apt install -y certbot python3-certbot-nginx
```

如果服务器上已经使用 Nginx：

```bash
sudo certbot certonly --nginx -d chat.example.com
```

如果没有 Nginx，且 80 端口可临时由 Certbot 占用：

```bash
sudo certbot certonly --standalone -d chat.example.com
```

两种命令生成的证书文件都可以给 SecureChat 或 Nginx 使用。差异只在域名验证方式。

证书通常位于：

```text
/etc/letsencrypt/live/chat.example.com/fullchain.pem
/etc/letsencrypt/live/chat.example.com/privkey.pem
```

复制或软链接到项目默认路径：

```bash
cd ~/SecureChat
mkdir -p certs
sudo cp /etc/letsencrypt/live/chat.example.com/fullchain.pem certs/fullchain.pem
sudo cp /etc/letsencrypt/live/chat.example.com/privkey.pem certs/privkey.pem
sudo chmod 600 certs/privkey.pem
```

启动云端 Server：

```bash
./start_server.sh
```

## 手动指定证书路径

不使用脚本时，可以显式设置：

Windows PowerShell：

```powershell
$env:SECURECHAT_TLS_CERT_FILE="D:\SecureChat\certs\fullchain.pem"
$env:SECURECHAT_TLS_KEY_FILE="D:\SecureChat\certs\privkey.pem"
.\out\build\x64-release\server.exe 25566
```

Linux Bash：

```bash
export SECURECHAT_TLS_CERT_FILE=/etc/letsencrypt/live/chat.example.com/fullchain.pem
export SECURECHAT_TLS_KEY_FILE=/etc/letsencrypt/live/chat.example.com/privkey.pem
./out/build/x64-linux-release/server 25566
```

## 本机和局域网开发证书

保持 TLS 路径环境变量为空即可自动生成：

Windows PowerShell：

```powershell
Remove-Item Env:SECURECHAT_TLS_CERT_FILE -ErrorAction SilentlyContinue
Remove-Item Env:SECURECHAT_TLS_KEY_FILE -ErrorAction SilentlyContinue
.\out\build\x64-release\server.exe 25566
```

Linux Bash：

```bash
unset SECURECHAT_TLS_CERT_FILE SECURECHAT_TLS_KEY_FILE
./out/build/x64-linux-release/server 25566
```

自动生成路径只覆盖本机名、`localhost`、回环地址和探测到的本机网卡 IP。它不接受手动追加公网域名，也不执行域名所有权验证；公网域名证书应使用 Certbot 等外部工具获取后，通过 `SECURECHAT_TLS_CERT_FILE` 和 `SECURECHAT_TLS_KEY_FILE` 显式传入。

## 续期

Let's Encrypt 证书通常有效期为 90 天。续期后重新复制或更新软链接，并重启 Server：

```bash
sudo certbot renew
cd ~/SecureChat
sudo cp /etc/letsencrypt/live/chat.example.com/fullchain.pem certs/fullchain.pem
sudo cp /etc/letsencrypt/live/chat.example.com/privkey.pem certs/privkey.pem
./stop_server.sh
./start_server.sh
```

## 注意事项

- 不要提交 `certs/` 中的私钥。
- `certs/fullchain.pem` 和 `certs/privkey.pem` 通常是域名证书，不适合直接用于 `wss://127.0.0.1` 或局域网 IP。
- 本地开发 CA `local-root-ca.pem` 可以分发给测试客户端用于信任本地 Server；`local-root-ca-key.pem` 是私钥，不能分发。
- WSS 只保护传输通道；聊天内容仍由应用层加密中继保护。

