# SecureChat WSS 证书方法

SecureChat 的 WSS 只需要两个 PEM 文件：

```text
certs/fullchain.pem
certs/privkey.pem
```

其中：

- `fullchain.pem`：证书链，传给 `SECURECHAT_TLS_CERT_FILE`
- `privkey.pem`：私钥，传给 `SECURECHAT_TLS_KEY_FILE`

项目里的 `certs/` 是推荐的本地证书放置目录，方便 Linux 和 Windows 的独立 Server 使用同一套路径。`certs/` 已在 `.gitignore` 中，不应提交证书和私钥。

本文件主要讲 WSS 服务器证书。阶段 9 的 Host/Client 成员身份签名证书使用 `SECURECHAT_PKI_TRUST_STORE`、`SECURECHAT_IDENTITY_CERT_FILE` 和 `SECURECHAT_IDENTITY_KEY_FILE`，说明见 `docs/pki-identity.md`。这两类证书都可以放在 `certs/` 下，但用途不同，不能混用。

## 域名要求

公网 WSS 推荐使用域名，例如：

```text
chat.la5te2.online -> 124.70.71.65
```

客户端应连接：

```text
wss://chat.la5te2.online:25566
```

不要用：

```text
wss://124.70.71.65:25566
```

原因是证书通常签给域名，不签给 IP。即使服务器 IP 正确，客户端也可能因为证书名称不匹配而拒绝连接。

## Linux：Certbot 申请证书

适用场景：

- 域名已经解析到云服务器 IP；
- 云服务器安全组放行 TCP 80；
- 80 端口没有被其他服务占用，或可以临时释放。

确认 DNS：

```bash
nslookup chat.la5te2.online
```

应该看到：

```text
Address: 124.70.71.65
```

安装 Certbot：

```bash
sudo snap install core
sudo snap refresh core
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
```

申请证书：

```bash
sudo certbot certonly --standalone -d chat.la5te2.online
```

成功后，Certbot 的原始证书文件通常在：

```text
/etc/letsencrypt/live/chat.la5te2.online/fullchain.pem
/etc/letsencrypt/live/chat.la5te2.online/privkey.pem
```

## Linux：复制到项目 certs/

SecureChat 推荐从项目目录读取证书：

```bash
cd ~/SecureChat
mkdir -p certs
sudo cp /etc/letsencrypt/live/chat.la5te2.online/fullchain.pem certs/fullchain.pem
sudo cp /etc/letsencrypt/live/chat.la5te2.online/privkey.pem certs/privkey.pem
sudo chmod 600 certs/fullchain.pem certs/privkey.pem
```

如果当前用户不是 root，且后续用当前用户运行 Host，还需要把文件所有者改回来：

```bash
sudo chown "$USER:$USER" certs/fullchain.pem certs/privkey.pem
```

启动 WSS：

```bash
export SECURECHAT_SIGNALING_TLS=1
export SECURECHAT_TLS_CERT_FILE=certs/fullchain.pem
export SECURECHAT_TLS_KEY_FILE=certs/privkey.pem
./start_server.sh --mode wss
```

如果使用 C++ CLI 直接启动：

```bash
export SECURECHAT_SIGNALING_TLS=1
export SECURECHAT_TLS_CERT_FILE=certs/fullchain.pem
export SECURECHAT_TLS_KEY_FILE=certs/privkey.pem
./out/build/x64-linux-release/server 25566
```

切回 WS：

```bash
export SECURECHAT_SIGNALING_TLS=0
./start_server.sh --mode ws
```

或者清理环境变量：

```bash
unset SECURECHAT_SIGNALING_TLS
unset SECURECHAT_TLS_CERT_FILE
unset SECURECHAT_TLS_KEY_FILE
./start_server.sh --mode ws
```

## Linux：续期后更新 certs/

Let’s Encrypt 证书通常有效期为 90 天。查看证书：

```bash
sudo certbot certificates
```

续期：

```bash
sudo certbot renew
```

续期后，重新复制到项目 `certs/`：

```bash
cd ~/SecureChat
sudo cp /etc/letsencrypt/live/chat.la5te2.online/fullchain.pem certs/fullchain.pem
sudo cp /etc/letsencrypt/live/chat.la5te2.online/privkey.pem certs/privkey.pem
sudo chmod 600 certs/fullchain.pem certs/privkey.pem
```

如果 Server 正在运行，需要重启，让它重新读取证书：

```bash
./stop_server.sh
./start_server.sh --mode wss
```

## Windows：使用 certs/

Windows 上也可以使用同样的目录：

```text
D:\Programming\CyberSecurity\Lessons\Experiment\SecureChat\certs\fullchain.pem
D:\Programming\CyberSecurity\Lessons\Experiment\SecureChat\certs\privkey.pem
```

WinUI 现在不配置 Server 证书路径。它作为 Host/Client 连接外部 Server，只需要在 Host 或 Join 页面填写：

```text
wss://chat.la5te2.online:25566
```

证书和私钥只配置在独立 Server 进程上。

Windows C++ Server：

```bat
set SECURECHAT_SIGNALING_TLS=1
set SECURECHAT_TLS_CERT_FILE=certs\fullchain.pem
set SECURECHAT_TLS_KEY_FILE=certs\privkey.pem
out\build\x64-release\server.exe 25566
```

切回 WS：

```bat
set SECURECHAT_SIGNALING_TLS=0
out\build\x64-release\server.exe 25566
```

## Windows：获得 PEM 证书

Windows 上获得 `certs/fullchain.pem` 和 `certs/privkey.pem` 有两种常见方式。

### 方法 1：从 Linux 服务器复制

如果证书是在云服务器上用 Certbot 申请的，可以把下面两个文件复制到 Windows 项目的 `certs/`：

```text
/root/SecureChat/certs/fullchain.pem
/root/SecureChat/certs/privkey.pem
```

复制后放到：

```text
D:\Programming\CyberSecurity\Lessons\Experiment\SecureChat\certs\fullchain.pem
D:\Programming\CyberSecurity\Lessons\Experiment\SecureChat\certs\privkey.pem
```

不要把 `privkey.pem` 发给无关人员，不要提交到 Git。

### 方法 2：win-acme 输出 PEM

win-acme 是 Windows 上常用的 ACME 客户端：

```text
https://www.win-acme.com/
```

交互模式：

```bat
wacs.exe
```

大致选择：

```text
Create certificate with full options
Manually input host names
输入域名，例如 chat.la5te2.online
选择验证方式
选择 store: pemfiles
设置 PEM 输出目录为项目 certs 目录
```

输出目录示例：

```text
D:\Programming\CyberSecurity\Lessons\Experiment\SecureChat\certs
```

如果 win-acme 输出文件名不是 `fullchain.pem` 和 `privkey.pem`，可以重命名或在 UI 中填写实际文件路径。

## DNS-01 方式

如果 TCP 80 不能开放，可以用 DNS-01 验证：

```bash
sudo certbot certonly --manual --preferred-challenges dns -d chat.la5te2.online
```

Certbot 会要求你在 DNS 中添加 TXT 记录，形如：

```text
_acme-challenge.chat.la5te2.online TXT <certbot-given-token>
```

DNS 生效后继续 Certbot 流程即可。

长期部署不建议一直手动 DNS 验证。更好的方式是使用 DNS 服务商插件或支持 DNS API 的 ACME 客户端，让续期自动化。

## 自签名证书

自签名证书只适合本地测试，不适合公网安全部署。默认客户端通常不会信任自签名证书，因此 WSS 连接可能失败，除非客户端系统显式信任该证书。

在项目 `certs/` 下生成自签名证书：

```bash
cd ~/SecureChat
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/privkey.pem \
  -out certs/fullchain.pem \
  -days 365 \
  -subj "/CN=localhost"
```

Windows PowerShell 如果有 OpenSSL，也可以：

```bat
cd /d D:\Programming\CyberSecurity\Lessons\Experiment\SecureChat
mkdir certs
openssl req -x509 -newkey rsa:2048 -nodes -keyout certs\privkey.pem -out certs\fullchain.pem -days 365 -subj "/CN=localhost"
```

自签名证书的问题：

- 只能证明流量经过 TLS 加密；
- 不能提供正常公网身份校验；
- 证书名称必须和连接 URL 匹配，否则仍会失败；
- 默认客户端不信任，需要手动导入信任库。

## 让客户端信任自签名证书

### Windows 客户端

图形界面：

1. 双击 `certs/fullchain.pem` 或转换后的 `.crt` 文件；
2. 选择 `安装证书`；
3. 选择 `当前用户` 或 `本地计算机`；
4. 选择 `将所有的证书都放入下列存储`；
5. 选择 `受信任的根证书颁发机构`；
6. 完成导入。

PowerShell：

```powershell
Import-Certificate `
  -FilePath D:\Programming\CyberSecurity\Lessons\Experiment\SecureChat\certs\fullchain.pem `
  -CertStoreLocation Cert:\CurrentUser\Root
```

所有用户信任需要管理员权限：

```powershell
Import-Certificate `
  -FilePath D:\Programming\CyberSecurity\Lessons\Experiment\SecureChat\certs\fullchain.pem `
  -CertStoreLocation Cert:\LocalMachine\Root
```

### Linux 客户端

Debian/Ubuntu：

```bash
sudo cp certs/fullchain.pem /usr/local/share/ca-certificates/securechat-test.crt
sudo update-ca-certificates
```

删除测试证书：

```bash
sudo rm /usr/local/share/ca-certificates/securechat-test.crt
sudo update-ca-certificates --fresh
```

## 文件速查

项目内推荐路径：

```text
SECURECHAT_TLS_CERT_FILE=certs/fullchain.pem
SECURECHAT_TLS_KEY_FILE=certs/privkey.pem
```

Linux Certbot 原始路径：

```text
SECURECHAT_TLS_CERT_FILE=/etc/letsencrypt/live/chat.la5te2.online/fullchain.pem
SECURECHAT_TLS_KEY_FILE=/etc/letsencrypt/live/chat.la5te2.online/privkey.pem
```

Windows 项目路径：

```text
SECURECHAT_TLS_CERT_FILE=D:\Programming\CyberSecurity\Lessons\Experiment\SecureChat\certs\fullchain.pem
SECURECHAT_TLS_KEY_FILE=D:\Programming\CyberSecurity\Lessons\Experiment\SecureChat\certs\privkey.pem
```

官方参考：

- Certbot Linux 安装和使用：https://certbot.eff.org/instructions
- Let's Encrypt 验证方式：https://letsencrypt.org/zh-cn/docs/challenge-types/
- win-acme Windows ACME 客户端：https://www.win-acme.com/
- win-acme PEM 输出插件：https://www.win-acme.com/reference/plugins/store/pemfiles
