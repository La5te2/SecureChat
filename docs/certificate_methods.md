# SecureChat WSS 证书获取方法

SecureChat 的 WSS 需要两个 PEM 文件：

```text
fullchain.pem  证书链，给 SECURECHAT_TLS_CERT_FILE 使用
privkey.pem    私钥，给 SECURECHAT_TLS_KEY_FILE 使用
```

推荐使用域名申请证书，例如：

```text
chat.example.com -> 124.70.71.65
```

不推荐直接用公网 IP 做 WSS 地址。正常公网证书通常签给域名，`wss://124.70.71.65:25566` 大概率无法通过证书校验，除非证书明确包含该 IP。

官方参考：

- Certbot Linux 安装和使用：https://certbot.eff.org/instructions
- Let's Encrypt 验证方式：https://letsencrypt.org/zh-cn/docs/challenge-types/
- win-acme Windows ACME 客户端：https://www.win-acme.com/
- win-acme PEM 输出插件：https://www.win-acme.com/reference/plugins/store/pemfiles

## Linux：Certbot standalone

适用场景：

- 有域名；
- 域名 A 记录指向服务器公网 IP；
- 可以临时开放 TCP 80 端口给 Let's Encrypt 验证。

安装 Certbot：

```bash
sudo snap install core
sudo snap refresh core
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
```

![image-20260608152311716](C:\Users\theri\AppData\Roaming\Typora\typora-user-images\image-20260608152311716.png)

申请证书：

```bash
sudo certbot certonly --standalone -d chat.example.com
```

成功后文件通常在：

```text
/etc/letsencrypt/live/chat.example.com/fullchain.pem
/etc/letsencrypt/live/chat.example.com/privkey.pem
```

启动 SecureChat WSS：

```bash
export SECURECHAT_SIGNALING_TLS=1
export SECURECHAT_TLS_CERT_FILE=/etc/letsencrypt/live/chat.example.com/fullchain.pem
export SECURECHAT_TLS_KEY_FILE=/etc/letsencrypt/live/chat.example.com/privkey.pem
./start.sh
```

如果 SecureChat 不用 root 运行，注意私钥权限。不要把 `privkey.pem` 设成全局可读。更稳妥的做法是复制到专用目录并限制权限：

```bash
sudo mkdir -p /etc/securechat/certs
sudo cp /etc/letsencrypt/live/chat.example.com/fullchain.pem /etc/securechat/certs/fullchain.pem
sudo cp /etc/letsencrypt/live/chat.example.com/privkey.pem /etc/securechat/certs/privkey.pem
sudo chmod 640 /etc/securechat/certs/fullchain.pem /etc/securechat/certs/privkey.pem
```

然后：

```bash
export SECURECHAT_TLS_CERT_FILE=/etc/securechat/certs/fullchain.pem
export SECURECHAT_TLS_KEY_FILE=/etc/securechat/certs/privkey.pem
```

续期：

```bash
sudo certbot renew
```

证书续期后需要让 SecureChat 重新读取证书，最简单是停止并重启 Host：

```bash
./stop.sh
./start.sh
```

## Linux：Certbot DNS-01

适用场景：

- 80 端口不能开放；
- 服务器不方便暴露 HTTP；
- 需要通配符证书，例如 `*.example.com`。

手动 DNS 验证：

```bash
sudo certbot certonly --manual --preferred-challenges dns -d chat.example.com
```

Certbot 会要求在 DNS 中添加 TXT 记录，形如：

```text
_acme-challenge.chat.example.com TXT <certbot-given-token>
```

DNS 生效后继续 Certbot 流程即可。

长期部署不建议一直手动 DNS 验证。更好的方式是使用 DNS 服务商插件或支持 DNS API 的 ACME 客户端，让续期自动化。

## Windows：win-acme 输出 PEM

适用场景：

- Windows 上运行 WinUI 或 Windows Web Host；
- 想直接得到 SecureChat 可用的 PEM 文件；
- 有域名，并能完成 HTTP-01 或 DNS-01 验证。

下载 win-acme：

```text
https://www.win-acme.com/
```

推荐用交互模式：

```bat
wacs.exe
```

大致选择：

```text
Create certificate with full options
Manually input host names
输入域名，例如 chat.example.com
选择验证方式
选择 store: pemfiles
设置 PEM 输出目录，例如 C:\SecureChatCerts
```

win-acme 的 PEM 插件会输出类似文件：

```text
C:\SecureChatCerts\chat.example.com-chain.pem
C:\SecureChatCerts\chat.example.com-key.pem
```

SecureChat Windows WSS 可这样设置：

```bat
set SECURECHAT_SIGNALING_TLS=1
set SECURECHAT_TLS_CERT_FILE=C:\SecureChatCerts\chat.example.com-chain.pem
set SECURECHAT_TLS_KEY_FILE=C:\SecureChatCerts\chat.example.com-key.pem
```

然后启动：

```bat
out\build\x64-release\host.exe secure-room 25566 host
```

或启动 WinUI / Web 后，在界面里打开 `WSS` 开关，并填写：

```text
Certificate PEM: C:\SecureChatCerts\chat.example.com-chain.pem
Private key PEM: C:\SecureChatCerts\chat.example.com-key.pem
```

win-acme 的 unattended PEM 示例格式：

```bat
wacs.exe --target manual --host chat.example.com --store pemfiles --pemfilespath C:\SecureChatCerts --accepttos --emailaddress you@example.com
```

具体验证参数取决于你的环境，例如 IIS、filesystem、self-hosting 或 DNS 插件。参数以 win-acme 官方 CLI 文档为准。

## Windows：使用 WSL 或 Linux 服务器申请后复制

如果 Windows 上的 ACME 流程不方便，也可以：

1. 在 Linux/WSL 上用 Certbot 申请证书；
2. 把 `fullchain.pem` 和 `privkey.pem` 复制到 Windows；
3. 在 WinUI/Web 的 WSS 设置里填写复制后的路径。

示例路径：

```text
C:\SecureChatCerts\fullchain.pem
C:\SecureChatCerts\privkey.pem
```

WinUI/Web 设置：

```text
Certificate PEM: C:\SecureChatCerts\fullchain.pem
Private key PEM: C:\SecureChatCerts\privkey.pem
```

注意：复制私钥时不要放到公开目录，不要提交到 Git，不要发给无关人员。

## 自签名证书

自签名证书只适合本地测试，不适合公网安全部署。默认客户端通常不会信任自签名证书，因此 WSS 连接可能失败，除非客户端系统显式信任该证书。

Linux 生成自签名证书：

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout privkey.pem \
  -out fullchain.pem \
  -days 365 \
  -subj "/CN=localhost"
```

Windows PowerShell 如果有 OpenSSL，也可以：

```bat
openssl req -x509 -newkey rsa:2048 -nodes -keyout privkey.pem -out fullchain.pem -days 365 -subj "/CN=localhost"
```

SecureChat 使用：

```bash
export SECURECHAT_SIGNALING_TLS=1
export SECURECHAT_TLS_CERT_FILE=/path/fullchain.pem
export SECURECHAT_TLS_KEY_FILE=/path/privkey.pem
```

再次强调：自签名证书只能证明“流量经过 TLS 加密”，不能提供正常公网身份校验。

## 让客户端显式信任自签名证书

客户端要信任自签名证书，通常不是信任 `fullchain.pem` 这个服务端证书文件本身，而是把签发它的 CA 证书导入客户端系统信任库。简单自签名证书同时充当“根证书”和“服务端证书”，也可以直接导入该证书，但这只适合测试。

还需要注意：证书信任通过后，证书里的域名仍必须和连接 URL 匹配。例如客户端连接：

```text
wss://chat.example.com:25566
```

证书就应该包含 `chat.example.com`。现代 TLS 校验主要看 Subject Alternative Name，只有 `CN=localhost` 的证书通常不能用于 `chat.example.com`。

### Windows 客户端信任

如果是测试用自签名证书，可以把证书导入 Windows 的“受信任的根证书颁发机构”。

图形界面方式：

1. 准备证书文件，例如 `fullchain.pem` 或导出的 `.crt` 文件。
2. 双击证书文件。
3. 选择 `安装证书`。
4. 选择 `本地计算机` 或 `当前用户`。
5. 选择 `将所有的证书都放入下列存储`。
6. 选择 `受信任的根证书颁发机构`。
7. 完成导入。

PowerShell 方式：

```powershell
Import-Certificate `
  -FilePath C:\SecureChatCerts\fullchain.pem `
  -CertStoreLocation Cert:\CurrentUser\Root
```

如果要让本机所有用户信任，需要管理员权限：

```powershell
Import-Certificate `
  -FilePath C:\SecureChatCerts\fullchain.pem `
  -CertStoreLocation Cert:\LocalMachine\Root
```

导入后，WinUI 或 Windows Web Client 使用：

```text
wss://chat.example.com:25566
```

删除测试证书时，可以打开 `certmgr.msc`，在 `受信任的根证书颁发机构` 中找到并删除对应证书。

### Linux 客户端信任

Debian/Ubuntu 系发行版通常使用 `/usr/local/share/ca-certificates/` 和 `update-ca-certificates`。

先把证书转换或保存为 `.crt` 文件：

```bash
sudo cp fullchain.pem /usr/local/share/ca-certificates/securechat-test.crt
sudo update-ca-certificates
```

然后客户端使用：

```bash
./out/build/x64-linux-release/client wss://chat.example.com:25566 secure-room user1
```

删除测试证书：

```bash
sudo rm /usr/local/share/ca-certificates/securechat-test.crt
sudo update-ca-certificates --fresh
```

不同 Linux 发行版的系统信任库命令可能不同：

- Debian/Ubuntu：`update-ca-certificates`
- Fedora/RHEL/CentOS：`update-ca-trust`
- Arch：通常使用 `trust anchor` 或更新 p11-kit 信任库

### 更推荐的测试方式：自建本地 CA

比“每个服务端证书都直接导入信任库”更好的测试方式，是先生成一个本地测试 CA，再用它签发服务端证书：

1. 客户端只导入一次本地 CA 证书；
2. 服务端使用该 CA 签发的 `fullchain.pem` 和 `privkey.pem`；
3. 后续可以给不同测试域名签发不同服务端证书。

工具上可以使用 `mkcert` 这类本地开发证书工具，也可以用 OpenSSL 手动生成 CA 和服务端证书。无论哪种方式，都不要把测试 CA 私钥放进仓库或发给他人。

## 文件选择速查

Linux Certbot：

```text
SECURECHAT_TLS_CERT_FILE=/etc/letsencrypt/live/chat.example.com/fullchain.pem
SECURECHAT_TLS_KEY_FILE=/etc/letsencrypt/live/chat.example.com/privkey.pem
```

Windows win-acme PEM：

```text
SECURECHAT_TLS_CERT_FILE=C:\SecureChatCerts\chat.example.com-chain.pem
SECURECHAT_TLS_KEY_FILE=C:\SecureChatCerts\chat.example.com-key.pem
```

Windows 从 Linux 复制：

```text
SECURECHAT_TLS_CERT_FILE=C:\SecureChatCerts\fullchain.pem
SECURECHAT_TLS_KEY_FILE=C:\SecureChatCerts\privkey.pem
```
