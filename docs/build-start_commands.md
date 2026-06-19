# SecureChat 构建和启动命令

本文档只保留当前可用的构建入口和最小启动入口。完整 Windows、Linux、WinUI、局域网和 Nginx 流程见 `docs/startup-guide.md`。

## Windows 构建

在项目根目录执行：

```bat
set VCPKG_ROOT=C:\src\vcpkg
build_win.bat
```

输出位置：

```text
out\build\x64-release\server.exe
out\build\x64-release\host.exe
out\build\x64-release\client.exe
app\chat\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\SecureChat.exe
```

## Windows 本机启动

Server 手动启动且 TLS 路径环境变量为空时，会自动生成本地/局域网开发证书：

```powershell
Remove-Item Env:SECURECHAT_TLS_CERT_FILE -ErrorAction SilentlyContinue
Remove-Item Env:SECURECHAT_TLS_KEY_FILE -ErrorAction SilentlyContinue
.\out\build\x64-release\server.exe 25566
```

Host/Client CLI 连接该自动证书时设置：

```powershell
$env:SECURECHAT_LOCAL_TLS_CA="certs\local-root-ca.pem"
```

Host/Client 仍必须分别配置自己的成员 PKI：

```powershell
$env:SECURECHAT_PKI_TRUST_STORE="certs\pki\root-ca.pem"
$env:SECURECHAT_IDENTITY_CERT_FILE="certs\pki\alice-chain.pem"
$env:SECURECHAT_IDENTITY_KEY_FILE="certs\pki\alice-key.pem"
```

创建或加入房间：

```powershell
.\out\build\x64-release\host.exe --server wss://127.0.0.1:25566 secure-room alice
.\out\build\x64-release\client.exe wss://127.0.0.1:25566 secure-room bob
```

## Linux 构建

```bash
export VCPKG_ROOT="$HOME/vcpkg"
chmod +x build.sh
./build.sh
```

## Linux 本机启动

本机/局域网测试直接运行 Server 可执行文件，让 C++ 自动生成本地证书：

```bash
unset SECURECHAT_TLS_CERT_FILE SECURECHAT_TLS_KEY_FILE
./out/build/x64-linux-release/server 25566
```

Host/Client CLI 连接该自动证书时设置：

```bash
export SECURECHAT_LOCAL_TLS_CA=certs/local-root-ca.pem
```

## Linux 云端脚本启动

`start_server.sh` 用于云端或长期部署。它在 TLS 路径环境变量为空时直接使用：

```text
certs/fullchain.pem
certs/privkey.pem
```

这两个文件通常来自 Certbot 域名证书。启动：

```bash
chmod +x start_server.sh stop_server.sh
./start_server.sh
```

停止：

```bash
./stop_server.sh
```

## WinUI

WinUI 只作为 Host/Client 图形客户端，不启动 Server，也不配置 Server 私钥。双击运行：

```text
app\chat\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\SecureChat.exe
```

WinUI 设置面板中选择成员 PKI 文件；Server URL 必须填写 `wss://...`。如果 Server 使用自动生成的本地证书，在设置面板的 `Local Server TLS CA / 本地服务器 TLS 信任根` 中选择 `certs/local-root-ca.pem`。

