# https_client — HTTPS 客户端 Demo

## 概述

验证 tbox_keystore ENGINE 对标准 OpenSSL 命令行工具的兼容性。客户端使用 ENGINE 加载 TA 密钥，通过 TLS 1.2 双向认证连接 `openssl s_server`（软件密钥），完成完整 HTTPS GET 请求。

```
openssl s_server                     https_client
(软件密钥, :9443)      TLS 1.2        (TA 密钥 via ENGINE)
       │                                  │
  cert: server-sw.crt              key:  client-key (TA)
  key:  server-sw.key              cert: client.crt (文件)
  CA:   client.crt                 CA:   server-sw.crt (文件)
       │                                  │
       └────────── GET / HTTP/1.1 ────────►
       ◄────────── 200 OK ────────────────┘
```

## 命令

```bash
https_client
# 无参数，固定连接 127.0.0.1:9443，使用 "client-key"
```

## 外部接口

```c
extern int ENGINE_load_tbox_keystore(void);
```

## 内部流程

```
[1] ENGINE_load_tbox_keystore       ← 注册 ENGINE
[2] SSL_CTX_new(TLS_client_method)
[3] ENGINE_load_private_key("client-key")    ← TA 密钥
[4] SSL_CTX_use_certificate_file(client.crt) ← 身份证书
[5] SSL_CTX_load_verify_locations(server-sw.crt) ← 信任锚
[6] socket + connect(127.0.0.1:9443)
[7] SSL_connect          ← TLS 握手：CertificateVerify 签名走 TA
[8] SSL_write(GET / HTTP/1.1)
[9] SSL_read 循环 → stdout
```

## 常量（硬编码）

| 常量 | 值 | 说明 |
|------|-----|------|
| `SERVER_HOST` | `127.0.0.1` | s_server 地址 |
| `SERVER_PORT` | `9443` | s_server 端口 |
| `CLIENT_CERT_FILE` | `/tmp/tbox-client.crt` | 客户端证书 |
| `SERVER_CERT_FILE` | `/tmp/server-sw.crt` | 服务端证书（信任锚） |

## 脚本

| 脚本 | 说明 |
|------|------|
| `test/https_test.sh` | 自动化：生成服务端证书 → 启动 s_server → 运行 https_client → 检查 HTTP 200 → 关闭 s_server |

测试脚本需要额外生成服务端软件密钥 + 自签名证书（`openssl genrsa` + `openssl req -x509`）。

## 前置依赖

| 依赖 | 来源 | 说明 |
|------|------|------|
| `libe_tbox_keystore.so` | `../../engine/build/` | ENGINE 库 |
| OpenSSL 1.1.x | `three_part/openssl/out/` | libssl + libcrypto |
| TA 密钥 (client-key) | TA 灌装 | 客户端私钥 |
| 客户端证书 | `tls_mutual_auth --gen-certs` | `/tmp/tbox-client.crt` |
| 服务端证书 | `openssl req -x509 -newkey rsa:2048` | `/tmp/server-sw.crt` + `/tmp/server-sw.key` |

## 构建

```bash
cd examples/https_client && mkdir -p build && cd build
cmake .. -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
    -DOPENSSL_ROOT_DIR=/home/test0923/workspace/OP-TEE/three_part/openssl/out \
    -DOPENSSL_INCLUDE_DIR=/home/test0923/workspace/OP-TEE/three_part/openssl/out/include \
    -DOPENSSL_SSL_LIBRARY=/home/test0923/workspace/OP-TEE/three_part/openssl/out/lib/libssl.so \
    -DOPENSSL_CRYPTO_LIBRARY=/home/test0923/workspace/OP-TEE/three_part/openssl/out/lib/libcrypto.so
make -j
```

产物：`https_client`。

## 设备端测试

```bash
# 1. 灌装 TA 密钥 + 生成客户端证书
./scrypt/setup_keys.sh

# 2. 生成服务端软件证书
cd ../https_client
openssl genrsa -out /tmp/server-sw.key 2048
openssl req -new -x509 -key /tmp/server-sw.key -out /tmp/server-sw.crt -days 3650 -subj "/CN=test-server"

# 3. 启动 s_server（软件密钥）
openssl s_server -cert /tmp/server-sw.crt -key /tmp/server-sw.key \
    -CAfile /tmp/tbox-client.crt -verify 1 -www -port 9443 &

# 4. 运行客户端
./https_client
```

## 设备端测试(简化)

```bash
# 1. 灌装 TA 密钥 + 生成客户端证书
./scrypt/setup_keys.sh

# 2. 生成服务端软件证书
./gen_sw_cert.sh

# 3. 启动 s_server（软件密钥）,运行客户端
./https_test.sh
```

## 预期输出

```
=== HTTPS Client (TEE-backed key: client-key) ===

[1] Loading TEE key 'client-key' via ENGINE ...  OK
[2] Connecting to 127.0.0.1:9443 ...             OK
[3] TLS handshake ...                             OK
    Cipher: ECDHE-RSA-AES256-GCM-SHA384
    Server cert: /CN=test-server
[4] GET / HTTP/1.1 ...
HTTP/1.1 200 OK
...
=== DONE ===
```

## 相关文档

- [engine/README.md](../../engine/README.md) — ENGINE 实现
- [17-https-client-demo.md](../../docs/17-https-client-demo.md) — HTTPS 客户端方案
