# tls_mutual_auth — TLS 双向认证 Demo

## 概述

TLS 1.2 双向认证演示，服务端和客户端均使用 TA 内密钥。双方 CertificateVerify 签名操作通过 ENGINE → TA 在 TEE 内完成。

支持三个模式：
- `--gen-certs` — 生成自签名证书（一次性）
- `--server` — 启动 TLS 服务端，监听 :9443
- `--client` — 连接 TLS 服务端

## 命令

```bash
tls_mutual_auth --gen-certs      # 一次运行：生成 /tmp/tbox-server.crt + /tmp/tbox-client.crt
tls_mutual_auth --server          # 后台运行：TLS server
tls_mutual_auth --client          # 前台运行：TLS client
```

## 外部接口

```c
extern int ENGINE_load_tbox_keystore(void);
```

与 engine_test 相同，仅依赖 ENGINE 的公开符号。

## 内部函数

| 函数 | 可见性 | 说明 |
|------|:---:|------|
| `make_self_signed_cert(pkey, cn)` | static | 用 EVP_PKEY 创建自签名 X.509 证书，`X509_sign` 走 ENGINE → TA |
| `save_cert(path, cert)` | static | PEM 格式写证书到文件 |
| `load_cert(path)` | static | 从文件读 PEM 证书 |
| `create_tls_ctx(mode, my_label, my_cert, peer_cert)` | static | 创建 SSL_CTX：ENGINE 加载私钥 + 绑定证书 + 信任对端 |
| `run_server(port)` | static | 完整 TLS server 流程 |
| `run_client(host, port)` | static | 完整 TLS client 流程 |
| `gen_certs()` | static | 加载双 key，生成双方证书，写入文件 |

## 证书流程

```
--gen-certs（单进程，同一 TEEC 会话）：
  ENGINE_load_private_key("server-key") → X509_sign → /tmp/tbox-server.crt
  ENGINE_load_private_key("client-key") → X509_sign → /tmp/tbox-client.crt

--server（只加载 server-key）：
  load_cert(SERVER_CERT_FILE)               ← 自身证书（文件读）
  load_cert(CLIENT_CERT_FILE)               ← 信任锚（文件读）
  ENGINE_load_private_key("server-key")     ← TA 密钥

--client（只加载 client-key）：
  load_cert(CLIENT_CERT_FILE)
  load_cert(SERVER_CERT_FILE)
  ENGINE_load_private_key("client-key")
```

**设计要点**：server 和 client 各自只访问自己的 TA 密钥，对端证书从文件读取。避开 OP-TEE 3.2 跨进程并发访问持久化对象的限制。

## 脚本

| 脚本 | 说明 |
|------|------|
| `test/setup_keys.sh` | 灌装 TA 密钥（server-key + client-key）+ Lock |
| `test/gen_sw_cert.sh` | 生成软件密钥 + 自签名证书（本地测试用） |
| `test/run_test.sh` | 自动化：启动 server → 客户端连接 → 检查握手成功 |

## 前置依赖

| 依赖 | 路径 | 说明 |
|------|------|------|
| `libe_tbox_keystore.so` | `../../engine/build/` | ENGINE 库 |
| `libteec.a` | `optee400/optee_client/` | 静态链接到 .so |
| OpenSSL 1.1.x | `three_part/openssl/out/` | libssl + libcrypto |
| TA 密钥 | `tbox_keystore` CLI 灌装 | server-key, client-key |

## 构建

```bash
cd examples/tls_mutual_auth && mkdir -p build && cd build
cmake .. -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
    -DOPENSSL_ROOT_DIR=/home/test0923/workspace/OP-TEE/three_part/openssl/out \
    -DOPENSSL_INCLUDE_DIR=/home/test0923/workspace/OP-TEE/three_part/openssl/out/include \
    -DOPENSSL_SSL_LIBRARY=/home/test0923/workspace/OP-TEE/three_part/openssl/out/lib/libssl.so \
    -DOPENSSL_CRYPTO_LIBRARY=/home/test0923/workspace/OP-TEE/three_part/openssl/out/lib/libcrypto.so
make -j
```

产物：`tls_mutual_auth`。

## 设备端测试

```bash
# 1. 灌装密钥
rm -rf /data/tee/*
./scrypt/setup_keys.sh

# 2. 生成证书
./tls_mutual_auth --gen-certs

# 3. 运行双向认证测试
./test/run_test.sh
```

## 预期输出

```
[OK] Self-signed certificate created for 'tbox-server' (signed by TA)
[OK] Self-signed certificate created for 'tbox-client' (signed by TA)
[OK] Private key 'server-key' loaded from TA via ENGINE
[SRV] Listening on :9443 ...
[OK] Private key 'client-key' loaded from TA via ENGINE
[SRV] Received: hello from tbox client (TA-signed)
[SRV] TLS mutual-auth handshake SUCCESS.
[CLI] Received: hello from tbox server (TA-signed)
[CLI] TLS mutual-auth handshake SUCCESS.
TEST PASSED
```

## 相关文档

- [engine/README.md](../../engine/README.md) — ENGINE 实现
- [13-openssl-engine-integration.md](../../docs/13-openssl-engine-integration.md) — ENGINE 集成方案
- [16-multi-process-concurrency-analysis.md](../../docs/16-multi-process-concurrency-analysis.md) — 多进程并发方案
