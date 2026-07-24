# HTTPS 客户端 Demo — OpenSSL s_server + TEE ENGINE 客户端

> **目标**：验证 tbox_keystore ENGINE 可以被标准 OpenSSL API 应用使用，完成端到端 HTTPS 双向认证通信。
>
> **服务端**：`openssl s_server` 命令行，纯软件密钥（不依赖 ENGINE）
> **客户端**：独立 C 程序，使用 tbox_keystore ENGINE 加载 TA 中的密钥，走完整 HTTPS GET 请求
>
> **与现有测试的区别**：
> | 测试 | 服务端私钥 | 客户端私钥 | 通信层 | 验证目标 |
> |------|:---:|:---:|------|------|
> | `engine_test` | — | TA（签名+验签） | — | ENGINE 回调正确性 |
> | `run_test.sh` | TA（tls_mutual_auth） | TA（tls_mutual_auth） | TLS 握手 | 两个 ENGINE 实例互通 |
> | **https_test.sh** | **软件（openssl s_server）** | **TA（https_client + ENGINE）** | **HTTPS GET** | **ENGINE 对标准 TLS 工具的兼容性** |

---

## 一、整体架构

```
┌───────────────────────────────────────┐   ┌─────────────────────────────────┐
│ openssl s_server（软件密钥）            │   │ https_client（C 程序, TEE ENGINE）│
│ :9443                                 │   │                                 │
│                                       │   │ SSL_CTX_new(TLS_client_method)   │
│ 证书: /tmp/server-sw.crt               │   │ ENGINE_load_tbox_keystore()      │
│ 私钥: /tmp/server-sw.key（PEM 文件）    │   │ ENGINE_load_private_key(         │
│ CA:   /tmp/tbox-client.crt             │   │   e, "client-key", NULL, NULL)   │
│                                       │   │                                  │
│ -verify 1 -Verify 1                   │   │ 证书: /tmp/tbox-client.crt        │
│ 双向认证，验证客户端证书                │   │ CA:   /tmp/server-sw.crt          │
│                                       │   │ SSL_CTX_set_verify(PEER)         │
│                                       │   │                                  │
│                   TLS 握手              │   │                                  │
│  ◄─────────── ClientHello ──────────────│─── 发起连接                        │
│  ── ServerHello, Certificate, ────────►│                                   │
│     CertificateRequest, ServerHelloDone│                                   │
│  ◄── Certificate, ClientKeyExchange,   │─── CertificateVerify              │
│      CertificateVerify ────────────────│    ↑ ENGINE → TA → rsa_priv_enc   │
│                                        │    ↑ 私钥在 TEE 内签名              │
│  ── ChangeCipherSpec, Finished ───────►│                                   │
│                                        │                                   │
│                   HTTPS                │                                   │
│  ◄────────── GET / HTTP/1.1 ──────────│─── SSL_write                     │
│  ── 200 OK + body ────────────────────►│─── SSL_read → stdout             │
└───────────────────────────────────────┘   └─────────────────────────────────┘
```

---

## 二、文件清单

```
optee_examples_AG519M/tbox_keystore/engine/
├── e_tbox_keystore.c            ← 已有（ENGINE 实现）
├── tls_mutual_auth.c            ← 已有（TLS 双向认证，双方 TA key）
├── CMakeLists.txt               ← 修改（新增 https_client target）
├── test/
│   ├── engine_test.c            ← 已有（ENGINE 冒烟测试）
│   ├── https_client.c           ← 新增（HTTPS 客户端 demo）
│   ├── setup_keys.sh            ← 已有（TA 灌装）
│   ├── run_test.sh              ← 已有（TLS 双向认证测试）
│   ├── gen_sw_cert.sh           ← 新增（生成服务端软件密钥+证书）
│   └── https_test.sh            ← 新增（HTTPS 双向认证端到端测试）
```

---

## 三、https_client.c 设计

### 3.1 程序流程

```
main()
  │
  ├─ 1. SSL_library_init / SSL_load_error_strings
  │
  ├─ 2. ENGINE_load_tbox_keystore()          ← 注册 ENGINE
  │
  ├─ 3. 创建 SSL_CTX
  │    ├─ TLS_client_method()
  │    ├─ ENGINE_load_private_key("client-key")     ← 从 TA 加载私钥
  │    ├─ SSL_CTX_use_certificate_file("client.crt")
  │    ├─ SSL_CTX_load_verify_locations("server-sw.crt")
  │    ├─ SSL_CTX_set_verify(PEER | FAIL_IF_NO_PEER_CERT)
  │    └─ TLS 1.2 only
  │
  ├─ 4. socket + connect("127.0.0.1", 9443)
  │
  ├─ 5. SSL_new + SSL_set_fd + SSL_connect
  │    │  ← TLS 握手：CertificateVerify 签名传入 ENGINE → TA
  │    │
  │    └─ 打印对端证书 Subject
  │
  ├─ 6. SSL_write("GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
  │
  ├─ 7. SSL_read 循环
  │    └─ 打印 HTTP 响应头 + body 到 stdout
  │
  └─ 8. SSL_shutdown + close + 清理
```

### 3.2 核心代码骨架

```c
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/err.h>

extern int ENGINE_load_tbox_keystore(void);

int main(void)
{
    SSL_CTX *ctx;
    SSL *ssl;
    int fd;

    SSL_library_init();
    SSL_load_error_strings();
    ENGINE_load_tbox_keystore();

    /* SSL_CTX — 双向认证 */
    ctx = SSL_CTX_new(TLS_client_method());

    {
        ENGINE *e = ENGINE_by_id("tbox_keystore");
        ENGINE_init(e);
        EVP_PKEY *pkey = ENGINE_load_private_key(e, "client-key", NULL, NULL);
        SSL_CTX_use_PrivateKey(ctx, pkey);
        EVP_PKEY_free(pkey);
    }

    SSL_CTX_use_certificate_file(ctx, CLIENT_CERT_FILE, SSL_FILETYPE_PEM);
    SSL_CTX_load_verify_locations(ctx, SERVER_CERT_FILE, NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

    /* Socket + connect */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    /* ... connect to 127.0.0.1:9443 ... */

    /* TLS */
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_connect(ssl);            /* ← CertificateVerify 签名走 TA */

    /* HTTPS */
    char *req = "GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n";
    SSL_write(ssl, req, strlen(req));

    char buf[4096];
    int n;
    while ((n = SSL_read(ssl, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        fputs(buf, stdout);
    }

    SSL_shutdown(ssl);
    close(fd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
```

### 3.3 输出预期

```
=== HTTPS Client (TEE-backed key: client-key) ===

[1] Loading TEE key 'client-key' via ENGINE ...  OK
[2] Connecting to 127.0.0.1:9443 ...             OK
[3] TLS handshake ...                             OK
    Cipher: ECDHE-RSA-AES256-GCM-SHA384
    Server cert: /CN=tbox-server-sw
[4] GET / HTTP/1.1 ...
HTTP/1.1 200 OK
Content-Type: text/html

<html><body>Hello from s_server</body></html>

=== DONE ===
```

---

## 四、测试脚本设计

### 4.1 gen_sw_cert.sh — 生成服务端软件密钥+证书

```bash
#!/bin/sh
# 生成服务端软件 RSA 密钥 + 自签名证书
openssl genrsa -out /tmp/server-sw.key 2048
openssl req -new -x509 -key /tmp/server-sw.key \
    -out /tmp/server-sw.crt -days 3650 \
    -subj "/CN=tbox-server-sw"
```

### 4.2 https_test.sh — 端到端 HTTPS 双向认证测试

```bash
#!/bin/sh
# 1. 确认 TA 密钥 + 客户端证书已就绪
# 2. 生成服务端软件证书
# 3. 启动 openssl s_server（后台，双向认证）
# 4. 运行 https_client
# 5. 检查输出中有 "HTTP/1.1 200 OK"
# 6. 关闭 s_server
```

---

## 五、CMakeLists.txt 新增

```cmake
add_executable(https_client test/https_client.c)
target_link_libraries(https_client
    ${OPENSSL_LIBRARIES}
    e_tbox_keystore
    ssl crypto
)
```

---

## 六、测试流程

```bash
# 1. 编译
cd engine/build && cmake .. && make -j

# 2. 部署到设备后，一次性准备
rm -rf /data/tee/*
./test/setup_keys.sh            # 灌装 TA key + 生成 tbox cert
./test/gen_sw_cert.sh           # 生成服务端软件 key+cert

# 3. 运行 HTTPS 测试
./test/https_test.sh
```

---

## 七、与已有测试的关系

```
测试金字塔:

              ┌──────────────┐
              │ https_test   │  ← HTTPS GET 端到端（新）
              │ s_server     │
              │ + https_client│
              ├──────────────┤
              │ run_test     │  ← TLS 握手 (双方 TA)
              │ tls_mutual   │
              │ _auth        │
              ├──────────────┤
              │ engine_test  │  ← ENGINE 回调冒烟
              └──────────────┘
```

`https_test.sh` 从底层 ENGINE 回调验证推进到 HTTPS 应用层通信——证明 tbox_keystore ENGINE 可以支撑真实的 HTTPS 客户端业务。
