# tbox_keystore TA → OpenSSL ENGINE 集成方案

> **版本**：OpenSSL 1.1.1w，ENGINE API
>
> **代码位置**：[optee_examples_AG519M/tbox_keystore/engine/](../engine/)
>
> **设计原则**：应用层零改动，`ENGINE_load_private_key(e, "label", ...)` 即可将 RSA 私钥操作路由到 OP-TEE TA。私钥全生命周期在 TEE 内，REE 仅持有公钥和 label 字符串。

---

## 一、代码文件清单

```
optee_examples_AG519M/tbox_keystore/
├── ta/
│   ├── keystore.c                  ← [已修改] CMD_KEY_EXPORT_PUB 增加 8 字节长度头
│   ├── entry.c                     ← 不变
│   ├── crypto_ops.c                ← 不变
│   ├── pin_mgr.c                   ← 不变
│   └── include/
│       └── tbox_keystore_ta.h      ← 不变 (UUID, CMD_* 枚举)
├── host/
│   └── keystore_client.c           ← 不变
└── engine/                         ← [新增目录]
    ├── CMakeLists.txt               ─ 构建 ENGINE so + TLS demo
    ├── e_tbox_keystore.c            ─ ENGINE 实现 (458 行)
    ├── tls_mutual_auth.c            ─ TLS 双向认证 demo (506 行)
    └── test/
        ├── setup_keys.sh            ─ 生成 TEE 测试密钥
        └── run_test.sh              ─ 自动化端到端测试
```

---

## 二、整体架构

```
┌──────────────────────────────────────────────────────────────────┐
│  TLS 应用 或 tls_mutual_auth demo                                  │
│                                                                    │
│  ENGINE_load_tbox_keystore();                                     │
│  ENGINE *e = ENGINE_by_id("tbox_keystore");                        │
│  ENGINE_init(e);                → TEEC 连接 TA                     │
│  EVP_PKEY *p = ENGINE_load_private_key(e, "client-key", ...);     │
│  SSL_CTX_use_PrivateKey(ctx, p);  ← 私钥在 TEE，永不出安全域        │
│  SSL_connect(ctx);               ← 签名操作自动路由到 TA            │
└──────────────────────────┬───────────────────────────────────────┘
                           │ OpenSSL EVP → RSA_METHOD
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│  e_tbox_keystore.so  (REE 侧，engine/e_tbox_keystore.c)            │
│                                                                    │
│  ┌─ ENGINE 生命周期 ────────────────────────────────────────────┐ │
│  │ ENGINE_init()    → TEEC_InitializeContext()                   │ │
│  │                    + TEEC_OpenSession(TA_TBOX_KEYSTORE_UUID)  │ │
│  │ ENGINE_finish()  → TEEC_CloseSession() + TEEC_FinalizeContext│ │
│  └──────────────────────────────────────────────────────────────┘ │
│  ┌─ RSA_METHOD 回调 ────────────────────────────────────────────┐ │
│  │ rsa_sign()       → TEEC_InvokeCommand(CMD_SIGN, label, digest)│ │
│  │ rsa_verify()     → TEEC_InvokeCommand(CMD_VERIFY, label, ...) │ │
│  │ rsa_priv_enc()   → (Phase 2 预留)                              │ │
│  │ rsa_keygen()     → 不支持（密钥在 TA 内预生成）                  │ │
│  └──────────────────────────────────────────────────────────────┘ │
│  ┌─ 密钥加载 ───────────────────────────────────────────────────┐ │
│  │ ENGINE_load_private_key(e, "client-key", ...)                 │ │
│  │   → CMD_KEY_EXPORT_PUB("client-key")                          │ │
│  │     ← [n_len:4][e_len:4][modulus][exponent]                   │ │
│  │   → RSA_new_method(e)       ← 绑定自定义 RSA_METHOD            │ │
│  │   → RSA_set0_key(rsa, n, e, NULL)   ← 只设公钥分量             │ │
│  │   → RSA_set_flags(rsa, RSA_FLAG_EXT_PKEY)                     │ │
│  │   → RSA_set_ex_data(rsa, idx, "client-key")                   │ │
│  │   → EVP_PKEY_assign_RSA(pkey, rsa)                            │ │
│  └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────┬───────────────────────────────────────┘
                           │ TEEC_InvokeCommand → SMC (#0)
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│  OP-TEE + tbox_keystore TA  (Secure World, ta/*.c)                │
│                                                                    │
│  TA_InvokeCommandEntryPoint:                                      │
│    CMD_SIGN   → keystore_load(label) → crypto_rsa_sign()         │
│                   → TEE_AsymmetricSignDigest(                     │
│                       TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,          │
│                       digest, 32, sig, &sig_len)                  │
│    CMD_VERIFY → keystore_load(label) → crypto_rsa_verify()       │
│    CMD_KEY_EXPORT_PUB → keystore_export_pub()                    │
│                           → 8 字节头 + n + e                      │
└──────────────────────────────────────────────────────────────────┘
```

---

## 三、TA 侧改动

Phase 1 只改了一处：[keystore.c:553-565](../ta/keystore.c) 中 `CMD_KEY_EXPORT_PUB` 的输出格式，从裸 `n||e` 拼接改为带长度头：

```c
/* 改前: [modulus][exponent] — 调用方无法确定分界点 */
total = n_len + e_len;
memcpy(out, n_data, n_len);
memcpy(out + n_len, e_data, e_len);

/* 改后: [n_len:4][e_len:4][modulus][exponent] — ENGINE 可直接解析 */
total = 8 + n_len + e_len;
uint32_t header[2];
header[0] = (uint32_t)n_len;
header[1] = (uint32_t)e_len;
memcpy(out, header, 8);
memcpy(out + 8, n_data, n_len);
memcpy(out + 8 + n_len, e_data, e_len);
```

其余 TA 代码（entry.c, crypto_ops.c, keystore.c 的序列化/加载逻辑）无需改动即满足 ENGINE 需求。

> **剪裁**：方案文档原计划增加 `CMD_KEY_EXPORT_DER` 和 `CMD_RSA_PRIVATE`，经评估 Phase 1 不需要——长度头方案已让 ENGINE 能正确分割 n/e，且 NID_sha256 覆盖了绝大多数 TLS 场景。

---

## 四、ENGINE 实现要点

源码：[engine/e_tbox_keystore.c](../engine/e_tbox_keystore.c) (458 行)

### 4.1 全局状态与 TEE 会话

```c
static TEEC_Context  g_ctx;
static TEEC_Session  g_sess;
static int           g_ready = 0;
static int           g_ex_idx = -1;   /* RSA ex_data 槽位，存 label 字符串 */
```

`ENGINE_init` 时建立 TEEC 会话，`ENGINE_finish` 时释放。Phase 1 为全局单会话（非线程安全）。

### 4.2 `rsa_sign` — 关键回调

```c
static int tbox_rsa_sign(int dtype, const unsigned char *m,
                          unsigned int m_len,
                          unsigned char *sigret, unsigned int *siglen,
                          const RSA *rsa)
{
    const char *label = RSA_get_ex_data(rsa, g_ex_idx);

    /* NID → TEE 算法映射 */
    switch (dtype) {
    case NID_sha256: tee_algo = TEE_ALG_RSASSA_PKCS1_V1_5_SHA256; break;
    case NID_sha384: tee_algo = TEE_ALG_RSASSA_PKCS1_V1_5_SHA384; break;
    case NID_sha512: tee_algo = TEE_ALG_RSASSA_PKCS1_V1_5_SHA512; break;
    default: return 0;
    }

    /* param[0]=label, param[1]=raw digest, param[2]=sig output */
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)label;
    op.params[0].tmpref.size   = strlen(label);
    op.params[1].tmpref.buffer = (void *)m;       /* ← OpenSSL 已计算好的摘要 */
    op.params[1].tmpref.size   = m_len;
    op.params[2].tmpref.buffer = sigret;
    op.params[2].tmpref.size   = *siglen;

    TEEC_InvokeCommand(&g_sess, CMD_SIGN, &op, NULL);
    *siglen = op.params[2].tmpref.size;
    return 1;
}
```

**关键设计点**：OpenSSL 的 TLS 栈在 `CertificateVerify` 阶段先计算握手摘要，再把**原始 SHA-256 摘要**（32 字节）传给 `rsa_sign`。TA 的 `crypto_rsa_sign` 内部调用 `TEE_AsymmetricSignDigest(TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, digest, ...)`——输入恰好也是原始摘要。两者天然对齐，无需在 ENGINE 或 TA 侧做额外加工。

### 4.3 `rsa_verify` — 验签回调

```c
static int tbox_rsa_verify(int dtype, const unsigned char *m, ...)
{
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,   /* label     */
        TEEC_MEMREF_TEMP_INPUT,   /* digest    */
        TEEC_MEMREF_TEMP_INPUT,   /* signature */
        TEEC_VALUE_OUTPUT);       /* result (0/1) */
    ...
    TEEC_InvokeCommand(&g_sess, CMD_VERIFY, &op, NULL);
    return (op.params[3].value.a == 1) ? 1 : 0;
}
```

`pub_dec` 未实现——对端证书的公钥验签走 OpenSSL 软件路径。

### 4.4 `ENGINE_load_private_key` — 标签→密钥

```c
static EVP_PKEY *tbox_load_privkey(ENGINE *e, const char *key_id, ...)
{
    /* 1. 从 TA 获取公钥数据: [n_len:4][e_len:4][modulus][exponent] */
    TEEC_InvokeCommand(&g_sess, CMD_KEY_EXPORT_PUB, ...);

    /* 2. 解析 8 字节头 → n_len, e_len */
    n_len = read32(pub_buf + 0);
    e_len = read32(pub_buf + 4);

    /* 3. 构造 RSA*，绑定自定义 RSA_METHOD */
    rsa = RSA_new_method(e);            /* ← 关键: 后续 sign/verify 走我们的回调 */
    BIGNUM *n = BN_bin2bn(pub_buf + 8, n_len, NULL);
    BIGNUM *bn_e = BN_bin2bn(pub_buf + 8 + n_len, e_len, NULL);
    RSA_set0_key(rsa, n, bn_e, NULL);   /* 只设 (n, e)，不设 d/p/q */

    /* 4. 标记外部密钥 + 存储 label */
    RSA_set_flags(rsa, RSA_FLAG_EXT_PKEY);
    RSA_set_ex_data(rsa, g_ex_idx, OPENSSL_strdup(key_id));

    /* 5. 封装为 EVP_PKEY */
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    return pkey;
}
```

### 4.5 ENGINE 注册

```c
int ENGINE_load_tbox_keystore(void)
{
    g_ex_idx = RSA_get_ex_new_index(0, "tbox_key_label", NULL, NULL, NULL);

    tbox_rsa_meth = RSA_meth_new("TBox Keystore RSA", 0);
    RSA_meth_set_sign(tbox_rsa_meth, tbox_rsa_sign);
    RSA_meth_set_verify(tbox_rsa_meth, tbox_rsa_verify);
    RSA_meth_set_priv_enc(tbox_rsa_meth, tbox_rsa_priv_enc);  /* Phase 2 stub */
    RSA_meth_set_keygen(tbox_rsa_meth, tbox_rsa_keygen);      /* 返回 0 */
    flags = RSA_meth_get_flags(tbox_rsa_meth) | RSA_FLAG_EXT_PKEY;
    RSA_meth_set_flags(tbox_rsa_meth, flags);

    ENGINE *e = ENGINE_new();
    ENGINE_set_id(e, "tbox_keystore");
    ENGINE_set_name(e, "TBox Keystore (OP-TEE backed)");
    ENGINE_set_RSA(e, tbox_rsa_meth);
    ENGINE_set_init_function(e, tbox_engine_init);
    ENGINE_set_finish_function(e, tbox_engine_finish);
    ENGINE_set_destroy_function(e, tbox_engine_destroy);
    ENGINE_set_load_privkey_function(e, tbox_load_privkey);
    ENGINE_set_load_pubkey_function(e, tbox_load_pubkey);
    ENGINE_add(e);
    ENGINE_free(e);
}

/* 支持 openssl.cnf dynamic_path 加载 */
IMPLEMENT_DYNAMIC_BIND_FN(bind_engine)
IMPLEMENT_DYNAMIC_CHECK_FN()
```

---

## 五、TLS 双向认证 Demo

源码：[engine/tls_mutual_auth.c](../engine/tls_mutual_auth.c) (506 行)

### 5.1 Demo 结构

单个二进制，`--server` / `--client` 两个模式。双方各自使用 TA 中的不同密钥：

```
--server: 加载 TA 中的 "server-key" → 创建自签名证书 → 监听 :9443
--client: 加载 TA 中的 "client-key" → 创建自签名证书 → 连接 127.0.0.1:9443

握手: Server CertificateVerify ← TA sign("server-key")
      Client CertificateVerify ← TA sign("client-key")
      ← 双方签名都在 TEE 内完成
```

### 5.2 自签名证书生成

Demo 在进程启动时调用 `make_self_signed_cert(pkey, cn)` 动态生成证书：

```c
static X509 *make_self_signed_cert(EVP_PKEY *pkey, const char *cn)
{
    x509 = X509_new();
    X509_set_version(x509, 2);
    X509_set_pubkey(x509, pkey);           /* 公钥来自 TA 导出 */

    /* Subject = Issuer (自签名) */
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, cn, ...);
    X509_set_subject_name(x509, name);
    X509_set_issuer_name(x509, name);

    /* 签名证书 → 经 ENGINE → TA → RSA_sign */
    X509_sign(x509, pkey, EVP_sha256());

    return x509;
}
```

`X509_sign` 内部会走 `EVP_DigestSign` → `RSA_sign` → `tbox_rsa_sign`（ENGINE 回调）→ TA。所以证书本身的签名也证明了 TEE 签名链路是通的。

### 5.3 对等认证信任

双方各自加载对端的公钥 → 生成对端证书 → 放入自己的 `X509_STORE` 作为信任锚：

```c
/* server 端: 信任 client 的自签名证书 */
EVP_PKEY *client_pkey = ENGINE_load_private_key(e, "client-key", ...);
X509 *client_cert = make_self_signed_cert(client_pkey, "tbox-client");
X509_STORE_add_cert(store, client_cert);

/* client 端: 信任 server 的自签名证书 */
EVP_PKEY *server_pkey = ENGINE_load_private_key(e, "server-key", ...);
X509 *server_cert = make_self_signed_cert(server_pkey, "tbox-server");
X509_STORE_add_cert(store, server_cert);
```

---

## 六、完整 TLS CertificateVerify 调用链

以 client 端签名 `CertificateVerify` 为例，从 OpenSSL 到 TA 硬件寄存器的全路径：

```
SSL_connect()
  ssl3_do_write()
    ssl3_send_certificate_verify()
      │
      ├─ ssl3_digest_cached_records()       // 计算所有握手消息的 SHA-256
      │
      └─ EVP_DigestSignFinal(&handshake_hash)
           │
           └─ RSA_sign(NID_sha256, sha256_digest, 32, sig, &siglen, rsa)
                │  rsa->meth = tbox_rsa_meth
                │
                └─ tbox_rsa_sign(dtype=NID_sha256, m=digest, m_len=32, ...)
                     │  engine/e_tbox_keystore.c:108
                     │
                     ├─ label = RSA_get_ex_data(rsa, g_ex_idx)  // "client-key"
                     │
                     └─ TEEC_InvokeCommand(&g_sess, CMD_SIGN, &op, NULL)
                          │  libteec.so → ioctl(TEE_IOC_INVOKE)
                          │
                          ├─ optee_do_call_with_arg()   // drivers/tee/optee/
                          │  SMC #0 → EL3 → OP-TEE Core
                          │
                          ├─ TA_InvokeCommandEntryPoint(sess, CMD_SIGN, ...)
                          │    │  ta/entry.c:441
                          │    │
                          │    ├─ pin_mgr_verify()              // PIN/Lock gate
                          │    │
                          │    ├─ keystore_load("client-key")    // label→TA key handle
                          │    │    │  ta/keystore.c:462
                          │    │    ├─ keystore_read() → TEE_OpenPersistentObject
                          │    │    └─ restore_rsa()   → TEE_PopulateTransientObject
                          │    │
                          │    └─ crypto_rsa_sign(key, 2048, digest, 32, sig, &siglen)
                          │         │  ta/crypto_ops.c:18
                          │         ├─ TEE_AllocateOperation(TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, SIGN, 2048)
                          │         ├─ TEE_SetOperationKey(op, key)
                          │         └─ TEE_AsymmetricSignDigest(op, NULL,0, digest,32, sig,&siglen)
                          │              │  OP-TEE Core: tee_svc_cryp.c
                          │              ├─ crypto_acipher_rsassa_sign()
                          │              └─ LibTomCrypt / mbedtls / HW Crypto Cell
                          │                   → m^d mod n  (私钥操作，硬件加速)
                          │
                          └─ 返回值传回 REE

    ← SSL_connect() 返回 1 (握手成功)
```

> 步骤 (1) `ssl3_digest_cached_records` 中 OpenSSL 计算 SHA-256 摘要。步骤 (10) `TEE_AsymmetricSignDigest` 接收原始摘要、内部添加 PKCS#1 v1.5 DigestInfo、调用 RSA 私钥操作。两者分工明确，输入/输出格式对齐。

---

## 七、构建与部署

### 7.1 构建

```bash
cd optee_examples_AG519M/tbox_keystore/engine
mkdir build && cd build

# 交叉编译（AG519M 平台）
cmake .. \
    -DCMAKE_C_COMPILER=aarch64-poky-linux-gcc \
    -DOPENSSL_ROOT_DIR=/path/to/openssl-1.1.1w \
    -DTEEC_INCLUDE_DIR=/opt/ql-ol-crosstool/sysroots/.../usr/include \
    -DTEEC_LIB_DIR=/opt/ql-ol-crosstool/sysroots/.../usr/lib
make

# 产物:
#   e_tbox_keystore.so  → 部署到 /usr/lib/engines-1.1/
#   tls_mutual_auth     → 部署到 /usr/bin/ 或测试目录
```

### 7.2 部署到开发板后运行测试

```bash
# 第一步：生成 TEE 测试密钥（运行一次）
./engine/test/setup_keys.sh
# 内部执行:
#   tbox_keystore --init-pin 31323334
#   tbox_keystore --gen-rsa server-key --size 2048 --sign --decrypt
#   tbox_keystore --gen-rsa client-key --size 2048 --sign --decrypt
#   tbox_keystore --lock

# 第二步：运行 TLS 双向认证测试
./engine/test/run_test.sh
# 内部执行:
#   ./tls_mutual_auth --server &        ← 后台启动 server
#   ./tls_mutual_auth --client           ← 客户端连接
```

### 7.3 预期输出

```
========================================
 TLS Mutual Auth Demo  (TEE-backed keys)
 Mode   : CLIENT
 Engine : tbox_keystore
========================================

[OK] Self-signed certificate created for 'tbox-client' (signed by TA)
[OK] Self-signed certificate created for 'tbox-server' (signed by TA)
[OK] Private key 'client-key' loaded from TA via ENGINE
[CLI] Received: hello from tbox server (TA-signed)
[CLI] TLS mutual-auth handshake SUCCESS.
[CLI] Peer certificate: /CN=tbox-server

========================================
 TEST PASSED
 Both sides' CertificateVerify were
 signed inside OP-TEE via ENGINE.
========================================
```

---

## 八、Phase 2 / Phase 3 路线图

### Phase 2：生产强化（预计 3 天）

| 项目 | 改动文件 | 说明 |
|------|----------|------|
| `rsa_priv_enc` 回调 | `e_tbox_keystore.c` | OpenSSL 加 DigestInfo + padding → TA 只做 `m^d mod n` → 支持所有 hash 算法 |
| `CMD_RSA_PRIVATE` | `ta/entry.c`, `ta/crypto_ops.c` | 使用 `TEE_ALG_RSA_NOPAD`，做原始 RSA 私钥操作 |
| TEEC session pool | `e_tbox_keystore.c` | 每线程一个 session，加 pthread mutex 保护 |
| TA 密钥缓存 | `ta/keystore.c` | session 内 LRU 缓存 `TEE_ObjectHandle`，避免每次签名都 `keystore_load/free` |

### Phase 3：OpenSSL 3.x Provider（未来）

| 项目 | 说明 |
|------|------|
| `tbox_keystore_provider.so` | 实现 `OSSL_PROVIDER_init` → 注册 keymgmt + signature |
| 与 ENGINE 共存 | 根据 OpenSSL 版本自动选择，`#if OPENSSL_VERSION_NUMBER >= 0x30000000L` |
| FIPS 兼容 | 可选 |

---

## 九、openssl.cnf 配置说明

当应用**不在代码中显式加载 ENGINE** 时（如 curl、nginx 等通用工具），可通过
`openssl.cnf` 让 OpenSSL 进程启动时自动注册 tbox_keystore ENGINE。

但需要注意：OpenSSL 1.1.1 的命令行工具对 ENGINE 私钥标识（`-key` 传 label 字符串）
支持不完善，**实际生产环境中 TLS 应用推荐走代码集成路径**（见 §八），
openssl.cnf 方式主要用于无需区分 key label 的算法加速场景。

```ini
# /etc/ssl/openssl.cnf
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
tbox_keystore = tbox_section

[tbox_section]
engine_id = tbox_keystore
dynamic_path = /usr/lib/engines-1.1/e_tbox_keystore.so
# 若设为 RSA 默认 engine，OpenSSL 的 RSA 操作会优先走 TA
# default_algorithms = RSA
```

> **tls_mutual_auth 不需要这个配置**——它在代码中直接调用
> `ENGINE_load_tbox_keystore()` 完成注册，完全不依赖 openssl.cnf。

---

## 十、安全分析

```
┌──────────────────────────────────────────────────────────────┐
│ REE 侧持有                                                    │
│   • 公钥 (n, e)             ← 可用于验签，无法伪造签名         │
│   • label 字符串             ← "server-key"                   │
│   • ENGINE so               ← 只含胶水代码，无密钥材料         │
│                                                              │
│ TEE 侧独占                                                    │
│   • 私钥 (d, p, q, dp, dq, qinv)  ← 永不出 TA 安全内存       │
│   • PIN hash                     ← 持久化在 TEE 安全存储      │
│   • Lock flag                    ← 持久化在 TEE 安全存储      │
│                                                              │
│ 威胁模型:                                                     │
│   攻击者 dump REE 内存     → 只能拿到 (n, e) + label           │
│   攻击者替换 ENGINE so     → Secure Boot 拒绝未签名 TA 加载    │
│   攻击者篡改 label 字符串  → 访问另一个密钥，但 TSK 隔离保护   │
│   攻击者重放 TEEC 命令     → 每次签名内容不同，重放无意义      │
└──────────────────────────────────────────────────────────────┘
```

---

## 十一、与 PKCS#11 路线对比

| 维度 | tbox_keystore ENGINE | OP-TEE PKCS#11 TA |
|------|---------------------|-------------------|
| 密钥标识 | 字符串 label（"ota-key"） | CKA_ID / CKA_LABEL |
| 接入代码 | `ENGINE_load_private_key(e, "ota-key", ...)` | `C_OpenSession` + `C_FindObjects` + `C_SignInit/C_Sign` |
| 新增代码量 | 458 行 ENGINE + 10 行 TA 改动 | 需 PKCS#11 module + libp11 全栈 |
| 调用层级 | EVP → RSA_METHOD → TEEC → TA (2 跳) | EVP → engine_pkcs11 → libp11 → PKCS#11 module → TEEC → TA (4 跳) |
| 非 OpenSSL 工具 | ❌ | ✅ (pkcs11-tool, p11tool, etc.) |
| 标准合规 | OpenSSL 特有 | PKCS#11 v2.40, GlobalPlatform |
| 本项目适用性 | ✅ 已有 TA 直接复用 | ⚠️ 需额外部署 PKCS#11 TA + module |

**结论**：当前阶段 ENGINE 方案是最短路径，最大化复用已有 tbox_keystore TA，无需引入 PKCS#11 运行时依赖。

---

## 十二、关键参考

| 参考 | 实际路径 | 关联点 |
|------|----------|--------|
| ENGINE 实现 | [engine/e_tbox_keystore.c](../engine/e_tbox_keystore.c) | 全局 TEEC 会话, rsa_sign, rsa_verify, ENGINE_load_private_key |
| TLS demo | [engine/tls_mutual_auth.c](../engine/tls_mutual_auth.c) | make_self_signed_cert, create_tls_ctx, run_server, run_client |
| CMake 构建 | [engine/CMakeLists.txt](../engine/CMakeLists.txt) | e_tbox_keystore.so + tls_mutual_auth 的构建配置 |
| 测试脚本 | [engine/test/setup_keys.sh](../engine/test/setup_keys.sh) | TA 密钥灌装 |
| 测试脚本 | [engine/test/run_test.sh](../engine/test/run_test.sh) | 端到端 TLS 测试 |
| TA 改动 | [ta/keystore.c](../ta/keystore.c) | CMD_KEY_EXPORT_PUB 8 字节长度头 |
| TA 头文件 | [ta/include/tbox_keystore_ta.h](../ta/include/tbox_keystore_ta.h) | UUID, CMD_* 枚举 |
| 密钥存储架构 | [05-key-storage.md](05-key-storage.md) | HUK→SSK→TSK→FEK 加密链 |
| 平台 API 替换 | [12-platform-api-replacement-analysis.md](12-platform-api-replacement-analysis.md) | BLOB 格式、接口映射 |
