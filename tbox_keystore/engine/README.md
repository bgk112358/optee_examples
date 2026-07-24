# TBox Keystore OpenSSL ENGINE

## 概述

`e_tbox_keystore.c` 实现了一个 OpenSSL 1.1.x ENGINE，将 RSA 密码学操作（签名/验签/解密）路由到 OP-TEE 中的 `tbox_keystore` TA。私钥全生命周期在 TEE 内，ENGINE 仅持有公钥和 label 字符串引用。

**单一源文件，约 330 行 C，零外部依赖（除 OpenSSL + libteec）。**

## 编译产物

| 产物 | 说明 |
|------|------|
| `libe_tbox_keystore.so` | ENGINE 共享库，部署到 `/usr/lib/` |

## 架构

```
TLS Application
      │ SSL_CTX_use_PrivateKey(ctx, pkey)
      ▼
OpenSSL EVP / RSA_METHOD
      │ rsa_sign / rsa_verify / rsa_priv_dec / rsa_priv_enc
      ▼
┌──────────────────────────────────────────────┐
│ e_tbox_keystore.c (this file)                │
│                                              │
│ 全局状态: g_ctx, g_sess (TEEC 会话)           │
│ 密钥引用: g_ex_idx  (RSA ex_data → label)    │
│                                              │
│ TEEC_InvokeCommand(CMD_*, label, data, ...)  │
└──────────────┬───────────────────────────────┘
               │ SMC (#0) → OP-TEE Core
               ▼
┌──────────────────────────────────────────────┐
│ tbox_keystore TA (Secure World)              │
│   CMD_SIGN / CMD_VERIFY / CMD_RSA_DECRYPT    │
│   CMD_KEY_EXPORT_PUB / CMD_GET_INFO          │
└──────────────────────────────────────────────┘
```

## 源码结构

```
e_tbox_keystore.c
│
├── [全局状态]  g_ctx, g_sess, g_ready, g_ex_idx, g_call_nr
│
├── [TEE 会话]  tee_start() / tee_stop() / tee_cmd()
│
├── [RSA_METHOD 回调]                      ← 被 OpenSSL RSA 层调用
│   ├── tbox_rsa_sign()        CMD_SIGN
│   ├── tbox_rsa_verify()      CMD_VERIFY
│   ├── tbox_rsa_priv_dec()    CMD_RSA_DECRYPT
│   ├── tbox_rsa_priv_enc()    → rsa_priv_dec
│   └── tbox_rsa_keygen()      不支持（返回 0）
│
├── [密钥加载]                              ← 被 OpenSSL ENGINE 框架调用
│   ├── load_rsa_pubkey()      CMD_KEY_EXPORT_PUB → 构造 RSA*
│   ├── tbox_load_privkey()    ENGINE_load_private_key 回调
│   └── tbox_load_pubkey()     ENGINE_load_pubkey 回调
│
├── [ENGINE 生命周期]                       ← 被 OpenSSL ENGINE 框架调用
│   ├── tbox_engine_init()     → tee_start()
│   ├── tbox_engine_finish()   → tee_stop()
│   └── tbox_engine_destroy()
│
└── [ENGINE 注册]                           ← 被应用代码调用
    ├── create_rsa_method()    RSA_meth_new + 回调绑定
    ├── ENGINE_load_tbox_keystore()  注册到 OpenSSL 全局 ENGINE 表
    └── bind_fn()              动态加载入口（openssl.cnf dynamic_path）
```

## 外部接口（公开 API）

### 注册函数

```c
int ENGINE_load_tbox_keystore(void);
```

向 OpenSSL 全局 ENGINE 表注册 `"tbox_keystore"` ENGINE。在进程启动时调用一次。

**返回**：1 成功，0 失败。

**使用示例**：
```c
ENGINE_load_tbox_keystore();
ENGINE *e = ENGINE_by_id("tbox_keystore");
```

### 动态加载入口

```c
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
IMPLEMENT_DYNAMIC_CHECK_FN()
```

`bind_fn` 被 `openssl.cnf` 中 `dynamic_path` 加载时调用。应用代码不需要直接使用。

## 内部接口（被 OpenSSL 回调）

### RSA_METHOD 回调表

| 回调 | OpenSSL 调用时机 | TA 命令 | 功能 |
|------|-----------------|---------|------|
| `rsa_sign` | TLS CertificateVerify 签名 | `CMD_SIGN` (5) | SHA-256 摘要 → RSA PKCS#1 v1.5 签名 |
| `rsa_verify` | 对端证书验签 | `CMD_VERIFY` (6) | SHA-256 摘要 + 签名 → 验签结果 |
| `rsa_priv_dec` | TLS ClientKeyExchange 解密 | `CMD_RSA_DECRYPT` (11) | RSA NOPAD `m^d mod n` |
| `rsa_priv_enc` | OpenSSL 某些代码路径签名 | → `rsa_priv_dec` | 转发到 rsa_priv_dec |
| `rsa_keygen` | 密钥生成请求 | — | 不支持（密钥在 TA 内预生成） |

### 签名回调详细流程

```
tbox_rsa_sign(dtype, m, m_len, sigret, siglen, rsa)
  │
  ├─ 1. label = RSA_get_ex_data(rsa, g_ex_idx)    ← 从 RSA 对象取出 key label
  ├─ 2. 校验 g_ready + dtype == NID_sha256
  ├─ 3. 如果 *siglen < RSA_size(rsa):
  │       使用本地 local_sig[512] 接收 TA 输出
  │       TA 写完后 memcpy 回 sigret            ← 尺寸探测兼容
  ├─ 4. TEEC_InvokeCommand(CMD_SIGN, label, digest, sigret)
  │      → TA: keystore_load(label) → TEE_AsymmetricSignDigest
  └─ 5. 设置 *siglen = 实际签名长度, return 1
```

### 密钥加载回调详细流程

```
tbox_load_privkey(e, key_id, ui, cb_data)
  │
  ├─ 1. load_rsa_pubkey(key_id, e)
  │      ├─ TEEC_InvokeCommand(CMD_KEY_EXPORT_PUB, label, buf)
  │      │     ← TA 返回 [n_len:4][e_len:4][modulus][exponent]
  │      ├─ memcpy(hdr, buf, 8) → n_len, e_len   ← ARM 小端序
  │      ├─ BN_bin2bn → n, e
  │      ├─ RSA_new_method(e)                      ← 绑定 RSA_METHOD
  │      ├─ RSA_set0_key(rsa, n, e, NULL)          ← 只设公钥分量
  │      └─ RSA_set_flags(rsa, RSA_FLAG_EXT_PKEY) ← 标记外部私钥
  │
  ├─ 2. RSA_set_ex_data(rsa, g_ex_idx, key_id)    ← 存 label 供回调查找
  └─ 3. EVP_PKEY_assign_RSA(pkey, rsa)             ← 封装为 EVP_PKEY
```

## 全局状态

| 变量 | 类型 | 说明 |
|------|------|------|
| `g_ctx` | `TEEC_Context` | TEE Client API 上下文 |
| `g_sess` | `TEEC_Session` | 与 TA 的会话（单一，非线程安全） |
| `g_ready` | `int` | 会话是否已建立 |
| `g_ex_idx` | `int` | RSA ex_data 索引（存取 key label） |
| `g_call_nr` | `int` | 调用计数器（LOG 宏使用） |

**注意**：当前为全局单会话模式。多线程场景需扩展为 session pool（Phase 2）。

## TA 命令映射

| 命令 ID | 宏 | 功能 | 参数 |
|:---:|------|------|------|
| 3 | `CMD_KEY_EXPORT_PUB` | 导出 RSA 公钥 | label → `[n_len:4][e_len:4][n][e]` |
| 5 | `CMD_SIGN` | RSA SHA-256 签名 | label + raw digest → signature |
| 6 | `CMD_VERIFY` | RSA SHA-256 验签 | label + digest + sig → result(0/1) |
| 11 | `CMD_RSA_DECRYPT` | RSA NOPAD 解密 | label + ciphertext → plaintext |

## 关键设计决策

### 尺寸探测兼容

OpenSSL 1.1.1w 某些代码路径会以 `*siglen=0` 调用 `rsa_sign` 做尺寸探测。ENGINE 使用本地 `local_sig[512]` 接收 TA 输出，再 `memcpy` 回调用者 buffer，兼容此行为。

### RSA_FLAG_EXT_PKEY

设置此标志告知 OpenSSL 私钥在外部硬件中，不应尝试访问 `rsa->d`、`rsa->p`、`rsa->q` 等字段。OpenSSL 会通过 RSA_METHOD 回调完成所有私钥操作。

### 小端序公钥解析

TA 和 ENGINE 均在 ARM (little-endian) 上运行。TA 通过 `memcpy(header, ...)` 写入 uint32 公钥头，ENGINE 同样用 `memcpy(hdr, buf, 8)` 解析，无需字节序转换。

### Label 引用

`ENGINE_load_private_key(e, "server-key", ...)` 中 key_id 通过 `OPENSSL_strdup` 拷贝后存入 `RSA_set_ex_data`。后续回调通过 `RSA_get_ex_data` 取出。label 是 TA 中密钥的唯一标识，通过 SHA-256(label) → UUID 确定性映射到持久化对象。

## 构建

```bash
cd engine && mkdir -p build && cd build
export PATH="/home/test0923/workspace/optee400/toolchains/aarch64/bin:$PATH"
cmake .. -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc
make -j
# 产物: libe_tbox_keystore.so
```

## 部署

```bash
cp libe_tbox_keystore.so /usr/lib/
# 或: cp libe_tbox_keystore.so /usr/lib/engines-1.1/（openssl.cnf dynamic_path 需要）
```

## 测试

```bash
# ENGINE 冒烟测试（6 步骤签名+验签）
cd ../examples/engine_test/build && ./engine_test server-key

# 预期输出: ALL TESTS PASSED
```

## 相关文档

| 文档 | 内容 |
|------|------|
| [13-openssl-engine-integration.md](../docs/13-openssl-engine-integration.md) | ENGINE 集成完整方案 |
| [15-engine-debug-issues.md](../docs/15-engine-debug-issues.md) | ENGINE 调试 15 个问题全记录 |
| [tbox_keystore_ta.h](../ta/include/tbox_keystore_ta.h) | TA UUID + 命令 ID 定义 |
| [e_tbox_keystore.c](e_tbox_keystore.c) | ENGINE 实现源码 |
