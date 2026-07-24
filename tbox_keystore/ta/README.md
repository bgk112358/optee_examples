# ta — TBox Keystore Trusted Application

## 概述

运行在 OP-TEE Secure World 中的密钥管理和密码学运算 TA。接收来自 REE 侧 CA（Client Application）的 TEEC 命令，使用 GP TEE Internal Core API 执行以下功能：

- **密钥生命周期**：生成 RSA/AES 密钥，序列化持久化到安全存储
- **密码学运算**：RSA 签名/验签/解密，AES 加解密
- **访问控制**：PIN 验证 + Lock 机制 + 密钥权限位
- **跨会话状态恢复**：PIN/Lock 状态从持久化存储恢复

**6 个源文件，约 1800 行 C。**

## 源文件清单

| 文件 | 行数 | 说明 |
|------|:---:|------|
| `entry.c` | ~500 | TA 入口点 + 12 条命令分发 + Gate 逻辑 |
| `keystore.c` | ~650 | 密钥生成/序列化/持久化/加载/删除/导出 |
| `pin_mgr.c` | ~230 | PIN 管理（init/verify/lock/restore） |
| `crypto_ops.c` | ~170 | 密码学封装（RSA sign/verify/decrypt, AES enc/dec） |
| `acl.c` | ~30 | 权限位校验 |
| `user_ta_header_defines.h` | — | TA 属性（UUID、stack size、flags） |
| `include/tbox_keystore_ta.h` | — | CA-TA 共享定义（UUID + 命令 ID + 结构体） |

## 编译产物

| 产物 | 部署路径 |
|------|----------|
| `f8e9209a-3c7d-4d6b-a15e-7f328b11c049.ta` | `/lib/optee_armtz/` |

## 共享头文件

`include/tbox_keystore_ta.h` 是 CA 和 TA 之间共享的唯一接口定义。

### TA UUID

```c
#define TA_TBOX_KEYSTORE_UUID \
    { 0xf8e9209a, 0x3c7d, 0x4d6b, \
        { 0xa1, 0x5e, 0x7f, 0x32, 0x8b, 0x11, 0xc0, 0x49 } }
```

### 命令 ID

| 宏 | 值 | 功能 |
|------|:---:|------|
| `CMD_PIN_INIT` | 0 | 写入灌装 PIN |
| `CMD_KEY_GEN_RSA` | 1 | 生成 RSA 密钥对 |
| `CMD_KEY_GEN_AES` | 2 | 生成 AES 密钥 |
| `CMD_KEY_EXPORT_PUB` | 3 | 导出 RSA 公钥 |
| `CMD_KEY_DELETE` | 4 | 删除密钥 |
| `CMD_SIGN` | 5 | RSA SHA-256 签名 |
| `CMD_VERIFY` | 6 | RSA SHA-256 验签 |
| `CMD_ENCRYPT_AES` | 7 | AES-CBC 加密 |
| `CMD_DECRYPT_AES` | 8 | AES-CBC 解密 |
| `CMD_GET_INFO` | 9 | 查询密钥信息 |
| `CMD_PROVISION_LOCK` | 10 | 锁定 TA |
| `CMD_RSA_DECRYPT` | 11 | RSA NOPAD `m^d mod n`（TLS 用） |

### 密钥类型与权限位

```c
#define KEY_TYPE_RSA_KEYPAIR  1
#define KEY_TYPE_AES          2

#define PERM_SIGN       0x01
#define PERM_VERIFY     0x02
#define PERM_ENCRYPT    0x04
#define PERM_DECRYPT    0x08
#define PERM_EXPORT_PUB 0x10

#define KEY_LABEL_MAX   64

struct key_info {
    uint32_t type;
    uint32_t size_bits;
    uint32_t permissions;
    uint8_t  label[KEY_LABEL_MAX];
};
```

## entry.c — TA 入口与命令分发

### TA 标准入口点

| 函数 | 说明 |
|------|------|
| `TA_CreateEntryPoint()` | TA 加载时调用 |
| `TA_DestroyEntryPoint()` | TA 卸载时调用 |
| `TA_OpenSessionEntryPoint()` | 新会话打开 → `pin_mgr_restore()` 恢复 PIN/Lock 状态 |
| `TA_CloseSessionEntryPoint()` | 会话关闭 |
| `TA_InvokeCommandEntryPoint()` | 命令分发 |

### Gate 机制

```
TA_InvokeCommandEntryPoint:
  ├─ Gate 1: 如果 cmd_needs_pin(cmd_id) → pin_mgr_verify()
  │     PIN_UNSET → 拒绝
  │     PIN_SET / PIN_LOCKED → 放行
  └─ Gate 2: 如果 cmd_needs_write(cmd_id) && pin_mgr_is_locked()
        PIN_LOCKED → 拒绝写操作
```

| 函数 | 返回 1 的命令 |
|------|------|
| `cmd_needs_pin()` | 除 `CMD_PIN_INIT`、`CMD_PROVISION_LOCK` 以外全部 |
| `cmd_needs_write()` | `CMD_KEY_GEN_RSA`、`CMD_KEY_GEN_AES`、`CMD_KEY_DELETE`、`CMD_PIN_INIT` |

### 内部依赖

```c
// 来自 pin_mgr.c
TEE_Result pin_mgr_init(pin, pin_len);
TEE_Result pin_mgr_verify(void);
void       pin_mgr_lock(void);
int        pin_mgr_is_locked(void);
int        pin_mgr_is_set(void);
void       pin_mgr_restore(void);

// 来自 keystore.c
TEE_Result keystore_gen_rsa(label, label_len, size_bits, perms);
TEE_Result keystore_gen_aes(label, label_len, size_bits, perms);
TEE_Result keystore_load(label, label_len, &type, &perms, &key_handle);
TEE_Result keystore_export_pub(label, label_len, out, out_len);
TEE_Result keystore_get_info(label, label_len, &info);
TEE_Result keystore_delete_key(label, label_len);

// 来自 acl.c
TEE_Result acl_check(permissions, required_perm);

// 来自 crypto_ops.c
TEE_Result crypto_rsa_sign(key, key_bits, data, data_len, sig, sig_len);
TEE_Result crypto_rsa_verify(key, key_bits, data, data_len, sig, sig_len);
TEE_Result crypto_rsa_decrypt(key, key_bits, cipher, c_len, plain, p_len);
TEE_Result crypto_aes_encrypt(key, key_bits, plain, p_len, cipher, c_len);
TEE_Result crypto_aes_decrypt(key, key_bits, cipher, c_len, plain, p_len);
```

## keystore.c — 密钥生命周期管理

### 密钥序列化格式

```c
struct serialized_key {
    uint32_t key_type;           // KEY_TYPE_RSA_KEYPAIR / KEY_TYPE_AES
    uint32_t permissions;        // PERM_SIGN | PERM_VERIFY | ...
    uint32_t key_size_bits;      // 2048 / 256 / ...
    uint32_t attr_count;         // RSA=8, AES=1
    uint32_t attr_sizes[8];      // 每个属性的字节长度
    // 后面紧跟属性数据: modulus, e, d, p, q, dp, dq, qinv (RSA)
    //               或 secret_value (AES)
};
```

### 持久化存储

- 密钥通过 `TEE_CreatePersistentObject` 写入 OP-TEE 安全存储
- 文件名 = `SHA-256(label)` 的前 16 字节作为 `TEE_UUID`
- 加密链：HUK → SSK → TSK → FEK → AES-GCM 密文
- 物理位置：`/data/tee/`（REE FS 开发）或 eMMC RPMB（量产）

### Session 读缓存

```c
#define CACHE_SLOTS 4

struct cache_entry { TEE_UUID uuid; uint8_t *data; size_t data_len; };
static struct cache_entry g_cache[CACHE_SLOTS];

// keystore_read: cache 命中 → 直接返回; cache miss → open→read→cache→close
```

缓存绕过 OP-TEE 3.2 REE FS 的同 session reopen 限制。

### 禁止覆盖策略

`keystore_gen_rsa/gen_aes` 生成前调用 `keystore_read` 检查 key 是否已存在——已存在则返回 `TEE_ERROR_ACCESS_CONFLICT`。

### 公钥导出格式

`CMD_KEY_EXPORT_PUB` 返回 `[n_len:4][e_len:4][modulus][exponent]`，调用方可解析无需预知 key size。

## pin_mgr.c — PIN 管理与 Lock

### 状态机

```
UNSET ──pin_mgr_init()──▶ SET ──pin_mgr_lock()──▶ LOCKED
  ▲                          │
  └── 持久化对象不存在         │ pin_mgr_restore() 从持久化存储恢复
                              ▼
                          SET / LOCKED
```

### 持久化对象

| 对象 | UUID | 内容 |
|------|------|------|
| `PIN_UUID` | `f8e9209a-3c7d-4d6b-a15e-7f328b11c0`**00** | PIN 的 SHA-256 hash |
| `LOCK_UUID` | `f8e9209a-3c7d-4d6b-a15e-7f328b11c0`**01** | Lock flag (1 byte) |

### 跨会话恢复

`pin_mgr_restore()` 在 `TA_OpenSessionEntryPoint` 被调用。通过尝试打开 `LOCK_UUID` → `PIN_UUID` 持久化对象来恢复 `g_pin_state`。

### pin_mgr_verify 简化

`PIN_SET` 状态下直接返回成功（不再做冗余的持久化对象 open/read），由 `pin_mgr_restore()` 在会话打开时完成验证。

## crypto_ops.c — 密码学封装

| 函数 | TEE 算法 | 模式 | 用途 |
|------|------|:---:|------|
| `crypto_rsa_sign` | `TEE_ALG_RSASSA_PKCS1_V1_5_SHA256` | SIGN | TLS CertificateVerify |
| `crypto_rsa_verify` | `TEE_ALG_RSASSA_PKCS1_V1_5_SHA256` | VERIFY | 对端证书验签 |
| `crypto_rsa_decrypt` | `TEE_ALG_RSA_NOPAD` | DECRYPT | TLS ClientKeyExchange 解密 |
| `crypto_aes_encrypt` | `TEE_ALG_AES_CBC_NOPAD` | ENCRYPT | 对称加密 |
| `crypto_aes_decrypt` | `TEE_ALG_AES_CBC_NOPAD` | DECRYPT | 对称解密 |

**注意**：
- RSA sign/verify 硬编码 SHA-256，Phase 2 可参数化
- RSA decrypt 使用 `TEE_ALG_RSA_NOPAD`（`m^d mod n`），OpenSSL 自行处理 padding
- AES 使用固定零 IV（`memset(iv, 0, 16)`），生产建议传入 IV

## acl.c — 访问控制

```c
TEE_Result acl_check(uint32_t permissions, uint32_t required_perm);
// permissions & required_perm == required_perm → TEE_SUCCESS
// 否则 → TEE_ERROR_ACCESS_DENIED
```

## 构建

TA 使用 OP-TEE 的 Makefile 构建系统（非 CMake）：

```bash
cd ta
source /opt/ql-ol-crosstool/ql-ol-crosstool-env-in
export TA_DEV_KIT_DIR=/opt/ql-ol-crosstool/sysroots/.../usr/include/optee/export-user_ta
make CROSS_COMPILE=aarch64-linux-gnu-
# 产物: f8e9209a-3c7d-4d6b-a15e-7f328b11c049.ta
```

## 部署

```bash
cp f8e9209a-*.ta /lib/optee_armtz/
# 设备启动时 OP-TEE 自动加载
```

## 依赖

| 依赖 | 说明 |
|------|------|
| OP-TEE OS ≥ 3.2 | 提供 GP TEE Internal Core API |
| GP TEE Internal Core API | `tee_internal_api.h` + `tee_internal_api_extensions.h` |
| TA dev kit | 交叉编译工具链 + sign.py |

## 相关文档

- [host/README.md](../host/README.md) — CA 命令行工具
- [engine/README.md](../engine/README.md) — OpenSSL ENGINE
- [05-key-storage.md](../docs/05-key-storage.md) — 密钥存储加密链
- [09-pin-management.md](../docs/09-pin-management.md) — PIN 管理方案
- [15-engine-debug-issues.md](../docs/15-engine-debug-issues.md) — TA 侧调试记录（问题 #5 #6 #7 #8）
