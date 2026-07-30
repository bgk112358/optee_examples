# 24 — SO-PIN + YubiKey 双因子解锁方案

## 1. 概述

### 1.1 问题

TA 量产锁定（`CMD_PROVISION_LOCK`）后，所有写操作被永久禁止。在以下场景中需要临时解除锁定：

| 场景 | 操作 |
|------|------|
| 设备证书到期 | 轮换密钥 + 重新签发证书 |
| 密钥泄露/疑似泄露 | 紧急吊销旧密钥 + 生成新密钥 |
| OTA 密钥迁移 | 写入新的解密密钥 |
| 安全策略变更 | 调整密钥权限位（需未来扩展） |
| 现场故障排查 | 临时生成测试密钥进行诊断 |

### 1.2 方案

**双因子认证（2FA）**：安全官员（Security Officer, SO）必须同时持有 **SO-PIN**（所知）和 **YubiKey**（所持）才能临时解除 TA 锁定。

这是智能卡/HSM 领域成熟的 SO 角色模型（PKCS#11 §6 的 Security Officer、GSMA eUICC ISD-R 密钥），适配到 TEE 环境：

- **SO-PIN**：32 字节随机值，灌装期写入 TA
- **YubiKey**：硬件令牌，持有 P-256 私钥，永不离硬件
- **两阶段解锁协议**：挑战-响应认证，防重放

### 1.3 与现有 PIN 的关系

| 维度 | Provisioning PIN | SO-PIN |
|------|:---:|:---:|
| 角色 | 工厂操作员 | 安全官员 |
| 数量 | 1 个 | 1 个 |
| 使用时机 | 产线灌装期 | 量产锁定后维护 |
| 存储 | `PIN_UUID` (SHA-256 hash) | `SO_PIN_UUID` (SHA-256 hash) |
| 锁定后可用 | 否（只读） | 是（触发解锁） |
| 硬件绑定 | 无 | 必须 + YubiKey |

两者**完全独立**、**并行存在**，互不影响。

---

## 2. 架构

```
┌──────────────────┐          ┌──────────────────┐          ┌─────────────────┐
│    YubiKey 5     │  USB     │  CA (Linux REE)  │  TEEC    │  TA (TEE)       │
│                  │◄────────▶│                  │─────────▶│                 │
│  PIV Slot 9a     │          │  keystore_client  │          │  so_pin_mgr.c   │
│  ECDSA P-256     │          │  + libykpiv       │          │  (新增模块)      │
│  私钥 (永不离硬件)│          │                  │          │                 │
│  证书 (可选)      │          │  仅中转,不持秘密   │          │  SO-PIN 验证     │
└──────────────────┘          └──────────────────┘          │  YubiKey 验签    │
                                                            │  失败计数器       │
                                                            │  Dongle 白名单    │
                                                            └─────────────────┘
```

**信任边界**：
- YubiKey 私钥 → 永不离 YubiKey 硬件
- CA → 不接触任何秘密材料（只做数据搬运）
- TA → 唯一的策略决策点，运行在 ARM TrustZone 安全世界

---

## 3. 解锁协议（两阶段）

```
Phase 1 — SO-PIN 验证
═══════════════════════════════════════════════════════════════
  CA ────CMD_SO_UNLOCK_REQ(pin_sha256)────▶ TA
                                         TA: 比对 SO-PIN hash ✓
                                         TA: TEE_GenerateRandom() → challenge[32]
  CA ◀──(challenge, dongle_count, dongle_id_list)──── TA

Phase 2 — YubiKey 证明
═══════════════════════════════════════════════════════════════
  CA 将 challenge 发送给 YubiKey:
       ykman piv sign 9a -s SHA256 challenge.bin > sig.der

  CA ────CMD_SO_UNLOCK_VERIFY(dongle_index, pubkey_der, signature)────▶ TA
                                                                      TA: 验证 pubkey hash ∈ 白名单
                                                                      TA: ECDSA_Verify(SHA256(challenge || TA_UUID), pubkey, sig)
                                                                      TA: ✓ → LOCKED → UNLOCKED
  CA ◀──(result, session_timeout_seconds)──── TA
```

### 3.1 防重放机制

`challenge` 由 TA 使用 `TEE_GenerateRandom()` 生成，每次调用不同。签名消息为：

```
SIGN( SHA256( challenge[32] || TA_UUID[16] || dongle_index[4] ) )
```

绑定 `TA_UUID` 确保签名不能跨 TA 实例复用；绑定 `dongle_index` 防止同一 challenge 在多个 YubiKey 间复用。

### 3.2 会话超时

UNLOCKED 状态是**临时**的，自动退出条件（任一满足即自动 `so_lock`）：

| 退出条件 | 机制 |
|----------|------|
| 显式锁定 | CA 调用 `CMD_SO_LOCK` |
| 会话关闭 | `TA_CloseSessionEntryPoint()` → `so_pin_auto_lock()` |
| 闲置超时 | `TEE_Wait(300000)` → 5 分钟无操作自动锁定 |
| TA 重启 | 状态从 `SO_LOCK_UUID` 恢复 → 始终回到 LOCKED |

---

## 4. 状态机

```
                    ┌──────────────┐
                    │    UNSET     │  无 PIN, TA 刚部署
                    │(pin+so均为unset)
                    └──────┬───────┘
                           │ pin_mgr_init() + so_pin_init() + provision_dongle()
                    ┌──────▼───────┐
                    │  PROVISIONED │  PIN+SO-PIN+Dongle 均已配置
                    │              │  可执行写操作
                    └──────┬───────┘
                           │ provision_lock()
                    ┌──────▼───────┐
                    │   LOCKED     │  量产锁定,写保护
                    │              │  SO-PIN+YubiKey 可解锁
                    └──────┬───────┘
                           │ so_unlock() ✓ (两阶段协议)
                    ┌──────▼───────┐
                    │  UNLOCKED    │  临时解锁(本会话有效,5min超时)
                    │              │  写操作恢复
                    └──────┬───────┘
                           │ so_lock() / 超时 / 会话关闭
                    ┌──────▼───────┐
                    │   LOCKED     │  自动回到锁定状态
                    └──────────────┘

                    异常路径:
                    ┌──────────────┐
                    │  SO_BRICKED  │  1000 次 SO-PIN 错误
                    │              │  永久锁定,不可恢复
                    └──────────────┘
```

**关键约束**：
- `so_unlock` 仅对 `LOCKED` 状态有效（`UNSET` 和 `PROVISIONED` 状态下无需解锁）
- `SO_BRICKED` 状态不可逆，设备需返厂重新灌装
- UNLOCKED 状态仅修改 Lock Gate，不影响 PIN Gate

---

## 5. TA 侧设计

### 5.1 新增模块: `so_pin_mgr.c`

```
ta/
├── entry.c          # 修改: 新增 SO 命令分发 + Gate 逻辑
├── pin_mgr.c        # 不变
├── keystore.c       # 不变
├── crypto_ops.c     # 修改: 新增 crypto_ecdsa_verify()
├── acl.c            # 不变
├── so_pin_mgr.c     # 新增: SO-PIN 管理 + 解锁协议
└── include/
    └── tbox_keystore_ta.h  # 修改: 新增命令 ID + SO 相关定义
```

### 5.2 新增持久化对象

| 对象 | UUID (末字节) | 内容 | 大小 |
|------|:---:|------|:---:|
| `SO_PIN_UUID` | `...0x10` | SO-PIN 的 SHA-256 hash | 32 B |
| `SO_DONGLE_UUID` | `...0x11` | Dongle 白名单 (见下方结构体) | 4 + N × 36 |
| `SO_FAIL_UUID` | `...0x12` | 失败计数器 (见下方结构体) | 12 |
| `SO_LOCK_UUID` | `...0x13` | SO 解锁状态标志 (1 = UNLOCKED) | 1 |

**Dongle 白名单结构体**:
```c
#define SO_DONGLE_MAX 8

struct so_dongle_entry {
    uint8_t  pubkey_hash[32];    // SHA-256(YubiKey P-256 公钥 DER)
    uint8_t  serial[4];         // YubiKey 序列号低 4 字节 (可选)
};

struct so_dongle_list {
    uint32_t count;              // 当前已注册数量
    struct so_dongle_entry entries[SO_DONGLE_MAX];
};
```

YubiKey P-256 公钥从 `ykman piv info` 获取（Slot 9a 默认用于 Authentication），导出为 DER (65 bytes 未压缩 or 33 bytes 压缩格式)，TA 侧计算 `SHA-256(pubkey_der)` 存入白名单。

**失败计数器结构体**:
```c
struct so_fail_counter {
    uint32_t consecutive_fails;   // 连续失败次数 (0..1000)
    uint32_t total_fails;         // 累计失败总数 (0..1000)
    uint32_t cooldown_until;      // 冷却期截止时间戳 (TEE_GetSystemTime)
};
```

### 5.3 新增命令

| 命令 | ID | 灌装期 | 锁定后 | 参数类型 | 说明 |
|------|:--:|:--:|:--:|------|------|
| `CMD_SO_PIN_INIT` | 12 | ✓ | ✗ | param[0]: MEMREF_INPUT (PIN hash) | 写入 SO-PIN |
| `CMD_PROVISION_DONGLE` | 13 | ✓ | ✗ | param[0]: MEMREF_INPUT (pubkey DER) | 注册 YubiKey 公钥 |
| `CMD_SO_UNLOCK_REQ` | 14 | — | ✓ | param[0]: MEMREF_INPUT (PIN hash), param[1]: MEMREF_OUTPUT (challenge), param[2]: VALUE_OUTPUT (dongle info) | Phase 1 |
| `CMD_SO_UNLOCK_VERIFY` | 15 | — | ✓ | param[0]: MEMREF_INPUT (pubkey DER), param[1]: MEMREF_INPUT (sig DER), param[2]: VALUE_INPUT (dongle_index) | Phase 2 |
| `CMD_SO_LOCK` | 16 | — | ✓ | 无参数 | 显式锁定 |
| `CMD_SO_GET_INFO` | 17 | ✓ | ✓ | param[0]: MEMREF_OUTPUT (status struct) | 查询 SO 状态 |

### 5.4 命令参数详细

#### CMD_SO_PIN_INIT (12)

```
param_types = TEE_PARAM_TYPES(
    TEE_PARAM_TYPE_MEMREF_INPUT,
    TEE_PARAM_TYPE_NONE,
    TEE_PARAM_TYPE_NONE,
    TEE_PARAM_TYPE_NONE
)

param[0].memref.buffer → SHA-256(SO-PIN) (32 bytes)
param[0].memref.size   → 32

返回: TEE_SUCCESS / TEE_ERROR_ACCESS_DENIED / TEE_ERROR_BAD_PARAMETERS
```

#### CMD_PROVISION_DONGLE (13)

```
param_types = TEE_PARAM_TYPES(
    TEE_PARAM_TYPE_MEMREF_INPUT,
    TEE_PARAM_TYPE_NONE,
    TEE_PARAM_TYPE_NONE,
    TEE_PARAM_TYPE_NONE
)

param[0].memref.buffer → YubiKey P-256 公钥 DER (65 or 33 bytes)
param[0].memref.size   → 公钥 DER 长度

TA 内部: SHA-256(pubkey_der) → 检查重复 → 追加到 so_dongle_list
返回: TEE_SUCCESS / TEE_ERROR_ACCESS_CONFLICT (重复) / TEE_ERROR_OVERFLOW (已满)
```

#### CMD_SO_UNLOCK_REQ (14)

```
param_types = TEE_PARAM_TYPES(
    TEE_PARAM_TYPE_MEMREF_INPUT,
    TEE_PARAM_TYPE_MEMREF_OUTPUT,
    TEE_PARAM_TYPE_VALUE_OUTPUT,
    TEE_PARAM_TYPE_NONE
)

param[0].memref.buffer → SHA-256(SO-PIN) (32 bytes)
param[1].memref.buffer ← challenge[32] + dongle_id_list[] (见下方格式)
param[1].memref.size   ← 实际输出字节数
param[2].value.a       ← 注册的 Dongle 数量
param[2].value.b       ← 冷却剩余秒数 (失败过多时)

param[1] 输出格式:
  [0..31]    challenge (32 bytes)
  [32..35]   dongle_count (4 bytes, little-endian)
  [36..67]   dongle[0].pubkey_hash (32 bytes)
  [68..71]   dongle[0].serial (4 bytes)
  [72..103]  dongle[1].pubkey_hash
  ... (循环)
```

#### CMD_SO_UNLOCK_VERIFY (15)

```
param_types = TEE_PARAM_TYPES(
    TEE_PARAM_TYPE_MEMREF_INPUT,
    TEE_PARAM_TYPE_MEMREF_INPUT,
    TEE_PARAM_TYPE_VALUE_INPUT,
    TEE_PARAM_TYPE_NONE
)

param[0].memref.buffer → YubiKey P-256 公钥 DER (用于验签)
param[0].memref.size   → 公钥 DER 长度
param[1].memref.buffer → ECDSA 签名 DER (64-72 bytes)
param[1].memref.size   → 签名长度
param[2].value.a       → dongle_index (0..7, 选择白名单条目)
param[2].value.b       → 保留

TA 验证:
  1. 检查 SO 状态 != SO_BRICKED
  2. SHA-256(param[0]) == so_dongle_list[dongle_index].pubkey_hash ?
  3. ECDSA_Verify(P-256, SHA256(challenge || TA_UUID || dongle_index),
                  param[0].pubkey, param[1].sig)
  4. 任一失败 → so_fail_counter 递增
  5. 全部通过 → g_so_state = SO_UNLOCKED, 重置连续计数器
                → 写入 SO_LOCK_UUID = 1
                → 返回 TEE_SUCCESS

返回: TEE_SUCCESS / TEE_ERROR_ACCESS_DENIED (PIN/公钥/签名错误) /
      TEE_ERROR_BAD_STATE (冷却中/已 bricked)
```

#### CMD_SO_LOCK (16)

```
param_types = TEE_PARAM_TYPES(
    TEE_PARAM_TYPE_NONE, ...
)

TA: g_so_state = SO_LOCKED
    TEE_CreatePersistentObject(SO_LOCK_UUID, flag=0)
    → 覆盖为 LOCKED 状态
```

#### CMD_SO_GET_INFO (17)

```
param[0].memref.buffer ← struct so_status {
    uint32_t state;           // 0=UNSET, 1=PROVISIONED, 2=LOCKED, 3=UNLOCKED, 4=BRICKED
    uint32_t dongle_count;    // 已注册 Dongle 数量
    uint32_t fail_total;      // 累计失败次数
    uint32_t fail_consecutive;// 连续失败次数
    uint32_t cooldown_left;   // 冷却剩余秒数 (0=未冷却)
}
```

### 5.5 抗暴力破解

```c
#define SO_FAIL_MAX_CONSECUTIVE  3     // 连续3次错误 → 冷却
#define SO_FAIL_COOLDOWN_SECS    60    // 冷却60秒
#define SO_FAIL_MAX_TOTAL        1000  // 累计1000次 → 永久锁定

/* so_pin_mgr 内部逻辑 */

static TEE_Result so_check_fail_counter(void)
{
    struct so_fail_counter fc;
    so_fail_load(&fc);

    // 1. 永久锁定检查
    if (fc.total_fails >= SO_FAIL_MAX_TOTAL) {
        g_so_state = SO_BRICKED;
        return TEE_ERROR_ACCESS_DENIED;  // "Permanently locked"
    }

    // 2. 冷却期检查
    if (fc.consecutive_fails >= SO_FAIL_MAX_CONSECUTIVE) {
        TEE_Time now;
        TEE_GetSystemTime(&now);
        uint32_t now_sec = (uint32_t)(now.seconds);

        if (now_sec < fc.cooldown_until) {
            // 仍在冷却中
            uint32_t left = fc.cooldown_until - now_sec;
            return TEE_ERROR_BAD_STATE;  // "Cooldown active, %u sec left"
        }

        // 冷却期已过,重置连续计数器
        fc.consecutive_fails = 0;
        fc.cooldown_until = 0;
    }

    return TEE_SUCCESS;
}

static void so_record_failure(void)
{
    struct so_fail_counter fc;
    so_fail_load(&fc);

    fc.consecutive_fails++;
    fc.total_fails++;

    if (fc.consecutive_fails >= SO_FAIL_MAX_CONSECUTIVE) {
        TEE_Time now;
        TEE_GetSystemTime(&now);
        fc.cooldown_until = (uint32_t)(now.seconds) + SO_FAIL_COOLDOWN_SECS;
    }

    so_fail_save(&fc);
}

static void so_reset_consecutive(void)
{
    struct so_fail_counter fc;
    so_fail_load(&fc);
    fc.consecutive_fails = 0;
    fc.cooldown_until = 0;
    so_fail_save(&fc);
}
```

**时序示例**：
```
尝试 1: ✗ → consecutive=1, total=1
尝试 2: ✗ → consecutive=2, total=2
尝试 3: ✗ → consecutive=3, total=3, cooldown=now+60s
尝试 4 (10s后): ✗ → 冷却中,拒绝 (剩余50s)
尝试 5 (65s后): ✓ → consecutive=0, cooldown=0, total=3

累计 total 达到 1000 → SO_BRICKED, 永久锁定, 设备返厂
```

### 5.6 TA 入口点修改

```c
// entry.c 新增 Gate 逻辑

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
                                      uint32_t cmd_id, ...)
{
    // Gate 1: PIN 检查 (SO 命令由 SO-PIN 自行验证,跳过 Provisioning PIN 检查)
    if (cmd_needs_pin(cmd_id) && !cmd_is_so(cmd_id)) {
        res = pin_mgr_verify();
        if (res != TEE_SUCCESS)
            return res;
    }

    // Gate 2: 写保护检查 (SO 命令在 UNLOCKED 状态下豁免)
    if (cmd_needs_write(cmd_id) && !cmd_is_so(cmd_id)) {
        if (pin_mgr_is_locked() && !so_pin_is_unlocked()) {
            return TEE_ERROR_ACCESS_DENIED;
        }
    }

    // 新增 SO 命令分发
    switch (cmd_id) {
        // ... 原有命令 ...
        case CMD_SO_PIN_INIT:       return cmd_so_pin_init(...);
        case CMD_PROVISION_DONGLE:  return cmd_provision_dongle(...);
        case CMD_SO_UNLOCK_REQ:     return cmd_so_unlock_req(...);
        case CMD_SO_UNLOCK_VERIFY:  return cmd_so_unlock_verify(...);
        case CMD_SO_LOCK:           return cmd_so_lock(...);
        case CMD_SO_GET_INFO:       return cmd_so_get_info(...);
    }
}

// SO 命令不需要 Provisioning PIN 验证 (自带 SO-PIN)
static int cmd_is_so(uint32_t cmd_id)
{
    switch (cmd_id) {
        case CMD_SO_PIN_INIT:
        case CMD_PROVISION_DONGLE:
        case CMD_SO_UNLOCK_REQ:
        case CMD_SO_UNLOCK_VERIFY:
        case CMD_SO_LOCK:
        case CMD_SO_GET_INFO:
            return 1;
        default:
            return 0;
    }
}
```

### 5.7 crypto_ops.c 新增函数

```c
/*
 * ECDSA P-256 verify — used for YubiKey challenge-response.
 * YubiKey signs SHA256(data), TA verifies with the corresponding public key.
 */
TEE_Result crypto_ecdsa_verify(
    const uint8_t *pubkey_der,  size_t pubkey_der_len,
    const uint8_t *data,        size_t data_len,
    const uint8_t *sig_der,     size_t sig_der_len)
{
    // 1. Import public key from DER
    // 2. Allocate transient ECC key object
    // 3. TEE_AsymmetricVerifyDigest(TEE_ALG_ECDSA_P256, hash, ...)
    // 4. Return TEE_SUCCESS / TEE_ERROR_SIGNATURE_INVALID
}
```

### 5.8 TA 侧估算代码量

| 模块 | 新增/修改 | 估算行数 |
|------|:--:|:--:|
| `so_pin_mgr.c` | 新增 | ~350 |
| `entry.c` | 修改 | +60 |
| `crypto_ops.c` | 修改 | +50 |
| `tbox_keystore_ta.h` | 修改 | +60 |
| **合计** | | **~520** |

---

## 6. CA 侧设计

### 6.1 Dongle 抽象层

CA 通过 `struct dongle_ops` 统一接口表操作 dongle，不感知底层品牌。代码位置：`host/dongle/`。

```
host/dongle/
├── dongle_ops.h          # 统一接口头文件 (struct dongle_ops)
├── dongle_factory.c      # 后端注册 + 自动检测
├── dongle_yubikey.c      # YubiKey 实现 (ykman CLI / libykpiv)
├── dongle_dummy.c        # 模拟 Dongle (本地 P-256 密钥文件, dev/CI)
└── (deps: libykpiv / ykman CLI / OpenSSL)
```

**统一接口**（详见 `host/dongle/dongle_ops.h`）：

```c
struct dongle_ops {
    const char *name;       // "yubikey" | "dummy"
    uint32_t    caps;       // DONGLE_CAP_SIGN | DONGLE_CAP_GET_PUBKEY | ...

    int  (*probe)(void);                // 检测硬件是否在位
    int  (*open)(struct dongle_ctx **ctx);
    void (*close)(struct dongle_ctx *ctx);

    int  (*sign)(struct dongle_ctx *ctx,
                 const uint8_t *digest, size_t digest_len,
                 uint8_t *sig_der, size_t *sig_len);  // ECDSA P-256

    int  (*get_pubkey)(struct dongle_ctx *ctx,
                       uint8_t *pubkey_der, size_t *pubkey_len);

    int  (*get_serial)(struct dongle_ctx *ctx, uint32_t *serial);
    int  (*get_attr)(struct dongle_ctx *ctx, const char *key,
                     char *val, size_t val_len);
};

// 工厂函数
const struct dongle_ops *dongle_detect(void);    // 自动检测第一个可用后端
const struct dongle_ops *dongle_get(const char *name); // 按名称选择
```

**后端注册机制**：每个 `dongle_*.c` 暴露一个 `dongle_<name>_get_ops()` 函数（weak symbol），`dongle_factory.c` 按优先级探测：YubiKey → Dummy。

### 6.2 YubiKey 后端

`dongle_yubikey.c` 支持两种通信模式：

```
WITH_LIBYKPIV=1 (推荐量产):
  libykpiv → ykpiv_connect() / ykpiv_sign_data() / ykpiv_get_cert()
  直接 USB 通信，无子进程开销

WITH_LIBYKPIV=0 (默认, 开发/调试):
  ykman CLI 子进程 fallback:
  ├── ykman piv info                    → 获取公钥 + 序列号
  ├── ykman piv sign 9a -s SHA-256 ... → 签名 challenge
  └── ykman piv export-certificate 9a - → 导出证书
```

### 6.2b Dummy 后端

`dongle_dummy.c` — 开发/CI 用，无需物理硬件：

```
从本地 PEM 文件读取 P-256 密钥:
  默认: ~/.tbox/dummy-dongle-key.pem
  环境变量: TBOX_DUMMY_KEY=<path>

make gen-dummy-key  → 自动生成测试密钥
sign() → OpenSSL EVP_DigestSign (ECDSA P-256)
probe() → 检查密钥文件是否存在
```

### 6.3 CA CLI 接口

```bash
# ===== 灌装期 (LOCK 前) =====
tbox_keystore --init-so-pin <hex-pin>
    # 写入 SO-PIN (32 bytes hex)
    # TA 内部: SHA-256(PIN) → SO_PIN_UUID

tbox_keystore --provision-dongle [--dongle <name>]
    # 自动检测 dongle (或指定 --dongle yubikey|dummy)
    # 读取公钥 → CMD_PROVISION_DONGLE 注册到 TA
    # 支持多次调用注册多把 dongle (最多 8 把)

tbox_keystore --provision-dongle-from-file <pubkey.der>
    # 从文件导入公钥 (量产批量灌装, 不依赖 dongle 在场)

# ===== 维护期 (LOCK 后) =====
tbox_keystore --so-unlock --so-pin <hex> [--dongle <name>] [--dongle-index <n>]
    # 自动执行两阶段协议:
    #   1. CMD_SO_UNLOCK_REQ(pin_hash) → challenge + dongle_list
    #   2. Dongle 签名 challenge
    #   3. CMD_SO_UNLOCK_VERIFY(pubkey, sig) → UNLOCKED

tbox_keystore --so-lock
    # 显式锁定 TA (UNLOCKED → LOCKED)

tbox_keystore --so-info
    # 查询 SO 状态: 状态/dongle 数量/失败次数/冷却时间
```

### 6.4 CA 内部流程: `do_so_unlock()`

```c
static int do_so_unlock(const char *pin_hex, const char *dongle_name,
                         int dongle_index)
{
    // 0. 准备 PIN (CA 发送原始 PIN, TA 内部 SHA-256)
    uint8_t pin_hash[32];
    hex_decode(pin_hex, pin_hash, 32);

    // 1. Phase 1: 请求解锁
    uint8_t chg_out[SO_CHG_BUF_SIZE];
    TEEC_Operation op = { ... };
    op.params[0].memref.buffer = pin_hash;
    op.params[1].memref.buffer = chg_out;
    res = TEEC_InvokeCommand(&g_sess, CMD_SO_UNLOCK_REQ, &op, ...);
    if (res == TEE_ERROR_BAD_STATE) {
        // 冷却中 ...
    }
    if (res != TEE_SUCCESS) goto fail;

    // 2. 解析 challenge + dongle_list
    uint8_t *challenge = chg_out;
    uint32_t dongle_count = *(uint32_t *)(chg_out + 32);

    // 3. Phase 2: Dongle 签名 (通过统一接口, 不感知品牌)
    const struct dongle_ops *ops;
    struct dongle_ctx *ctx;

    ctx = dongle_open(&ops, dongle_name);  // auto-detect or --dongle <name>

    uint8_t sig_der[72];
    size_t sig_len = sizeof(sig_der);
    ops->sign(ctx, challenge, 32, sig_der, &sig_len);

    uint8_t pubkey_der[91];
    size_t pubkey_len = sizeof(pubkey_der);
    ops->get_pubkey(ctx, pubkey_der, &pubkey_len);
    ops->close(ctx);

    // 4. 发送验证请求
    op.params[0].memref.buffer = pubkey_der;
    op.params[1].memref.buffer = sig_der;
    op.params[2].value.a = dongle_index;
    res = TEEC_InvokeCommand(&g_sess, CMD_SO_UNLOCK_VERIFY, &op, ...);

    if (res == TEE_SUCCESS) {
        printf("SO unlock succeeded. TA is UNLOCKED (5 min timeout).\n");
        return 0;
    }
    ...
}
```

注意：`dongle_open()` 内部调用 `dongle_detect()` 或 `dongle_get(name)`，CA 代码不需要 `#ifdef` 或品牌判断逻辑。

### 6.5 CA 侧估算代码量

| 文件 | 新增/修改 | 估算行数 |
|------|:--:|:--:|
| `dongle/dongle_ops.h` | 新增 | ~70 |
| `dongle/dongle_factory.c` | 新增 | ~80 |
| `dongle/dongle_dummy.c` | 新增 | ~220 |
| `dongle/dongle_yubikey.c` | 新增 | ~250 |
| `keystore_client.c` | 修改 | +200 (SO 命令) |
| `Makefile` | 修改 | +15 |
| **合计** | | **~835** |

---

## 7. 多 Dongle 支持

### 7.0 设备-Dongle 映射关系（核心架构决策）

**一个 YubiKey → 多个设备（1:N 共享模式）**

YubiKey 认证的是**安全官员这个人（角色身份）**，不是某一台设备：

```
┌─────────────────────────────────────────────────────┐
│                   安全官员 (1 人)                      │
│                                                     │
│   主 YubiKey (dongle #0)  +  备用 YubiKey (dongle #1) │
│   已知 SO-PIN                                        │
└──────────┬──────────────┬──────────────┬────────────┘
           │              │              │
    ┌──────▼──────┐ ┌─────▼──────┐ ┌────▼──────┐
    │ TBox #00001 │ │ TBox #00002│ │ TBox #... │  ...最多 10,000+ 台
    │ 白名单里都存  │ │ 白名单里都存 │ │ 白名单里都存 │
    │ 同一把YubiKey│ │ 同一把YubiKey│ │ 同一把YubiKey│
    │ 的公钥哈希    │ │ 的公钥哈希   │ │ 的公钥哈希   │
    └─────────────┘ └────────────┘ └────────────┘
```

**为什么这个模型是正确的：**

| 考量 | 说明 |
|------|------|
| **角色模型** | 与 PKCS#11 §6 SO 模型、GSMA eUICC ISD-R 一致——SO 是角色身份，不是设备身份 |
| **运维效率** | 安全官员带 1 把 YubiKey 可维护整个车队的任意设备，无需携带设备-YubiKey 对照表 |
| **防重放天然隔离** | 每台设备的 TA 独立生成随机 challenge，且签名绑定 TA_UUID，签名无法跨设备重放 |
| **风险评估** | YubiKey 丢失 → 所有设备受影响（严重但概率低，物理令牌+SO-PIN 双因子）vs 攻击者物理接触单台设备 → 仅该设备受影响 |

**不推荐的替代方案：**

| 方案 | 问题 |
|------|------|
| 一设备一 YubiKey（1:1） | 10,000 台设备 = 10,000 把 YubiKey，采购成本 $50×10000=$500,000，管理不可行 |
| 一 YubiKey 内多 Slot 区分设备 | YubiKey PIV 仅 4 个 Slot，无法扩展到车队规模 |

### 7.1 白名单管理

TA 通过 `so_dongle_list`（最多 8 个条目）维护授权 YubiKey 列表，同一把 YubiKey 的公钥哈希被写入所有设备的 TA：

```
灌装期 (每台设备重复执行):
  --provision-dongle          # 注册安全官员的主 YubiKey → dongle[0]
  --provision-dongle          # 注册安全官员的备用 YubiKey → dongle[1]
  --provision-dongle          # 注册审计部门的 YubiKey → dongle[2] (可选)

维护期 (安全官员到任意一台设备):
  --so-unlock --dongle-index 0   # 使用主 YubiKey 解锁
  --so-unlock --dongle-index 1   # 使用备用 YubiKey 解锁
```

### 7.2 车队规模部署模型

| 角色 | YubiKey 编号 | 持有者 | 注册范围 |
|------|:--:|------|------|
| 主安全官员 | Dongle #0 | 安全部门负责人 | **所有设备** |
| 备用安全官员 | Dongle #1 | 安全部门副手（密钥托管在保险柜） | **所有设备** |
| 区域维护工程师 | Dongle #2 | 特定区域负责人 | **该区域设备**（分批灌装时按注册） |
| 审计/合规 | Dongle #3 | 第三方审计机构 | **抽检设备**（按需注册） |

### 7.3 SO-PIN 策略

| 策略 | 说明 | 推荐场景 |
|------|------|---------|
| **同批次共用 SO-PIN** | 同一生产批次的设备使用相同 SO-PIN | ✓ 推荐：产线自动化简单，运维方便 |
| 每设备独立 SO-PIN | 工控机为每台设备生成独立 SO-PIN，加密交付给安全官员 | 极高安全场景（需配套 PIN 管理系统） |

**共用 SO-PIN 的安全论证**：SO-PIN 是双因子中的"所知"因子，单独泄露不构成威胁（攻击者仍需 YubiKey 物理硬件）。YubiKey 私钥永不离硬件，且解锁需要同时输入 SO-PIN + 插入 YubiKey + 签名 challenge。

### 7.4 防克隆

TA 可选记录 YubiKey 序列号（4 字节），解锁时交叉验证：
```
SHA-256(pubkey) == whitelist[index].pubkey_hash  ✓
ykpiv_get_serial() == whitelist[index].serial    ✓ (可选)
```

由于 YubiKey 固件禁止私钥导出，即使公钥被复制也无法伪造签名。序列号验证是额外的深度防护层。

---

## 8. 灌装流程变更

### 8.1 原流程（单台设备）

```
[1/5] init PIN → [2/5] gen RSA → [3/5] gen AES → [4/5] export pub → [5/5] lock
```

### 8.2 新流程（单台设备）

```
[1/7] init PIN           → tbox_keystore --init-pin <PIN>
[2/7] gen RSA device key → tbox_keystore --gen-rsa device-key ...
[3/7] gen AES OTA key    → tbox_keystore --gen-aes ota-key ...
[4/7] export public key  → tbox_keystore --export-pub device-key --out key.pub
[5/7] init SO-PIN        → tbox_keystore --init-so-pin <SO-PIN>        ← 新增
[6/7] provision dongle   → tbox_keystore --provision-dongle            ← 新增
                            tbox_keystore --provision-dongle  (备用)   ← 新增
[7/7] lock TA            → tbox_keystore --lock
```

**步骤 5-6 是生产环境强制步骤**。如果跳过，锁定后无法通过 SO 维护。`lock` 命令应检查 `SO_PIN_UUID` 是否存在，若不存在则打印警告并要求确认。

### 8.3 量产批量灌装（关键变更）

产线上 YubiKey **不需要逐台插拔**。工控机预先从安全官员的 YubiKey 导出公钥（一次性操作），然后在每台设备的灌装脚本中从文件导入：

```bash
#!/bin/bash
# =============================================
# 量产灌装脚本 (provision_batch.sh)
# 在工厂工控机上对 N 台设备循环执行
# =============================================

# === 一次性准备（工厂初始化时执行一次） ===
# 1. 安全官员插入 YubiKey 到工控机
# 2. 导出公钥到文件
ykman piv export-certificate 9a - | openssl x509 -pubkey -noout > so-dongle-0.pub
# 3. 如有备用 YubiKey，重复上一步
ykman piv export-certificate 9a - | openssl x509 -pubkey -noout > so-dongle-1.pub

# 4. 生成批次 SO-PIN（整个批次共用）
openssl rand -hex 32 > batch-so-pin.txt
# 5. SO-PIN 加密交付给安全官员（如 GPG 加密邮件）
gpg --encrypt --recipient security-officer@example.com batch-so-pin.txt

# === 每台设备循环（YubiKey 不需要在场） ===
SO_PIN=$(cat batch-so-pin.txt)

for device_serial in $(cat devices.txt); do
    echo "=== Provisioning device: $device_serial ==="

    # 生成设备独立的 Provisioning PIN
    DEV_PIN=$(openssl rand -hex 16)

    tbox_keystore --init-pin $DEV_PIN
    tbox_keystore --gen-rsa device-key --size 2048 --sign --decrypt
    tbox_keystore --gen-aes ota-key --size 256 --decrypt
    tbox_keystore --export-pub device-key --out ${device_serial}-device-key.pub
    tbox_keystore --init-so-pin $SO_PIN
    tbox_keystore --provision-dongle-from-file so-dongle-0.pub
    tbox_keystore --provision-dongle-from-file so-dongle-1.pub
    tbox_keystore --lock

    echo "  → Done. Pubkey: ${device_serial}-device-key.pub"
done
```

**YubiKey 物理连接拓扑**：

```
┌────────── 量产阶段（工厂）──────────┐   ┌──────── 维护阶段（现场）───────┐
│                                     │   │                              │
│  YubiKey ─USB─▶ 工控机(PC)          │   │  方案A: YubiKey ─USB─▶ TBox   │
│  (安全官员插一次,30秒导出公钥)       │   │  (TBox 有 USB Host,直接插)     │
│                                     │   │                              │
│  工控机 ─串口─▶ TBox #1             │   │  方案B: YubiKey ─USB─▶ 笔记本  │
│         ─串口─▶ TBox #2             │   │  笔记本 ─SSH/串口─▶ TBox      │
│         ─串口─▶ TBox #...           │   │  (TBox 无 USB Host,间接连)    │
│         ─串口─▶ TBox #N             │   │                              │
│                                     │   │                              │
│  YubiKey 和 TBox 无物理接触          │   │  YubiKey 连到跑 CA 命令的设备   │
│  TBox 只拿到公钥哈希(存 TA 安全存储)  │   │  CA 调用 YubiKey 签名 challenge │
└─────────────────────────────────────┘   └──────────────────────────────┘
```

**关键点**：
- **YubiKey 插在工控机上**，不是插在 TBox 上；工控机通过串口/USB Ethernet/ADB 连接每台 TBox 并发送灌装命令
- YubiKey 只在工厂初始化时插一次（导出公钥到文件），量产循环中 YubiKey 不需要在场
- TBox 设备在整个量产过程中从未物理接触 YubiKey
- 同一批次共用 SO-PIN，简化产线自动化
- SO-PIN 通过独立安全通道（GPG 加密邮件 / 密码管理器共享）交付给安全官员
- Provisioning PIN 仍是每设备独立的（设备身份凭证）
- `--provision-dongle-from-file` 从公钥文件导入，与 `--provision-dongle`（从 YubiKey 实时读取）等效

### 8.4 SO-PIN 生成与交付

```bash
# 工厂工控机生成随机 SO-PIN
openssl rand -hex 32 > batch-so-pin.txt

# 安全交付给安全官员（如加密邮件/HSM 传输密钥保护）
gpg --encrypt --recipient security-officer@example.com batch-so-pin.txt
```

SO-PIN 不应与 Provisioning PIN 相同，应由独立的安全通道交付给 SO 角色人员。建议每批次换一个 SO-PIN，降低长期运营风险。

---

## 9. 安全分析

### 9.1 威胁模型

| 威胁 | 缓解 | 残余风险 |
|------|------|---------|
| SO-PIN 暴力破解 | 3 次冷却 → 1000 次 brick | 侧信道泄露 PIN hash 比对时间 |
| YubiKey 丢失/被盗 | 私钥无法导出; 攻击者仍需 SO-PIN | 物理强制使用 YubiKey (按按钮) 可能被利用 |
| 重放攻击 | 一次性 challenge 绑定 TA_UUID | challenge PRNG 熵不足 (极低风险) |
| CA 内存篡改 | CA 不持有秘密; TA 独立验证 | 内存损坏可能导致 CA 崩溃,但不影响 TA |
| 中间人攻击 (REE→TA) | ARM TrustZone SMC 隔离 | ARM 硬件漏洞 (如漏洞 CVE,极低风险) |
| YubiKey 克隆 | YubiKey 固件禁止私钥导出; 序列号可选验证 | 供应链攻击替换 YubiKey |
| 会话劫持 | UNLOCKED 状态 5 分钟超时 + 会话关闭自动锁定 | 攻击者在 5 分钟窗口内执行恶意操作 |
| TA 重启绕过 | `SO_LOCK_UUID` 持久化; 启动时恢复到 LOCKED | TA 持久化存储被物理篡改 (需 eMMC RPMB) |

### 9.2 剩余风险

1. **SO-PIN 与 Provisioning PIN 同源**：如果工厂工控机同时生成两个 PIN 并明文传输，则双因子退化为单因子
   - 缓解：SO-PIN 由独立的安全通道（如安全官员的密码管理器）生成，工厂只负责写入

2. **UNLOCKED 窗口期**：5 分钟内攻击者可利用解锁状态执行写操作
   - 缓解：维护后立即执行 `--so-lock`；TA 侧可缩短超时时间

3. **SO_BRICKED 后无可恢复路径**：1000 次失败是终局的
   - 缓解：1000 次上限足够高 (日均 3 次可撑近一年)

### 9.3 安全等级评估

| 指标 | 等级 | 说明 |
|------|:--:|------|
| 认证强度 | **高** | 双因子: SO-PIN (所知) + YubiKey (所持) + 挑战-响应 |
| 防暴力破解 | **高** | 3 次冷却 + 1000 次 brick |
| 防重放 | **高** | TA_UUID 绑定 + 一次性 challenge |
| 权限分离 | **高** | SO 与工厂操作员完全分离 |
| 审计能力 | **中** | TA 记录失败计数器和解锁事件,但缺少带时间戳的详细审计日志 |

---

## 10. 实现计划

### Phase 1: 核心 TA (1-2 周)

| 任务 | 文件 | 说明 |
|------|------|------|
| 1.1 定义 SO 命令 + 结构体 | `tbox_keystore_ta.h` | 新增 CMD 12-17 + SO 结构体 |
| 1.2 实现 `so_pin_mgr.c` | `so_pin_mgr.c` | SO-PIN 管理 + 解锁协议 + 失败计数器 |
| 1.3 实现 `crypto_ecdsa_verify()` | `crypto_ops.c` | ECDSA P-256 验签 |
| 1.4 修改 TA 入口 | `entry.c` | Gate 逻辑 + 命令分发 |
| 1.5 TA 单元测试 | `ta/test/` | 各命令测试用例 |

### Phase 2: CA + YubiKey 集成 (1 周)

| 任务 | 文件 | 说明 |
|------|------|------|
| 2.1 `ykpiv_comm.c` | CA 新增模块 | libykpiv 封装 |
| 2.2 `ykman_fallback.c` | CA 新增模块 | ykman CLI fallback (可选) |
| 2.3 CA CLI 扩展 | `keystore_client.c` | 6 个新命令 |
| 2.4 端到端测试 | `test/so_unlock_test.sh` | 灌装 → 锁定 → SO 解锁 → 重新锁定 |

### Phase 3: 文档 + 部署 (0.5 周)

| 任务 | 说明 |
|------|------|
| 3.1 灌装脚本更新 | `provision.sh` 加入 SO-PIN + Dongle 步骤 |
| 3.2 安全操作手册 | SO 解锁操作 SOP |
| 3.3 灾难恢复指南 | YubiKey 丢失/Brick 恢复流程 |

---

## 11. 依赖

| 依赖 | 版本 | 用途 |
|------|------|------|
| OP-TEE OS | ≥ 3.2 | `TEE_GenerateRandom`, `TEE_GetSystemTime` |
| GP TEE Internal Core API | 1.1 | `TEE_AsymmetricVerifyDigest` (ECDSA) |
| libykpiv | ≥ 0.6 | CA 侧 YubiKey 通信 |
| ykman CLI | ≥ 4.0 | CA 侧 fallback (可选) |
| YubiKey 5 / 5C / 5 Nano | — | 硬件令牌 (P-256, PIV Slot 9a) |

---

## 12. 兼容性与约束

### 12.1 向后兼容

- 现有灌装流程如果**不**执行 `--init-so-pin` + `--provision-dongle`，TA 在 LOCKED 后无法通过 SO 解锁——行为与当前版本一致
- 建议：从本版本起，`lock` 命令检查 SO-PIN 是否已配置，如果 `SO_PIN_UUID` 不存在则打印警告

### 12.2 未来扩展

| 扩展项 | 说明 |
|--------|------|
| 方案 B 完整证书链 | TA 内嵌 X.509 验证器 → 支持按 CA 灵活授权 |
| SO 审计日志环 | TA 内分配固定大小的审计日志缓冲区 (e.g. 128 条记录) |
| 国密 SM2 支持 | 替换 ECDSA P-256 为 SM2 签名验签 → 适配国密 YubiKey |
| 远程 SO 解锁 | CA 代理模式下将 YubiKey 签名远程化 (安全风险高,需额外保护) |

---

## 附录 A. YubiKey PIV Slot 说明

| Slot | 默认用途 | 密钥类型 | 推荐 |
|------|---------|---------|:--:|
| 9a | PIV Authentication | P-256 | ✓ (本方案默认) |
| 9c | Digital Signature | P-256 | 备选 |
| 9d | Key Management | P-256 | 备选 |
| 9e | Card Authentication | P-256 | 备选 |

选择 Slot 9a 的原因：出厂预置密钥（无需手动生成），`ykman piv info` 可直接读取公钥。

## 附录 B. ykman 命令参考

```bash
# 查看 YubiKey 信息 (含公钥 + 序列号)
ykman piv info

# 签名 challenge (YubiKey 内部 SHA-256 + ECDSA)
echo -n '<challenge>' | ykman piv sign 9a -s SHA256 - > sig.der

# 导出 Slot 9a 公钥
ykman piv export-certificate 9a - | openssl x509 -pubkey -noout > pubkey.pem

# 导出序列号
ykman info | grep "Serial number"
```
