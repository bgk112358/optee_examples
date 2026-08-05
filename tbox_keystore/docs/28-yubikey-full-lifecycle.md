# 28 — YubiKey 在 SO 解锁流程中的端到端使用

## 摘要

本文档描述 YubiKey 在 TBox 安全体系中的**完整使用闭环**——从采购到灌装到现场 SO 解锁。

[27-yubikey-provisioning-trusted-server.md](27-yubikey-provisioning-trusted-server.md) 已详细描述了"灌装阶段"如何将 YubiKey 公钥哈希通过可信服务器签名的 manifest 安全写入 TA 白名单。本文档聚焦**灌装之后**：白名单如何在 SO 解锁流程中发挥实际作用，以及当前实现中的缺口和修复方案。

---

## 1. 全生命周期概览

```
┌─────────────────────────────────────────────────────────────────┐
│ 阶段 1: 灌装（一次性）                            详见 doc 27    │
│                                                                 │
│  采购 YubiKey                                                   │
│    → 可信服务器: 读公钥 → SHA-256 → manifest 签名               │
│    → 工控机: 搬运 manifest.bin + .sig 到 TBox                   │
│    → TA: RSA 验签 → 白名单写入 SO_DONGLE_UUID                   │
│                                                                 │
│  结果: TA 安全存储中存有:                                        │
│    {                                                             │
│      dongle[0]: SHA-256(pubkey_A), serial_A                     │
│      dongle[1]: SHA-256(pubkey_B), serial_B                     │
│    }                                                             │
├─────────────────────────────────────────────────────────────────┤
│ 阶段 2: SO 解锁（日常维护）                       本文档重点     │
│                                                                 │
│  安全官员携带 YubiKey 到现场                                    │
│    → TBox CA: 读 YubiKey 公钥                                   │
│    → TBox CA: SHA-256(pubkey) → 得到 hash                       │
│    → TBox CA: challenge = CMD_SO_UNLOCK_REQ(SO-PIN)             │
│    → TBox CA: YubiKey 签名 challenge                            │
│    → TBox CA: OpenSSL 本地验签                                  │
│    → TBox CA: CMD_SO_UNLOCK_CONFIRM → TA 解锁                   │
│                                                                 │
│  安全保证:                                                        │
│    ① SO-PIN 必须正确（Phase 1）                                 │
│    ② YubiKey 必须能对 challenge 产生有效签名（Phase 2 CA 验签） │
│    ③ YubiKey 公钥哈希必须在白名单中（Phase 2 → 见 §3 缺口）    │
└─────────────────────────────────────────────────────────────────┘
```

**YubiKey 在整个闭环中的四个功能点**：

| # | 功能 | 使用的 YubiKey 能力 | 在哪个阶段 | 作用 |
|:--:|------|------|:--:|------|
| 1 | 公钥提取 | `ykman piv export-certificate 9a` → PIV Slot 9a 设备证书 | 灌装 | 获取公钥 → SHA-256 → 写入白名单 |
| 2 | Challenge 签名 | `ykman piv sign 9a -s SHA256 <digest>` → PIV ECDSA P-256 签名 | SO 解锁 | 证明"我持有这把 YubiKey 的私钥" |
| 3 | 公钥识别 | `ops->get_pubkey()` → 读取同一个 PIV Slot 9a 公钥 | SO 解锁 | 让 TA 知道"是哪把 YubiKey 在签名" |
| 4 | （当前未用）序列号验证 | `ykman info` → 设备序列号 | 可选 | 额外的物理设备身份绑定 |

关键在于**闭环逻辑**：灌装时写入白名单的公钥哈希，必须与解锁时出示的 YubiKey 公钥的哈希一致。YubiKey 持有者无法改变其 YubiKey 的公钥（私钥不可导出，无法生成对应另一个公钥的签名）。

---

## 2. SO 解锁流程中的 YubiKey 交互

### 2.1 完整时序

```
安全官员                    TBox CA (REE)              TBox TA (TEE)          TBox 安全存储
────────                    ────────────               ────────────           ──────────────
① 插入 YubiKey ──USB──▶ 

② 输入 SO-PIN
   "f1e2d3c4..."

                        ③ SHA-256(PIN) ─────CMD_SO_UNLOCK_REQ────▶
                                                                       ④ 验证 PIN hash
                                                                          检查失败计数器
                                                                          检查冷却期
                                                                       ⑤ 生成 challenge[32]
                                                                          TEE_GenerateRandom()
                                                                       ⑥ 读取白名单
                                                                          SO_DONGLE_UUID
                                                           ◀──challenge──────────────
                                                              + dongle_list

                        ⑦ SHA-256(challenge) → chg_hash
                        ⑧ 调用 YubiKey:               ← YubiKey 私钥签名
                           ECDSA P-256 sign(chg_hash)
                           → sig_der (71-73 bytes)

                        ⑨ 读取 YubiKey 公钥:          ← 读取 Slot 9a 证书
                           ops->get_pubkey()
                           → pubkey_der (~91 bytes)

                        ⑩ OpenSSL 验签:            ⚠ 在 CA 侧（REE 不可信）
                           ECDSA_do_verify(chg_hash,      ← 攻击者替换 CA 可跳过此步
                               sig_der, pubkey_der)
                           ✓ 签名有效

                        ⑪ ─────CMD_SO_UNLOCK_CONFIRM──▶   param: <空> ⚠
                                                                       ⑫ 检查 g_so_challenge_valid ✓
                                                                         ⚠ 不验白名单
                                                                         ⚠ 不验签名
                                                                         ⚠ 不验公钥
                                                                         只要 PIN 正确+CA说OK就解锁
                                                                       ⑬ UNLOCKED ← 攻击可达！
                                                                          写保护解除
```

### 2.2 各步骤详解

| 步骤 | 位置 | YubiKey 操作 | 输入 | 输出 | 安全作用 |
|:--:|------|------|------|------|------|
| ① | TBox USB | 插入 | — | — | 物理存在证明 |
| ⑦ | CA (REE) | 无（CA 自己算） | `challenge[32]` | `chg_hash[32]` | 防重放：challenge 是一次性的 |
| ⑧ | CA→YubiKey | `PIV SIGN 9a`（ECDSA P-256） | `chg_hash[32]` | `sig_der` (71-73 B) | **核心**：证明持有对应私钥 |
| ⑨ | CA→YubiKey | `PIV GET CERT 9a` | — | `pubkey_der` (~91 B) | 识别"是哪把 YubiKey" |
| ⑩ | CA (REE) | OpenSSL ECDSA 验签 | `pubkey_der` + `chg_hash` + `sig_der` | pass/fail | 证明签名有效 |

### 2.3 ECDSA 签名原理（设计意图 vs 当前实现）

**设计意图**——白名单匹配应在 TA 内完成，形成三道防线：

```
YubiKey 内部:
  ┌─────────────────────────┐
  │ PIV Slot 9a              │
  │   ECDSA P-256 私钥 (d)   │  ← 永不离开 YubiKey 硬件
  │   公钥 Q = d × G         │  ← 可通过 PIV 命令读取
  └─────────────────────────┘

三道防线（设计目标）:
  ┌──────────────────────────────────────────────────────────────┐
  │ 防线 1: SO-PIN 验证  (TA 内, 已实现 ✓)                      │
  │   输入: SO-PIN                                              │
  │   检查: SHA-256(PIN) == 存储的 PIN hash                     │
  │                                                             │
  │ 防线 2: ECDSA 签名验证  (CA 内 OpenSSL, 已实现 ✓)           │
  │   输入: challenge + sig_der + pubkey_der                    │
  │   检查: ECDSA_Verify(chg_hash, sig, Q)                      │
  │   含义: "这把 YubiKey 确实持有私钥 d"                       │
  │                                                             │
  │ 防线 3: 公钥白名单匹配  (TA 内, ⚠ 未实现)                  │
  │   输入: pubkey_der                                          │
  │   检查: SHA-256(Q) ∈ 白名单 ?                               │
  │   含义: "这把 YubiKey 是经过授权的"                          │
  └──────────────────────────────────────────────────────────────┘
```

**防线 3 缺失的后果**——攻击者替换 CA 后可以完全绕过 YubiKey：

```
攻击路径（攻击者替换了 CA 二进制）:
  ┌─────────────────────────────────────────────────────────────┐
  │ 攻击者的假 CA                     TA (不可篡改)              │
  │                                                             │
  │ ① CMD_SO_UNLOCK_REQ(SO-PIN)                                 │
  │    ─────────────────────────▶  验证 SO-PIN ✓               │
  │                               返回 challenge[32]            │
  │                                                             │
  │ ② (什么都不做, 不调 YubiKey,                                │
  │     不签名, 不验签, 不查白名单)                             │
  │                                                             │
  │ ③ CMD_SO_UNLOCK_CONFIRM()                                   │
  │    ─────────────────────────▶  检查 g_so_challenge_valid ✓  │
  │                               ⚠ 不检查白名单!               │
  │                               ⚠ 不检查签名!                 │
  │                               → UNLOCKED ←                  │
  └─────────────────────────────────────────────────────────────┘
```

**关键问题**：TA 在步骤③只检查了"`CMD_SO_UNLOCK_REQ` 是否被成功调用过"（即 SO-PIN 是否正确），完全没有检查"YubiKey 是否在白名单中"。

CA 侧的 ECDSA 验签（防线 2）是攻击者可以**完全跳过的**——攻击者替换了 CA 二进制，直接跳过验签步骤，调用 `CMD_SO_UNLOCK_CONFIRM`。

**为什么不把防线 2（ECDSA 验签）也放在 TA 内**：OP-TEE 3.2 不支持 ECDSA transient 对象，调用相关 API 直接 TA panic（详见 [24-so-pin-yubikey-unlock.md](24-so-pin-yubikey-unlock.md) 调试记录）。

**防线 3 不需要 ECDSA**——只需 SHA-256 + memcmp，OP-TEE 3.2 完全支持。当前未实现，见 §3 修复方案。

---

## 3. 当前实现的缺口

### 3.1 缺口：`CMD_SO_UNLOCK_CONFIRM` 不检查白名单

当前 `so_unlock_confirm()` 的实现（`ta/so_pin_mgr.c`）：

```c
void so_unlock_confirm(void)
{
    so_reset_consecutive();
    g_so_state = SO_STATE_UNLOCKED;
    // ... 持久化 ...
    DMSG("SO unlock confirmed (CA verified ECDSA), TA UNLOCKED");
}
```

**问题**：这个函数**不验证任何东西**。它只检查了 `g_so_challenge_valid`（即 `CMD_SO_UNLOCK_REQ` 是否被调用过），没有检查：
- 出示的 YubiKey 公钥是否在白名单中
- 签名是否真的有效

CA 做了 ECDSA 验签，但 CA 在不可信的 REE 侧——CA 可以被攻击者替换或篡改。

### 3.2 为什么当初这样设计

OP-TEE 3.2 的 `TEE_AllocateTransientObject(TEE_TYPE_ECDSA_*)` 会导致 TA panic（[24-so-pin-yubikey-unlock.md](24-so-pin-yubikey-unlock.md) 已详细记录调试过程），TA **无法**执行 ECDSA 验签。因此验签移到了 CA 侧。

但即使 CA 验签了，TA 也应该**至少检查**出示的公钥哈希是否在其安全存储的白名单中。这个检查不需要 ECDSA——只需要 SHA-256 + memcmp。

### 3.3 伪修复（为什么"白名单匹配"单独不够）

一个自然的想法是给 `CMD_SO_UNLOCK_CONFIRM` 增加 `pubkey_der` 参数，TA 内部计算 `SHA-256(pubkey_der)` 后与白名单比对。

**这个修复无效**。原因：

```
攻击者不需要 YubiKey，只需要两样东西:
  - SO-PIN（安全官员知道）
  - pubkey_der（manifest.bin 明文中有公钥哈希，可从任意渠道获取公钥本身）

攻击路径（即使加了白名单匹配）:
  ① CMD_SO_UNLOCK_REQ(SO-PIN) → challenge ✓
  ② CMD_SO_UNLOCK_CONFIRM(pubkey_der_known)
       TA: SHA-256(pubkey_der) = 白名单[0] ✓
       → UNLOCKED

manifest.bin 不涉密（doc 27 §5.1），工控机上明文存放，
任何经手人都能拿到里面每条记录对应的 pubkey_der。
公钥本身就是公开信息——YubiKey 插到任意机器上都能读。
```

**白名单匹配是必要条件，但不是充分条件**。必须同时验证"出示者持有对应私钥"（= ECDSA 签名验证）。这两个检查**必须在同一个信任域内完成**才能形成闭合——要么都在 TA（OP-TEE ECDSA 不可用），要么都在 CA（CA 可被替换）。

### 3.4 诚实结论：当前 OP-TEE 3.2 下能做到的最好安全

OP-TEE 3.2 不支持 ECDSA，TA 无法独立完成"签名验证 + 白名单匹配"的原子检查。**两者必须在同一信任域才能闭合**——但 TA 做不了 ECDSA，CA 不可信。

在此约束下，实际的安全等级只有两层：

| 防线 | 位置 | TA 能验证 | 攻击者绕过的条件 |
|------|------|:--:|------|
| SO-PIN | TA 内 | ✓ SHA-256(PIN) | 知道 SO-PIN |
| YubiKey 签名 + 白名单 | CA 内 (不可信) | ✗ | 替换 CA 二进制 / 知道 pubkey_der |

**当前实现的真实安全含义**：

- **防远程攻击者**（不知道 SO-PIN，没有 YubiKey）：✓ 有效——SO-PIN 是 TA 内验证的，远程攻击者绕不过
- **防物理接触 TBox 的攻击者**（替换 CA 二进制）：**✗ 无效**——攻击者替换 CA 后可以跳过所有 YubiKey 相关逻辑，直接 call `CMD_SO_UNLOCK_CONFIRM`
- **防安全官员恶意使用未授权 YubiKey**：**✗ 无法区分**——TA 看不到 YubiKey，不知道 CA 是否真的调了 YubiKey

**要补上这个缺口，唯一途径是 OP-TEE 升级**——启用 `CFG_CRYPTO_ECDSA=y` 后，TA 可以在 `so_unlock_confirm()` 中同时完成：
1. `crypto_ecdsa_verify(pubkey_der, challenge, sig)` — 验证签名（证明持有私钥）
2. `SHA-256(pubkey_der) == 白名单[i]` — 验证公钥已授权（在白名单中）

两个检查在 TA 同一个函数内完成，中间没有 CA 可以切断的环节。

**短期内**（OP-TEE 升级前）的缓解：
1. Secure Boot 保护 CA 二进制不被替换（BootROM → SPL → OP-TEE → Linux → CA 签名验证）
2. `CMD_SO_UNLOCK_CONFIRM` 至少加上 `pubkey_der` 参数和简易白名单匹配（§3.3 的代码）——即使不能防攻击者替换 CA，至少能防**配置错误**（产线灌装了错误的公钥时能发现）

---

## 4. 实际安全模型（坦诚版）

### 4.1 当前有效的防线

```
┌────────────────────────────────────────────────────────────┐
│                                                            │
│  防线 1: SO-PIN 验证（TA 内）          ← TA 独立执行 ✓    │
│  ──────────────────────────                                │
│  防止: 不知道 SO-PIN 的人解锁                               │
│  被攻破: SO-PIN 泄露                                       │
│                                                            │
│  ════════════════ 信任边界 ════════════════                │
│  以下是 CA (REE) 侧，攻击者可替换 CA 全部绕过:               │
│                                                            │
│  防线 2: YubiKey 签名 + 白名单（CA 内）  ← TA 看不到 ✗    │
│  ──────────────────────────────────                        │
│  设计意图: 防止没有 YubiKey 的人解锁                         │
│  实际效果: 防君子不防小人（CA 替换即失效）                   │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### 4.2 攻击场景

| 攻击者 | 能力 | SO-PIN | 是否需要 YubiKey | 结果 |
|------|------|:--:|:--:|------|
| 远程攻击者 | 网络访问 TBox | ✗ | — | **拒绝**——SO-PIN 在 TA 内验证 |
| 远程攻击者 | 知道 SO-PIN（社工/泄露） | ✓ | 不需要（跳过 CA 的 YubiKey 逻辑） | **可能解锁**——需先替换 CA |
| 工控机操作员 | 灌装时接触到 manifest.bin | ✓（知道 SO-PIN） | 不需要 | **可能解锁**——知道 pubkey_der + SO-PIN，CTRL+C 替换 CA |
| 安全官员 | 持有授权 YubiKey + SO-PIN | ✓ | 有，且在白名单中 | **正常解锁** ✓ |
| ~~安全官员~~ | ~~尝试用未授权 YubiKey~~ | ~~✓~~ | ~~有，但不在白名单~~ | **无法阻止**——CA 做 ECDSA 验签，但攻击者可替换 CA |

### 4.3 与理想模型的差距

```
当前 OP-TEE 3.2                    OP-TEE 升级后
─────────────                      ────────────
SO-PIN → TA 验证 ✓                  SO-PIN → TA 验证 ✓
YubiKey → CA 验证 (可绕过) ✗        YubiKey → TA 验证 ✓
                                     (ECDSA + 白名单原子操作)
```

> **结论**：当前方案在前提"CA 二进制不可篡改"下是安全的。如果攻击者能替换 CA，YubiKey 的防护可被完全绕过。需 OP-TEE ECDSA 支持才能在 TA 内闭合整个验证环。

---

## 5. 改动计划

### 5.1 临时缓解（OP-TEE 升级前）

这些改动**不能防 CA 替换攻击**（见 §3.3 分析），但至少能防配置错误和误操作。

| 层 | 文件 | 改动 | 效果 |
|------|------|:--:|------|
| **TA** | `tbox_keystore_ta.h` | 小 | `CMD_SO_UNLOCK_CONFIRM`(18) param[0]=MEMREF_INPUT(pubkey_der) |
| **TA** | `so_pin_mgr.c` | 中 | `so_unlock_confirm()` SHA-256 + 白名单 memcmp |
| **TA** | `entry.c` | 小 | `cmd_so_unlock_confirm` 传 pubkey_der |
| **CA** | `keystore_client.c` | 小 | `--so-unlock` 增加 pubkey_der 参数 |

**不改动**：`crypto_ops.c` / `dongle/` / 可信服务器 / manifest 格式。

### 5.2 真正修复（OP-TEE 升级后，版本 ≥ XXX）

当 OP-TEE 编译了 `CFG_CRYPTO_ECDSA=y` 且 ECDSA transient object 不再 panic 时：

| 改动 | 内容 |
|------|------|
| 恢复 `crypto_ecdsa_verify()` | 代码已在 `crypto_ops.c` 中（当前为死代码） |
| 合并防线 2+3 | `so_unlock_confirm(pubkey_der, sig_der, challenge)` 内同时完成 ECDSA 验签 + 白名单匹配，形成原子检查 |
| 废弃 `CMD_SO_UNLOCK_VERIFY`(15) | 不再使用 indirect confirm 流程 |

### 5.3 不改动（永远不改）

这些在 OP-TEE 任何版本下都无法由 TA 验证，必须依赖 CA（REE）或物理安全：

- YubiKey 是否真的插在 TBox 上（可被 USB 模拟器欺骗）
- YubiKey 序列号是否真实（可被 USB 重放攻击）
- 安全官员是否是本人（生物特征应由物理警卫验证）

---

## 6. 与 doc 27 的衔接

```
doc 27 (§5 产线灌装):                    本文档 (§2 SO 解锁):
───────────────                         ──────────────
可信服务器 签名 manifest                安全官员 带 YubiKey 到 TBox
    │                                       │
    ▼                                       ▼
TA 白名单                                TA 白名单
    │  {hash_A, hash_B}                      │  {hash_A, hash_B}
    │                                       │
    │                              ┌────────┴────────┐
    │                              │ SHA-256(pubkey) │
    │                              │   == hash_A ?   │
    │                              └────────┬────────┘
    │                                   ✓   │
    │                              ┌────────┴────────┐
    │                              │ YubiKey 签名     │
    │                              │ ECDSA 验签通过   │
    │                              └────────┬────────┘
    │                                       │
    ▼                                       ▼
  灌装完成                                SO 解锁完成
                                          写保护解除
```

灌装阶段 doc 27 已回答："谁来决定哪些 YubiKey 合法"（可信服务器签名）。

本文档回答："解锁时如何执行这个决定"（TA 白名单匹配 + CA ECDSA 验签 + SO-PIN 三重防线）。

---

> 相关文档：
> - [27-yubikey-provisioning-trusted-server.md](27-yubikey-provisioning-trusted-server.md) — 可信服务器灌装方案（白名单签名 + 工厂部署）
> - [24-so-pin-yubikey-unlock.md](24-so-pin-yubikey-unlock.md) — SO-PIN 双因子解锁协议设计
> - [25-yubikey-guide.md](25-yubikey-guide.md) — YubiKey 选型与使用指南
> - [26-sgx-provisioning-attestation.md](26-sgx-provisioning-attestation.md) — SGX 远程证明方案（各级信任模型对比）
