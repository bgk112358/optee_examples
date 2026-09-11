# 30 — TA 不支持 ECC P-256 验签的调试记录

> **目标**：SO-PIN 双因子解锁中，用 YubiKey PIV 对 challenge 签名，TA 在安全世界（TEE）内完成验签 + 白名单匹配。
>
> **环境**：OP-TEE 3.2（产品版本）+ YubiKey 4 PIV + ARM aarch64；开发验证环境为 QEMU（OP-TEE 4.0，仅用于功能验证）。
>
> **结论**：OP-TEE 3.2 不支持 ECDSA transient object，TA 无法在安全世界内做 ECDSA 验签 → 改用 RSA-2048（OP-TEE 3.2 原生支持）。

---

## 一、问题概述

SO-PIN 解锁方案最初设计为「YubiKey 对 challenge 做 ECDSA P-256 签名，TA 在安全世界内验签」。选 ECDSA 的理由很自然：YubiKey PIV 的 Slot 9a 出厂就预置了 ECDSA P-256 密钥，零配置即可用。

但在 TA 侧实现 `crypto_ecdsa_verify()` 时，调试过程先后遇到两个现象：

1. **编译报错**：`TEE_ATTR_ECC_PUBLIC_VALUE` 未声明（OP-TEE 3.2 头文件里没有该属性，只有 `TEE_ATTR_ECC_PUBLIC_VALUE_X / _Y` 分开的坐标属性）。
2. **运行时 panic**：调用 `TEE_AllocateTransientObject(TEE_TYPE_ECDSA_*, ...)` 直接导致 TA panic。

两者指向同一个根因：**OP-TEE 3.2 不支持 ECDSA transient object**。

---

## 二、调试过程（时间线）

### 2.1 初始设计：ECDSA P-256（约 2026-07-30）

按 [24-so-pin-yubikey-unlock.md](24-so-pin-yubikey-unlock.md) 的设计，TA 侧新增验签函数：

```c
TEE_Result crypto_ecdsa_verify(
    const uint8_t *pubkey_der,  size_t pubkey_der_len,
    const uint8_t *data,        size_t data_len,
    const uint8_t *sig_der,     size_t sig_der_len)
{
    // 1. Import public key from DER
    // 2. Allocate transient ECC key object
    // 3. TEE_AsymmetricVerifyDigest(TEE_ALG_ECDSA_P256, hash, ...)
}
```

### 2.2 编译报错：`TEE_ATTR_ECC_PUBLIC_VALUE` 未声明

实现到「把 YubiKey 公钥 DER 导入 transient object」这一步时，编译报错：

```
crypto_ops.c:227:41: error: 'TEE_ATTR_ECC_PUBLIC_VALUE' undeclared (first use in this function);
  did you mean 'TEE_ATTR_ECC_PUBLIC_VALUE_X'?
```

原因：OP-TEE 3.2 的 GP TEE API 头文件里，没有「整值导入 ECC 公钥」的属性 `TEE_ATTR_ECC_PUBLIC_VALUE`，只有分开的坐标 `TEE_ATTR_ECC_PUBLIC_VALUE_X / _Y`——这已经暗示 3.2 对 ECDSA 的支持不完整。

### 2.3 运行时 panic：ECDSA transient object 不支持

即便绕过编译错误，真正执行到分配 ECC 临时对象时也会 panic：

```c
res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, 256, &ec_obj);  // → TA panic
```

**这是决定性的现象**：OP-TEE 3.2 的 `TEE_AllocateTransientObject(TEE_TYPE_ECDSA_*)` 会直接导致 TA panic，TA 侧无法持有 ECDSA 密钥对象、也就无法执行 `TEE_AsymmetricVerifyDigest(TEE_ALG_ECDSA_P256, ...)`。

> 参考 [28-yubikey-full-lifecycle.md](28-yubikey-full-lifecycle.md) §3.2：
> "OP-TEE 3.2 的 `TEE_AllocateTransientObject(TEE_TYPE_ECDSA_*)` 会导致 TA panic"。

### 2.4 临时妥协：验签移到 CA 侧 → 留下安全缺口

因为 TA 做不了 ECDSA 验签，只能把验签挪到 **CA 侧（REE，OpenSSL `ECDSA_do_verify`）**。结果 `CMD_SO_UNLOCK_CONFIRM`(18) 变成**无参数**，TA 只检查 `g_so_challenge_valid`（即 `CMD_SO_UNLOCK_REQ` 是否调用过），**不验签名、不查白名单**：

```c
void so_unlock_confirm(void)
{
    so_reset_consecutive();
    g_so_state = SO_STATE_UNLOCKED;
    DMSG("SO unlock confirmed (CA verified ECDSA), TA UNLOCKED");
}
```

由此产生一个明确的安全缺口：CA 运行在不可信的 REE 侧，攻击者替换 CA 二进制后即可**完全跳过 ECDSA 验签**，直接调用 `CMD_SO_UNLOCK_CONFIRM` 解锁。详细分析见 [28-yubikey-full-lifecycle.md](28-yubikey-full-lifecycle.md) §2.3 / §3。

### 2.5 最终方案：改用 RSA-2048（约 2026-08-05）

关键洞察：**OP-TEE 3.2 原生支持 RSA-2048 验签**（`crypto_rsa_verify` 是项目里已实现的算法）。于是：

- YubiKey Slot 9a 删除出厂预置的 ECDSA 密钥，手动生成 RSA-2048：
  `ykman piv generate-key 9a -a RSA2048`
- TA 内 `so_unlock_confirm(pubkey_der, sig_der)` **原子完成**「RSA 验签 + 白名单匹配」，闭合缺口。

完整方案见 [29-rsa-yubikey-provisioning.md](29-rsa-yubikey-provisioning.md)。

---

## 三、根本原因

| 项 | 说明 |
|---|---|
| 直接原因 | OP-TEE 3.2 不支持 ECDSA transient object（`TEE_AllocateTransientObject(TEE_TYPE_ECDSA_*)` → TA panic） |
| 版本限制 | 3.2 未启用 ECDSA 相关能力；需升级到支持 ECDSA transient object 的版本（`CFG_CRYPTO_ECDSA=y`） |
| 深层原因 | 验签 + 白名单必须在**同一信任域**内原子完成才能闭合；TA 做不了 ECDSA → 只能挪到不可信的 CA 侧 → 产生缺口 |

---

## 四、方案对比

| 维度 | ECDSA P-256 方案 | RSA-2048 方案（最终采用） |
|------|------|------|
| YubiKey 密钥 | 出厂预置 P-256 | 手动生成 RSA-2048 |
| YubiKey 初始化 | 零配置 | 需 `generate-key -a RSA2048`（约 30 秒） |
| TA 验签 | **不支持（3.2 panic）** | **支持（`crypto_rsa_verify` 已实现）** |
| 验签 + 白名单匹配 | 分开（CA 验 + TA 比）→ 可被切断 | **原子操作**（TA 内同时完成）→ 不可切断 |
| `CMD_SO_UNLOCK_CONFIRM` 参数 | 空（TA 盲信 CA） | `pubkey_der` + `sig_der`（TA 独立验证） |

---

## 五、遗留项

1. **死代码**：`ta/crypto_ops.c:144` 的 `crypto_ecdsa_verify()` 已编译进 TA（符号表可见），但**无任何调用点**（entry.c 的 CMD 分发未接入），处于"编译进但永不执行"的死代码状态。一旦调用就会触发 3.2 的 ECDSA transient object panic。
2. **升级后恢复**：当 OP-TEE 升级到支持 ECDSA transient object 的版本（启用 `CFG_CRYPTO_ECDSA=y`）后，可恢复 `CMD_SO_UNLOCK_VERIFY` 流程，把 ECDSA 验签移回 TA 侧，详见 [25-yubikey-guide.md](25-yubikey-guide.md) §8。

---

## 六、相关文档

| 文档 | 关系 |
|------|------|
| [24-so-pin-yubikey-unlock.md](24-so-pin-yubikey-unlock.md) | 最初的 ECDSA P-256 设计方案（含 `crypto_ecdsa_verify` 设计稿） |
| [28-yubikey-full-lifecycle.md](28-yubikey-full-lifecycle.md) | 调试结果 + 安全缺口坦诚分析（§2.3 / §3） |
| [29-rsa-yubikey-provisioning.md](29-rsa-yubikey-provisioning.md) | 最终方案：RSA-2048 完整设计 |
| [25-yubikey-guide.md](25-yubikey-guide.md) | YubiKey 选型与操作、§8 未来恢复 ECDSA 的展望 |
