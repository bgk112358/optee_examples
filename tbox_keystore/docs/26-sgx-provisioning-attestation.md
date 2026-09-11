# 26 — SGX 远程证明在产线安全中的应用方案

## 摘要

本文档梳理了将 Intel SGX 远程证明引入 TBox 产线灌装流程的**四个递进层次**，硬件信任根从工控机（方案 A）完整迁移到云端 enclave（方案 D），在第三个方案开始安全官员也只傀儡不再可信，每次升级解决上一层次的安全漏洞。

---

## 1. 背景与现状

### 1.1 当前灌装流程（无 SGX）

```
安全官员（可信）               工控机（需信任）              TBox
─────────────               ────────────              ────
① 插入 YubiKey   ──USB──▶  ② 读取公钥                   │
                            ③ SHA-256(pubkey)          │
                            ④ 生成 SO-PIN               │
                            ⑤ 生成 Provisioning PIN      │
                            ⑥ ──串口──▶ 灌装到 TA        │
                            ⑦ ──lock──▶                │
```

**问题**：步骤 ②-⑥ 的安全性完全取决于工控机是否可信。工控机是第三方维护的普通 Linux PC，一旦被植入恶意软件，公钥哈希可被替换、SO-PIN 可被窃取。

### 1.2 信任假设的逐级弱化

本文按"信任收缩"的递进关系组织：

```
方案 A: SGX 在工控机本地 — 给工控机加一个硬件信任根
   │  问题: 工控机是第三方的，SGX 部署不进去
   ▼
方案 B: SO 离线签名 — 工控机不可信，签名权交给安全官员
   │  问题: 安全官员本身不可信怎么办？
   ▼
方案 C: 云端 SGX 签署 — 安全官员变傀儡，签名权收归云端 enclave
   │  前提: YubiKey 出厂设备证书链
   │  问题: 云端管理员有物理/root 访问权
   │  当前可达的最高安全层级
```

---

## 2. 方案 A：SGX 在工控机本地

### 2.1 架构

SGX enclave 部署在产线工控机上，提供以下安全能力：

```
┌──────────────────────────────────────────┐
│ 工控机 (x86, Intel SGX)                    │
│                                          │
│  ┌──────────────────────────────────┐    │
│  │ SGX Enclave                       │    │
│  │                                   │    │
│  │  ① SO-PIN 生成                    │    │
│  │     硬件 RDRAND + 密封公钥加密     │    │
│  │     明文永不离开 enclave           │    │
│  │                                   │    │
│  │  ② YubiKey 公钥注册               │    │
│  │     enclave 直连 USB 读取公钥      │    │
│  │     与远程证明 Quote 绑定签名      │    │
│  │                                   │    │
│  │  ③ 审计日志                       │    │
│  │     日志条目 enclave 签名 + 时间戳  │    │
│  │     只追加链，不可篡改             │    │
│  │                                   │    │
│  │  ④ 跨域 TEE 链                    │    │
│  │     SGX Quote → TA 安全存储记录    │    │
│  └──────────────────────────────────┘    │
│                                          │
│  ┌────────────────┐  ┌────────────────┐  │
│  │ CA (REE)        │  │ TBox           │  │
│  │ 灌装逻辑         │  │ OP-TEE + TA    │  │
│  └────────────────┘  └────────────────┘  │
└──────────────────────────────────────────┘
```

### 2.2 切入点

| 优先级 | 切入点 | 说明 |
|:--:|------|------|
| **P1** | SO-PIN 安全生成 | enclave 内硬件随机数生成 PIN → 直接以安全官员公钥加密 → 明文永不泄露 |
| P1 | 审计日志防篡改 | enclave 签名日志链 → 满足 ISO 21434 审计追溯 |
| P2 | YubiKey 公钥防调包 | enclave 内 USB 直通 YubiKey → Hash 绑定 Quote |
| P3 | 跨域 TEE 信任链 | SGX Quote + OP-TEE TA → 双向设备身份证明 |

### 2.3 现实约束

| 约束 | 影响 |
|------|------|
| **SGX 需要 Intel CPU**（Core 6th gen+） | 工控机必须符合硬件要求，成本 ~$200-400 额外 |
| **YubiKey USB 在 enclave 内直通不官方支持** | 需 split-driver 模式绕过（RE 侧驱动 + enclave 内逻辑） |
| **enclave 开发门槛** | 需 SGX SDK + EDL 接口定义 |
| **工控机为第三方维护** | **物理部署权限在自己手里可以，反之不行** |

### 2.4 适用场景

- **OEM 自建产线**，工控机由 OEM 自己采购和维护
- 不适用于第三方代工厂维护的工控机

### 2.5 局限：为什么需要后续方案

当工控机不属于 OEM、由第三方代工厂维护时，SGX 的**远程证明机制仍然可用**——但攻击面转移到 enclave 外部：
- 恶意管理员可替换非 enclave 内运行的 CA 代码
- 物理攻击（DRAM 冷冻、总线探针）

**结论**：工控机上的 SGX 能防软件攻击，不能防物理攻击。当工控机完全不可信（他人维护）时，信任根必须移出工控机。

---

## 3. 方案 B：SO 离线签名（工控机不可信）

### 3.1 核心思路

信任根从工控机移交给**安全官员的离线 RSA 私钥**。工控机降级为数据搬运工。

```
安全官员（离线，安全笔记本）              工控机（不可信）
──────────────────────────              ──────────────
① 插主 YubiKey                             │
   ykman piv export-cert 9a                │
   → SHA-256(pubkey) → hash_0              │
                                           │
② 插备用 YubiKey                           │
   → SHA-256(pubkey) → hash_1              │
                                           │
③ 构建清单:                                │
   manifest = {                            │
     hash_0, hash_1,                       │
     serials, timestamp,                   │
     版本号, 有效期                          │
   }                                       │
                                           │
④ RSA 私钥签名:                            │
   → manifest.sig                          │
                                           │
⑤ 交付工厂 (U盘/邮件): ───▶   ⑥ tbox_keystore
   manifest.bin                     --provision-dongle-manifest
   manifest.sig                     manifest.bin manifest.sig
                                         │
                                         ▼
                                    ┌──────────────┐
                                    │ TA            │
                                    │ RSA_Verify(   │
                                    │   manifest,   │
                                    │   sig,        │
                                    │   SO_pubkey   │← 硬编码在 TA 内
                                    │ )             │
                                    │ → 原子替换白名单│
                                    └──────────────┘
```

### 3.2 安全保证链

```
SO 私钥 (安全官员持有)
   │
   ▼
 签名清单 (工控机传不了假数据——没有私钥签不出有效签名)
   │
   ▼
TA 硬编码 SO 公钥 (编译时固定, TA 签名保护)
   │
   ▼
RSA_Verify(manifest, sig, SO_pubkey)
   │
   ├─ ✓ 通过 → 白名单写入安全存储
   └─ ✗ 失败 → 拒绝, 工控机被污染
```

### 3.3 需要改动

| 层 | 改动 | 说明 |
|------|------|------|
| TA | 硬编码 SO RSA 公钥 | ~300 字节 DER，编译时常量 |
| TA | 新增 `CMD_PROVISION_DONGLE_MANIFEST` (19) | param[0]=memref(清单), param[1]=memref(签名) |
| TA | `so_provision_dongle_manifest()` | RSA-2048 SHA-256 验签 + 原子替换白名单 |
| CA | 新增 `--provision-dongle-manifest` | 读取清单文件 + 签名文件，打包传给 TA |
| SO | 离线工具脚本 | `gen-manifest.sh` + `sign-manifest.sh` |
| 工控机 | **零改动** | |

### 3.4 安全边界

| 攻击 | 是否可防 |
|------|:--:|
| 工控机替换白名单公钥哈希 | ✓ — 被 TA RSA 验签拦截 |
| 工控机注入额外非法 YubiKey | ✓ — 同上 |
| 工控机拒绝服务（不发命令） | ✗ — 无解（但无安全影响） |
| 安全官员**主动**签名恶意清单 | ✗ **此方案不防** |
| 安全官员私钥泄露 | ✗ **此方案不防** |

---

## 4. 方案 C：云端 SGX 签署（安全官员也不可信）

### 4.1 核心思路

SO 离线签名解决了工控机不可信，但**安全官员本身不可信**时（内部威胁、被胁迫、私钥泄露），方案 B 全线崩溃。

方案 C 将签名权收归**云端 SGX enclave**——安全官员降级为纯粹的物理载体（傀儡）。

```
┌──────────┐       ┌──────────────────────┐       ┌──────────┐
│ 安全官员  │       │   云端 SGX Enclave     │       │ 工控机    │
│ (不可信)  │       │   (唯一信任根)          │       │ (不可信)  │
│          │       │                       │       │          │
│ ① 插YubiKey │    │                       │       │          │
│    读设备证书 │   │                       │       │          │
│    读序列号  │   │                       │       │          │
│    (傀儡操作) │   │                       │       │          │
│          │       │                       │       │          │
│ ② 上传:   │──────▶│ ③ Enclave 验证:       │       │          │
│   设备证书   │     │  - Yubico CA 证书链     │       │          │
│   序列号    │     │  - 设备证书 = 真YubiKey  │       │          │
│          │       │  - 序列号 ∈ 授权清单     │       │          │
│          │       │                       │       │          │
│          │       │ ④ Enclave 内部私钥     │       │          │
│          │       │   RSA 签名白名单        │◀──────│ ⑤ 下载    │
│          │       │                       │       │   签名清单 │
│          │       │                       │ ⑥ 灌装 │          │
│          │       │                       │──────▶│          │
│          │       │                       │       │          │
└──────────┘       └──────────────────────┘       └─────┬────┘
                                                        │
                                           ┌────────────▼────────┐
                                           │  TBox TA             │
                                           │  RSA_Verify(         │
                                           │    manifest,         │
                                           │    sig,              │
                                           │    SGX_pubkey ← 硬编码 │
                                           │  )                   │
                                           │  → 白名单写入/替换     │
                                           └─────────────────────┘
```

### 4.2 关键机制：YubiKey 设备证书链

YubiKey 出厂预置 **Yubico 签发的 X.509 Attestation Certificate**：

| 字段 | 说明 |
|------|------|
| Subject | `CN=Yubico PIV Attestation <serial>` |
| Public Key | Slot f9 (Attestation) 的 ECDSA P-256 公钥 |
| Serial Number | YubiKey 唯一硬件序列号 |
| Issuer | `CN=Yubico PIV Attestation CA` |

云端 SGX enclave 内部验证链：

```
Yubico Root CA (硬编码在 enclave 内)
      │
      ▼ 验证签名
Yubico PIV Attestation CA
      │
      ▼ 验证签名
设备证书 (序列号 + 公钥)
      │
      ▼ 检查序列号 ∈ 授权设备清单
SHA-256(pubkey) → 白名单条目
```

**安全官员无法伪造**——没有 Yubico 的 CA 私钥，签不出合法的设备证书。

### 4.3 安全保证链

```
云端 SGX Enclave (唯一信任根)
   │  enclave 私钥仅存在于 enclave 内,   sealed 到 CPU 硬件
   │  MRENCLAVE 可远程验证
   │
   ▼
签名白名单 (安全官员、工控机、云端管理员都无法伪造)
   │  没有 Yubico CA 私钥 → 设备证书无法伪造
   │  没有 enclave 私钥 → 清单签名无法伪造
   │
   ▼
TA 硬编码 SGX 公钥 (编译时固定, TA 签名保护)
   │
   ▼
RSA_Verify(manifest, sig, SGX_pubkey)
   │
   ├─ ✓ 通过 → 白名单写入安全存储
   └─ ✗ 失败 → 拒绝
```

### 4.4 信任层次总览

```
方案 C 架构
═══════════════════════════════════════
  云端 SGX enclave ................ 唯一信任根
           │                          (远程证明可验证)
           │ 签名白名单
           ▼
  ┌────────────────────────────────┐
  │  TA (ARM TrustZone) .......... 第二层信任 │
  │    硬编码 SGX 公钥              │  (不可篡改) │
  │    RSA 验签                    │           │
  └────────────────────────────────┘           │
           │                                   │
  ─ ─ ─ ─ ┼ ─ ─ 信任边界 ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─
           │                                   │
  ┌────────────────────────────────┐           │
  │  工控机 (REE) ................ 不可信     │
  │    只搬运已签名的清单            │           │
  └────────────────────────────────┘           │
           │                                   │
  ┌────────────────────────────────┐           │
  │  安全官员 .................... 傀儡/不可信 │
  │    只物理插拔 YubiKey           │           │
  └────────────────────────────────┘           │
           │                                   │
  ┌────────────────────────────────┐           │
  │  云端管理员 ................... 不可信     │
  │    看不到 enclave 私钥           │           │
  └────────────────────────────────┘           │
═══════════════════════════════════════════════
```

### 4.5 安全边界分析

| 攻击者 | 能做什么 | 为什么失败 |
|------|------|------|
| 安全官员 | 用自己的私钥 YubiKey 替换 | 云端 SGX 验证 Yubico 设备证书链 + 序列号白名单 |
| 安全官员 | 购买新 YubiKey 混入 | 序列号不在云端授权清单中 |
| 安全官员 | 凭空编造公钥哈希 | 没有对应的 Yubico Attestation Certificate |
| 工控机 | 替换清单内容 | 清单有 enclave 签名，TA 验签失败 |
| 工控机 | 重放旧清单 | 清单含时间戳 + 版本号，TA 检查 freshness |
| 云端管理员 | 修改 enclave 逻辑 | SGX sealing 保护私钥，MRENCLAVE 改变 = 私钥丢失 |
| 云端管理员 | 物理攻击服务器 | 需破 SGX 硬件防护（成本极高） |

### 4.6 需要改动

| 层 | 改动 | 说明 |
|------|------|------|
| **云端** | SGX enclave 程序 | Yubico CA 验证 + 白名单策略 + RSA-2048 签名；REST API 对外暴露 |
| **云端** | 授权设备清单 | YubiKey 序列号列表，由 OEM 管理层维护 |
| **TA** | 硬编码 SGX 公钥 | ~300 字节 DER |
| **TA** | 新增 `CMD_CLOUD_PROVISION` (19) | param[0]=memref(清单), param[1]=memref(签名) |
| **TA** | `so_provision_dongle_cloud()` | RSA-2048 SHA-256 验签 + 清单版本号/time window 检查 + 原子替换 |
| **CA** | `--provision-dongle-cloud <URL>` | 从云端下载签名清单 + 传给 TA |
| **云端** | REST API: `GET /manifest/latest` | 返回最新的签名白名单 |
| **工控机** | **零改动** | |
| **安全官员** | 工具变为纯读证书工具 | `ykman piv export-certificate f9 - > device.cer` |

### 4.7 序列号授权清单管理

这是整个信任模型的核心——"谁能注册 YubiKey"的答案。

```
授权清单更新流程:
─────────────────
OEM 管理层
  │
  │  决定: "序列号 12345678 授权为主 SO YubiKey"
  │         "序列号 87654321 授权为备用 YubiKey"
  │
  ▼
云端管理门户
  │
  │  调用 SGX REST API:  PUT /authorized-devices
  │  (需 OEM 管理层 TLS 客户端证书)
  │
  ▼
SGX Enclave
  │
  │  1. 验证客户端证书
  │  2. 更新内部白名单
  │  3. 记录审计日志
  │
  ▼
完成
```

安全官员拿到新 YubiKey 后，必须先在云端注册序列号——之后的上传和签名才有效。**注册权和签名权分离**：OEM 管理层决定谁能注册，SGX enclave 执行签名。

### 4.8 开发要点

**云端 SGX Enclave 关键技术点**：

| 技术点 | 实现 |
|------|------|
| Yubico Root CA 存储 | 硬编码在 enclave 源码中，编译进 MRENCLAVE |
| Enclave 密钥管理 | 使用 SGX `EGETKEY` 派生 RSA 密钥对；支持 sealing 持久化 |
| 远程证明 | Intel DCAP (Data Center Attestation Primitives) — 客户可验证 `MRENCLAVE` 匹配已知值 |
| 传输安全 | TLS 终结于 enclave 内（RA-TLS），enclave 持有 TLS 私钥 |
| 服务部署 | Azure Confidential Computing / Alibaba Cloud SGX 实例 / 自建 SGX 服务器 |

**TA 侧关键技术点**：

| 技术点 | 实现 |
|------|------|
| SGX 公钥硬编码 | TA 源码常量数组，编译进 TA 签名 |
| RSA 验签 | 复用 `crypto_rsa_verify()` — OP-TEE 已有 |
| 清单版本号 | 每个清单包含单调递增版本号，TA 拒绝降版本（防重放旧清单） |
| Time window | 清单可选有效期，TA 用 `TEE_GetSystemTime()` 检查 |

### 4.9 与其他方案的关系

| 方案 | SGX 位置 | 工控机信任 | SO 信任 | 适用阶段 |
|------|:--:|:--:|:--:|------|
| A (本地 SGX) | 工控机 | 半信任 | 可信 | OEM 自建产线 |
| B (SO 离线签名) | 无 | 不可信 | 可信 | Tier-1 代工厂 |
| **C (云端 SGX)** | **云** | **不可信** | **不可信** | **最高安全要求** |

三个方案不是互斥的——可以渐进部署：
1. 先上线方案 B（SO 离线签名），立即消除工控机信任依赖
2. 云端 SGX 开发完成后，切换到方案 C，消除安全官员信任依赖

---

## 5. 实施路线图

| 阶段 | 内容 | 周期 |
|------|------|:--:|
| **Phase 1** | 方案 B 落地：TA 硬编码 SO 公钥 + `CMD_PROVISION_DONGLE_MANIFEST` + SO 离线工具 | 2 周 |
| **Phase 2** | 云端 SGX enclave 开发：Yubico CA 验证 + 白名单策略 + RSA 签名 | 6-8 周 |
| **Phase 3** | TA 切换到 SGX 公钥 + `CMD_CLOUD_PROVISION` | 1 周 |
| **Phase 4** | 产线全线切换到方案 C | 2 周 |

---

> 相关文档：
> - [24-so-pin-yubikey-unlock.md](24-so-pin-yubikey-unlock.md) — SO-PIN 双因子解锁方案
> - [25-yubikey-guide.md](25-yubikey-guide.md) — YubiKey 选型与使用指南
> - [07-provisioning-procedure.md](07-provisioning-procedure.md) — 产线灌装详细流程
> - [08-provisioning-security.md](08-provisioning-security.md) — 灌装安全约束
