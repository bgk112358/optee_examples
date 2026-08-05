# 29 — 基于 YubiKey RSA-2048 + 可信服务器的产线灌装与 SO 解锁完整方案

## 摘要

本文档合并并替代：

| 文档 | 内容 | 状态 |
|------|------|:--:|
| [25-yubikey-guide.md](25-yubikey-guide.md) | YubiKey 选型、功能对比、操作指南 | 合并 |
| [27-yubikey-provisioning-trusted-server.md](27-yubikey-provisioning-trusted-server.md) | 可信服务器签名白名单灌装 | 合并 |
| [28-yubikey-full-lifecycle.md](28-yubikey-full-lifecycle.md) | SO 解锁完整闭环（含缺口分析） | 合并 |

**核心决策**：使用 YubiKey PIV RSA-2048 替代 ECDSA P-256。原因是 OP-TEE 3.2 原生支持 RSA-2048 验签 (`crypto_rsa_verify` 已实现），TA 可在安全世界内**同时**完成 RSA 验签 + 白名单匹配，从根本上闭合 ECDSA 方案中"TA 无法验证 YubiKey 签名"的安全缺口。

**安全模型**（一句话）：攻击者即使知道 SO-PIN 且替换了 CA 二进制，若没有持有已在白名单中的 YubiKey，TA 验签 → 失败 → 无法解锁。

---

## 1. 角色与信任模型

| 角色 | 可信度 | 操作 | 说明 |
|------|:--:|------|------|
| **IT 管理员**（可信服务器） | **唯一操作信任根** | 初始化 YubiKey, 读 RSA 公钥, 签名 manifest | 物理隔离服务器, 双人操作, 审计日志 |
| **安全官员** | 不可信 | 携带 YubiKey 到机房/现场, 记忆 SO-PIN | 快递员；不操作任何软件命令 |
| **工控机** | 不可信（第三方） | 下载 manifest, 搬运到 TBox | 不接触任何私钥 |
| **TBox TA**（ARM TrustZone） | 可信 | RSA-2048 验签 + 白名单匹配 → 原子解锁 | OP-TEE 3.2 |
| **TBox CA**（REE Linux） | 不可信 | 中转 challenge 和 RSA 签名 | 攻击者替换后可跳过 YubiKey 签名, 但 TA 验签失败 → 拒绝 |
| **YubiKey 硬件** | 可信 | 持有 RSA-2048 私钥, 执行 RSA 签名 | 私钥不可导出 |

**信任根链**：

```
IT 管理员（可信服务器）
  │
  ▼
YubiKey 初始化（生成 RSA-2048 密钥 → 读取公钥 → 清单签名）
  │
  ▼
TA 硬编码: RSA_pub_server  (验证 manifest 签名)
TA 硬编码: RSA 验签能力     (验证 YubiKey 签名)
TA 安全存储: 白名单          (SHA-256(pubkey) 列表)
  │
  ▼
解锁时: TA 同时验证:
  ① SO-PIN hash 正确
  ② RSA 签名有效 (证明持有 YubiKey 私钥)
  ③ SHA-256(pubkey) ∈ 白名单 (证明 YubiKey 已授权)
  ①②③ 全满足 → UNLOCKED
```

---

## 2. 前置条件

### 2.1 硬件要求

| 场景 | 设备 | 操作系统 | 网络 |
|------|------|------|:--:|
| YubiKey 初始化 + manifest 签名 | 可信服务器（Intel NUC / 超微迷你服务器） | Ubuntu Server 22.04 LTS, LUKS 全盘加密 | **物理断开**或隔离 VLAN |
| 产线灌装 | 工控机（第三方维护） | Linux | 工厂内网 |
| SO 解锁 | TBox 设备 | TBox Linux (ARM) | 现场 |

### 2.2 YubiKey 选型

| 项目 | 选择 |
|------|------|
| 型号 | YubiKey 4 USB-A（推荐, 成本 ¥180-260）或 YubiKey 5 USB-A |
| 使用接口 | **PIV（FIPS 201）**，不涉及 FIDO2/OATH/OpenPGP/OTP/NFC |
| 使用 Slot | **9a（PIV Authentication）** |
| 密钥算法 | **RSA-2048**（非出厂预置，需手动生成） |
| 选购数量 | N+1 把（N = 安全官员数, 1 = 保险柜备用） |

详见 [25-yubikey-guide.md §2-4](25-yubikey-guide.md)。

### 2.3 可信服务器软件安装

**操作系统**：Ubuntu Server 22.04 LTS，全盘 LUKS 加密，最小安装。

```bash
# 1. 安装 ykman (YubiKey Manager CLI)
sudo apt-add-repository ppa:yubico/stable
sudo apt update
sudo apt install yubikey-manager

# 2. 验证安装
ykman --version
# 预期: YubiKey Manager (ykman) version: 5.x.x

# 3. 安装 PC/SC 智能卡驱动（YubiKey CCID 接口依赖）
sudo apt install pcscd libpcsclite1

# 4. 启动 pcscd 服务
sudo systemctl enable pcscd
sudo systemctl start pcscd

# 5. 安装 OpenSSL（RSA 密钥生成 + 签名 + 公钥解析）
sudo apt install openssl

# 6. 安装辅助工具
sudo apt install xxd jq

# 7. 插入 YubiKey 后验证识别
ykman piv info
# 能输出 PIV 信息 → 驱动安装成功
# 报 "No YubiKey detected" → 检查 pcscd 是否运行
```

### 2.4 USB 权限配置（Linux 必须）

```bash
# 添加 udev 规则
sudo bash -c 'cat > /etc/udev/rules.d/70-yubikey.rules << EOF
# YubiKey 4/5 — CCID (PIV/OpenPGP)
SUBSYSTEM=="usb", ATTR{idVendor}=="1050", ATTR{idProduct}=="0407", MODE="0660", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="1050", ATTR{idProduct}=="0406", MODE="0660", GROUP="plugdev"
# YubiKey 5 NFC
SUBSYSTEM=="usb", ATTR{idVendor}=="1050", ATTR{idProduct}=="0402", MODE="0660", GROUP="plugdev"
EOF'

sudo udevadm control --reload-rules
sudo udevadm trigger
sudo usermod -a -G plugdev it-admin
# 注销重新登录后生效

# 验证
ykman piv info   # 不应要求 sudo
```

### 2.5 验证安装清单

| 检查项 | 命令 | 预期结果 |
|------|------|------|
| ykman 可用 | `ykman --version` | ≥ 4.0 |
| pcscd 运行 | `systemctl status pcscd` | active (running) |
| YubiKey 识别 | `ykman info` | 显示设备型号和序列号 |
| PIV 接口正常 | `ykman piv info` | 显示 Slot 9a 信息 |
| USB 权限 | 非 root 运行 `ykman info` | 不需要 sudo |
| OpenSSL 可用 | `openssl version` | ≥ 1.1.1 |
| 签名目录存在 | `ls /opt/yubikey-signer/` | 显示 keys/ manifests/ logs/ |

---

## 3. YubiKey PIV RSA-2048 初始化

> **核心变化（与 ECDSA 方案的区别）**：不使用出厂预置的 ECDSA P-256 密钥，改为在 Slot 9a 手动生成 RSA-2048 密钥。此操作在可信服务器上由 IT 管理员执行，**每把 YubiKey 执行一次**。

### 3.1 完整初始化命令

**执行位置**：`[可信服务器]` — IT 管理员

```bash
# =============================================
# 1. 验证 YubiKey 基本信息
# =============================================
[可信服务器]$ ykman info
# Device type: YubiKey 4
# Serial number: 12345678
# Firmware version: 4.3.4

# =============================================
# 2. 修改默认 PIV PIN 和 PUK（安全必须）
# =============================================
# 默认 PIN:  123456
# 默认 PUK:  12345678
# 默认 Management Key: 010203040506070801020304050607080102030405060708

[可信服务器]$ ykman piv access change-pin
# Enter current PIN: 123456
# Enter new PIN: <IT 管理员设定的 PIN>

[可信服务器]$ ykman piv access change-puk
# Enter current PUK: 12345678
# Enter new PUK: <IT 管理员设定的 PUK>

# =============================================
# 3. 在 Slot 9a 生成 RSA-2048 密钥
# =============================================
# 删除出厂预置的 ECDSA P-256 密钥
[可信服务器]$ ykman piv delete 9a

# 生成 RSA-2048 密钥
[可信服务器]$ ykman piv generate-key 9a -a RSA2048 -m "$MGMT_KEY" --pin "$PIN" \
    -s "CN=TBox SO Dongle $(ykman info | grep Serial | awk '{print $NF}')"

# 生成自签名证书（OpenSSL 提取公钥需要证书格式，不重要——公钥是关键）
[可信服务器]$ ykman piv generate-certificate 9a -s "CN=TBox SO Dongle" - \
    --pin "$PIN" -m "$MGMT_KEY"

# =============================================
# 4. 验证 RSA-2048 密钥已生成
# =============================================
[可信服务器]$ ykman piv info
# Slot 9a:
#   Algorithm: RSA2048           ← 确认是 RSA-2048
#   Subject DN: CN=TBox SO Dongle 12345678

# =============================================
# 5. 提取 RSA 公钥（DER 格式）并计算哈希
# =============================================
[可信服务器]$ ykman piv export-certificate 9a - \
    | openssl x509 -pubkey -noout \
    | openssl pkey -pubin -outform DER \
    > /opt/yubikey-signer/manifests/yk-12345678-pub.der

[可信服务器]$ sha256sum /opt/yubikey-signer/manifests/yk-12345678-pub.der \
    | awk '{print $1}' \
    > /opt/yubikey-signer/manifests/yk-12345678.hash

[可信服务器]$ cat /opt/yubikey-signer/manifests/yk-12345678.hash
# 输出: 64 位 hex 字符串（SHA-256）

# =============================================
# 6. 测试 RSA 签名（自检验证）
# =============================================
echo -n "test challenge" | openssl dgst -sha256 -binary > /tmp/test_digest.bin

# YubiKey 签名（需要 PIN）
[可信服务器]$ ykman piv sign 9a -s SHA256 /tmp/test_digest.bin /tmp/test_sig.der \
    --pin "$PIN"

# OpenSSL 验证
[可信服务器]$ openssl dgst -sha256 -verify \
    <(openssl pkey -pubin -in /opt/yubikey-signer/manifests/yk-12345678-pub.der -inform DER -pubout) \
    -signature /tmp/test_sig.der /tmp/test_digest.bin
# 预期: Verified OK

# =============================================
# 7. 拔掉 YubiKey → 交还安全官员
# =============================================
```

**关键点**：
- `-a RSA2048` 指定 RSA-2048 算法
- 第 6 步的自检确保 YubiKey 签名 + OpenSSL 验签闭环——**也是后续 TA 内验签的原理预演**
- PIV PIN 和 Management Key 由 IT 管理员记录后密封保管
- 安全官员不知道 PIV PIN——他只知道 SO-PIN（完全不同的凭证）

---

## 4. 可信服务器密钥管理

### 4.1 生成 RSA 签名密钥对（manifest 签名用）

**执行位置**：`[可信服务器]` — IT 管理员

```bash
# 生成 RSA-2048 密钥对（用于签名 manifest）
# 这个私钥签名白名单清单, TA 存储对应公钥
[可信服务器]$ openssl genpkey -algorithm RSA \
    -out /opt/yubikey-signer/keys/manifest_key.pem \
    -pkeyopt rsa_keygen_bits:2048

# 提取公钥 DER（编译进 TA）
[可信服务器]$ openssl rsa -pubout \
    -in /opt/yubikey-signer/keys/manifest_key.pem \
    -outform DER \
    -out /opt/yubikey-signer/keys/manifest_key_pub.der

# 私钥保护
[可信服务器]$ sudo chown root:root /opt/yubikey-signer/keys/manifest_key.pem
[可信服务器]$ sudo chmod 400 /opt/yubikey-signer/keys/manifest_key.pem
```

### 4.2 公钥硬编码进 TA

TA 编译时需要 manifest 签名服务器的 RSA 公钥（TA 用此公钥验证 manifest 的 RSA 签名，证明白名单确实来自可信服务器）。

新建 `ta/include/trusted_server_pubkey.h`：

```c
/* RSA-2048 public key DER of the trusted provisioning server.
 * Generated once at server setup. Only this key can sign valid
 * dongle manifests. */
static const uint8_t TRUSTED_SERVER_PUBKEY_DER[] = {
    /* paste xxd output of manifest_key_pub.der here */
};
static const size_t TRUSTED_SERVER_PUBKEY_DER_LEN =
    sizeof(TRUSTED_SERVER_PUBKEY_DER);
```

### 4.3 密钥轮换

| 场景 | 影响 | 操作 |
|------|------|------|
| manifest 签名私钥泄露 | 需重新编译 TA（公钥更新）→ 所有 TBox 重新灌装 | 紧急流程 |
| YubiKey 私钥丢失（硬件丢失/损坏） | 单把 YubiKey 失效, 备用 YubiKey 可用 | 重新生成备用 YubiKey 的 manifest |
| 定期轮换（2 年） | 计划内维护 | 同泄露流程 |

### 4.4 两种 RSA 密钥的区分

本文档涉及两对完全独立的 RSA-2048 密钥，不要混淆：

| 密钥对 | 私钥在哪里 | 公钥在哪里 | 用途 |
|------|------|------|------|
| **Manifest 签名密钥** | 可信服务器 (`manifest_key.pem`) | TA 内硬编码 (`TRUSTED_SERVER_PUBKEY_DER`) | 签名 manifest → TA 验签证明"白名单来自可信服务器" |
| **YubiKey PIV Slot 9a 密钥** | YubiKey 硬件内部（不可导出） | manifest.bin 白名单中（SHA-256 哈希形式） | 签名 challenge → TA 验签证明"我持有授权的 YubiKey" |

---

## 5. 白名单 Manifest 生成与签名

### 5.1 读取 YubiKey 公钥

**执行位置**：`[可信服务器]` — IT 管理员

```bash
# 对每把授权 YubiKey 重复（见 §3.1 步骤 5）
# 结果: /opt/yubikey-signer/manifests/ 下为每把 YubiKey 生成:
#   yk-<serial>-pub.der     ← RSA-2048 公钥 DER (~294 字节)
#   yk-<serial>.hash         ← SHA-256(公钥 DER)，64 字符 hex
```

### 5.2 构建和签名 Manifest

```bash
#!/bin/bash
# 在可信服务器上依次执行

# 1. 构建 JSON 白名单描述
cat > /opt/yubikey-signer/manifests/manifest_v1.json << EOF
{
    "version": 1,
    "timestamp": $(date +%s),
    "generated_by": "trusted-server-01",
    "comment": "Production batch 2026-Q3, 2 YubiKeys (RSA-2048)",
    "dongles": [
        {
            "index": 0,
            "serial": 12345678,
            "role": "primary-so",
            "pubkey_sha256": "$(cat /opt/yubikey-signer/manifests/yk-12345678.hash)"
        },
        {
            "index": 1,
            "serial": 87654321,
            "role": "backup-so",
            "pubkey_sha256": "$(cat /opt/yubikey-signer/manifests/yk-87654321.hash)"
        }
    ]
}
EOF

# 2. JSON → 二进制 manifest（使用 gen-manifest.sh，见附录 A）
/opt/yubikey-signer/gen-manifest.sh \
    /opt/yubikey-signer/manifests/manifest_v1.json \
    /opt/yubikey-signer/manifests/manifest_v1.bin

# 3. RSA-2048 SHA-256 签名
openssl dgst -sha256 -sign /opt/yubikey-signer/keys/manifest_key.pem \
    -out /opt/yubikey-signer/manifests/manifest_v1.sig \
    /opt/yubikey-signer/manifests/manifest_v1.bin

# 4. 自检验证（用 TA 硬编码的公钥——这是 TA 验签的预演）
openssl dgst -sha256 -verify \
    <(openssl rsa -pubin -inform DER -in /opt/yubikey-signer/keys/manifest_key_pub.der -pubout) \
    -signature /opt/yubikey-signer/manifests/manifest_v1.sig \
    /opt/yubikey-signer/manifests/manifest_v1.bin
# 预期: Verified OK

# 5. 审计日志
echo "$(date -Iseconds) | manifest_v1 | $(sha256sum manifest_v1.bin | awk '{print $1}') | IT-Admin:$(whoami)" \
    >> /opt/yubikey-signer/logs/signing.log
```

### 5.3 交付工厂

| 交付物 | 内容 | 涉密 | 传输方式 |
|------|------|:--:|------|
| `manifest_v1.bin` | 版本号 + 时间戳 + SHA-256(pubkey) × N | 否 | SCP / U盘 / 邮件 |
| `manifest_v1.sig` | RSA-2048 签名 | 否 | 同 manifest.bin |
| `batch-so-pin.txt` | 32 字节 hex SO-PIN | **是** | 安全官员 → GPG 加密邮件 → 产线负责人 |

---

## 6. 产线灌装

### 6.1 工控机准备工作

```
/factory/                        ← 工控机本地临时目录
├── manifest_v1.bin              ← 可信服务器签名的白名单
├── manifest_v1.sig              ← RSA-2048 签名
├── batch-so-pin.txt             ← 批次 SO-PIN（涉密，灌装后用 shred -u 擦除）
├── devices.txt                  ← 本批次 TBox 序列号（每行一个）
└── provision_batch.sh           ← 灌装脚本
```

**文件说明**：

| 文件 | 内容示例 | 谁提供 | 涉密 |
|------|------|------|:--:|
| `manifest_v1.bin` | 二进制，12 + N×40 字节 | 可信服务器 IT 管理员 | 否（公钥哈希） |
| `manifest_v1.sig` | 256 字节 | 可信服务器 IT 管理员 | 否 |
| `batch-so-pin.txt` | `f1e2d3c4b5a60718293a4b5c6d7e8f90` | 安全官员通过 GPG 加密交付 | **是** |
| `devices.txt` | `TBOX-PROD-2026Q3-00001`<br>`TBOX-PROD-2026Q3-00002`<br>... | MES 系统导出 | 否 |

### 6.2 批量灌装脚本

```bash
#!/bin/bash
# /factory/provision_batch.sh
# 在工控机上执行, 每个 TBox 循环灌装
set -e

MANIFEST_BIN="/factory/manifest_v1.bin"
MANIFEST_SIG="/factory/manifest_v1.sig"
SO_PIN=$(cat /factory/batch-so-pin.txt)
DEVICES="/factory/devices.txt"
LOG="/factory/provision-$(date +%Y%m%d-%H%M%S).log"

echo "=========================================="  | tee -a "$LOG"
echo " TBox Batch Provisioning"                     | tee -a "$LOG"
echo " Manifest: $(basename $MANIFEST_BIN)"         | tee -a "$LOG"
echo " Devices:  $(wc -l < $DEVICES) units"        | tee -a "$LOG"
echo "=========================================="  | tee -a "$LOG"

PASS=0; FAIL=0

for device_serial in $(cat "$DEVICES"); do
    echo "" | tee -a "$LOG"
    echo "--- [$device_serial] Provisioning ---" | tee -a "$LOG"

    # 每设备独立的 Provisioning PIN
    DEV_PIN=$(openssl rand -hex 16)

    # 步骤 1: 写入 Provisioning PIN
    echo "  [1/6] Init PIN..." | tee -a "$LOG"
    tbox_keystore --init-pin "$DEV_PIN"
    echo "  [1/6] ✓ PIN initialized" | tee -a "$LOG"

    # 步骤 2-3: 生成设备密钥
    echo "  [2/6] Generate RSA key..." | tee -a "$LOG"
    tbox_keystore --gen-rsa device-key --size 2048 --sign --decrypt
    echo "  [2/6] ✓ RSA-2048 key: device-key" | tee -a "$LOG"

    echo "  [3/6] Generate AES key..." | tee -a "$LOG"
    tbox_keystore --gen-aes ota-key --size 256 --decrypt
    echo "  [3/6] ✓ AES-256 key: ota-key" | tee -a "$LOG"

    # 步骤 4: 导出设备公钥（用于向 CA 签发设备证书）
    echo "  [4/6] Export public key..." | tee -a "$LOG"
    tbox_keystore --export-pub device-key --out /tmp/${device_serial}-device-key.pub
    echo "  [4/6] ✓ Public key exported" | tee -a "$LOG"

    # 步骤 5: SO-PIN + 签名白名单灌装
    echo "  [5/6] Provision SO-PIN + dongle manifest..." | tee -a "$LOG"

    tbox_keystore --init-so-pin "$SO_PIN"

    # 上传 manifest 到 TBox 临时目录
    scp "$MANIFEST_BIN" root@TBOX_IP:/tmp/manifest.bin
    scp "$MANIFEST_SIG" root@TBOX_IP:/tmp/manifest.sig

    # 灌装签名白名单
    # TA 内部: RSA_Verify(manifest, sig, TRUSTED_SERVER_PUBKEY)
    # → 验签通过, 白名单写入 SO_DONGLE_UUID
    # → 验签失败, 拒绝 (TEE_ERROR_SIGNATURE_INVALID)
    tbox_keystore --provision-dongle-manifest \
        /tmp/manifest.bin /tmp/manifest.sig

    # 擦除 TBox 临时文件
    ssh root@TBOX_IP "rm /tmp/manifest.bin /tmp/manifest.sig"
    echo "  [5/6] ✓ SO-PIN + dongle manifest provisioned" | tee -a "$LOG"

    # 步骤 6: 锁定 TA
    echo "  [6/6] Locking TA..." | tee -a "$LOG"
    tbox_keystore --lock
    echo "  [6/6] ✓ TA locked" | tee -a "$LOG"

    PASS=$((PASS + 1))
    echo "  ✅ [$device_serial] Done ($PASS/$((PASS+FAIL)))" | tee -a "$LOG"
done

echo "" | tee -a "$LOG"
echo "==========================================" | tee -a "$LOG"
echo " Provisioning complete" | tee -a "$LOG"
echo " Pass: $PASS  Fail: $FAIL" | tee -a "$LOG"
echo "==========================================" | tee -a "$LOG"

exit $FAIL
```

### 6.3 灌装后清理

```bash
# 擦除涉密文件
[工控机]$ shred -u /factory/batch-so-pin.txt

# 归档日志
[工控机]$ cp /factory/provision-*.log /archive/provision-logs/
```

---

## 7. SO 解锁流程

### 7.1 协议

```
安全官员                TBox CA (REE)              TBox TA (TEE)           安全存储
────────                ────────────               ────────────            ────────
① 插入 YubiKey

② 输入 SO-PIN          ③ ──CMD_SO_UNLOCK_REQ──▶
                                                 ④ SHA-256(PIN) ✓
                                                   失败计数器检查 ✓
                                                   冷却期检查 ✓
                                                 ⑤ TEE_GenerateRandom → challenge[32]
                                                 ⑥ 读 SO_DONGLE_UUID → dongle_list
                           ◀──challenge + dongle_list──

                        ⑦ SHA-256(challenge) → chg_hash

                        ⑧ YubiKey 签名:         ← PIV Slot 9a RSA-2048 私钥
                           ykman piv sign 9a
                           -s SHA256 chg_hash
                           → sig_der (256 B)

                        ⑨ 读 YubiKey 公钥:
                           ykman piv export-cert 9a
                           → pubkey_der (~294 B)

                        ⑩ ──CMD_SO_UNLOCK_CONFIRM──▶   param: pubkey_der + sig_der
                                                 ⑪ TA 原子验证:
                                                    Ⓐ crypto_rsa_verify(
                                                         pubkey, 2048,
                                                         chg_hash, 32,
                                                         sig_der, sig_len)
                                                       ✓ 签名有效
                                                    Ⓑ SHA-256(pubkey_der) → hash
                                                       hash ∈ 白名单[0..N] ✓
                                                 ⑫ Ⓐ∧Ⓑ 全满足 → UNLOCKED
                                                    任一失败 → TEE_ERROR_ACCESS_DENIED
                                                    失败计数器 +1

                        ⑬ ◀──UNLOCKED──
                        ✓ 写保护解除
```

### 7.2 关键差异：与 ECDSA 方案的对比

| 维度 | ECDSA 方案（当前实现） | RSA-2048 方案（本文档） |
|------|------|------|
| YubiKey 密钥类型 | ECDSA P-256（出厂预置） | RSA-2048（手动生成） |
| YubiKey 初始化 | 零配置 | 需 `ykman piv generate-key 9a -a RSA2048`（30 秒） |
| TA 验签 | **不支持**（OP-TEE 3.2 panic） | **支持**（`crypto_rsa_verify` 已实现） |
| TA 验签 + 白名单匹配 | 分开（CA 验 + TA 比）→ 可被切断 | **原子操作**（TA 内同时完成）→ 不可切断 |
| CMD_SO_UNLOCK_CONFIRM 参数 | 空（TA 盲信 CA） | pubkey_der + sig_der（TA 独立验证） |

### 7.3 TA 侧实现

#### 7.31 新增命令

`ta/include/tbox_keystore_ta.h` 新增两条命令：

```c
/*
 * CMD_PROVISION_DONGLE_MANIFEST — 一次性写入整个 dongle 白名单
 * param[0] (memref) manifest 二进制
 * param[1] (memref) RSA-2048 SHA-256 签名（可信服务器私钥签名）
 */
#define CMD_PROVISION_DONGLE_MANIFEST  19

/*
 * CMD_SO_UNLOCK_CONFIRM — 提交 YubiKey RSA 签名 + 公钥，TA 内部
 * 同时完成 RSA 验签 + 白名单匹配，两项均通过才解锁。
 * param[0] (memref) YubiKey RSA-2048 公钥 DER (~294 bytes)
 * param[1] (memref) RSA-2048 SHA-256 签名 (256 bytes)
 */
#define CMD_SO_UNLOCK_CONFIRM          18  /* 注意: 与 ECDSA 方案的 CMD 18 参数不同 */
```

#### 7.32 SO-PIN 解锁确认逻辑

`ta/so_pin_mgr.c` 中的 `so_unlock_confirm()`：

```c
TEE_Result so_unlock_confirm(const uint8_t *pubkey_der, size_t der_len,
                             const uint8_t *sig_der, size_t sig_len,
                             const uint8_t *challenge)
{
    struct so_dongle_list dl;
    uint8_t pk_hash[32];
    uint8_t chg_hash[32];
    TEE_ObjectHandle rsa_key = TEE_HANDLE_NULL;
    TEE_Result res;

    /* 步骤 1: 将 pubkey DER 导入为 RSA 公钥对象，用于验签 */
    /* (使用 TEE_AllocateTransientObject + TEE_ATTR_RSA_PUBLIC_EXPONENT + TEE_ATTR_RSA_MODULUS) */
    res = rsa_import_pubkey_from_der(pubkey_der, der_len, &rsa_key);
    if (res != TEE_SUCCESS)
        goto out;

    /* 步骤 2: SHA-256(challenge) — 构建验签的消息摘要 */
    res = so_sha256(challenge, 32, chg_hash, sizeof(chg_hash));
    if (res != TEE_SUCCESS)
        goto out;

    /* 步骤 3: RSA-2048 SHA-256 验签（证明持有 YubiKey 私钥） */
    res = crypto_rsa_verify(rsa_key, 2048, chg_hash, 32, sig_der, sig_len);
    if (res != TEE_SUCCESS) {
        EMSG("SO confirm: RSA signature INVALID");
        so_record_failure();
        goto out;
    }

    /* 步骤 4: SHA-256(pubkey_der) → 白名单匹配（证明 YubiKey 已授权） */
    res = so_sha256(pubkey_der, der_len, pk_hash, sizeof(pk_hash));
    if (res != TEE_SUCCESS)
        goto out;

    so_dongle_load(&dl);

    for (uint32_t i = 0; i < dl.count; i++) {
        if (memcmp(pk_hash, dl.entries[i].pubkey_hash, 32) == 0) {
            /* 步骤 3 ∧ 步骤 4 全部通过 → 原子解锁 */
            DMSG("SO unlock: RSA verified + whitelist[%u] matched → UNLOCKED", i);
            so_reset_consecutive();
            g_so_state = SO_STATE_UNLOCKED;
            // 持久化 SO_LOCK_UUID
            res = TEE_SUCCESS;
            goto out;
        }
    }

    /* 白名单不匹配 — 签名有效但此 YubiKey 未授权 */
    EMSG("SO confirm: pubkey NOT in whitelist (RSA sig was valid)");
    so_record_failure();
    res = TEE_ERROR_ACCESS_DENIED;

out:
    if (rsa_key != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(rsa_key);
    return res;
}
```

**关键**：步骤 3（RSA 验签）和步骤 4（白名单匹配）在同一个函数、同一段代码中**不可分割地**完成。CA 无法在中间篡改——要么全通过，要么全拒绝。

### 7.4 命令行

```bash
# SO 解锁（安全官员操作）
TBox$ tbox_keystore --so-unlock --so-pin <SO-PIN> --dongle yubikey

# CA 内部自动:
#   1. CMD_SO_UNLOCK_REQ(SO-PIN) → challenge + dongle_list
#   2. SHA-256(challenge)
#   3. ykman piv sign 9a -s SHA256 <chg_hash> → sig_der
#   4. ykman piv export-certificate 9a → pubkey_der
#   5. CMD_SO_UNLOCK_CONFIRM(pubkey_der, sig_der) → TA 验签+白名单匹配
```

---

## 8. 安全分析

### 8.1 三道防线

```
┌─────────────────────────────────────────────────────────────────┐
│ 防线 1: SO-PIN 验证（TA 内）                      ✓ TA 独立执行 │
│   CMD_SO_UNLOCK_REQ → SHA-256(PIN) vs SO_PIN_UUID              │
│   防止: 不知道 PIN 的人解锁                                      │
│                                                                 │
│ 防线 2: RSA-2048 签名验证（TA 内）                ✓ TA 独立执行 │
│   CMD_SO_UNLOCK_CONFIRM → crypto_rsa_verify(pubkey, sig)       │
│   防止: 没有持有 YubiKey 的人解锁                                │
│                                                                 │
│ 防线 3: 公钥白名单匹配（TA 内）                    ✓ TA 独立执行 │
│   CMD_SO_UNLOCK_CONFIRM → SHA-256(pubkey) ∈ 白名单             │
│   防止: YubiKey 未授权（不在采购清单中）                           │
│                                                                 │
│ 防线 2 ∧ 防线 3 在同一函数内原子完成 — 中间没有 CA 可以切断的环节    │
└─────────────────────────────────────────────────────────────────┘
```

### 8.2 攻击场景

| 攻击者 | 能做的事 | SO-PIN | YubiKey | 公钥在白名单 | TA RSA 验签 | 结果 |
|------|------|:--:|:--:|:--:|:--:|------|
| 攻击者（替换 CA） | 知道 SO-PIN，无 YubiKey | ✓ | ✗ | — | ✗ | **拒绝**——无法产生有效 RSA 签名 |
| 攻击者（替换 CA） | 知道 SO-PIN，有**未授权** YubiKey | ✓ | ✓ | ✗ | ✓ | **拒绝**——白名单不匹配 |
| 攻击者（替换 CA） | 知道 SO-PIN，知道 pubkey_der（从 manifest.bin） | ✓ | — | ✓ | ✗ | **拒绝**——无对应私钥，无法签名 |
| 安全官员 | SO-PIN + 授权 YubiKey | ✓ | ✓ | ✓ | ✓ | **通过** ✓ |
| 安全官员（丢失 YubiKey） | SO-PIN + 备用 YubiKey | ✓ | ✓ | ✓ | ✓ | **通过** ✓ |
| 远程攻击者 | 不知道 SO-PIN | ✗ | — | — | — | **拒绝**——防线 1 失败 |

**核心保证**：即使攻击者**完全替换了 CA 二进制**（知道 SO-PIN + 知道 pubkey_der + 可以构造任意 TEEC 命令），只要没有白名单中 YubiKey 的 RSA 私钥，就无法让 TA 通过第 2 道防线（RSA 验签）。

### 8.3 信任边界

```
═══════════════════ TA (TEE) 内 — 可信 ═══════════════════
  SO-PIN hash 比较
  RSA-2048 验签 ←─ 关键: 在 TA 内, 不受 CA 影响
  白名单 hash 比较
  → 三个条件全部满足才解锁
══════════════════════════════════════════════════════════

═══════════════════ CA (REE) 侧 — 不可信 ═════════════════
  CA 负责: 读 YubiKey 公钥, 中转 challenge/签名到 TA
  CA 无法: 伪造有效 RSA 签名 (没有 YubiKey 私钥)
  攻击者替换 CA: 可以跳过 YubiKey 交互, 但无法产生有效 RSA 签名 → TA 拒绝
══════════════════════════════════════════════════════════
```

---

## 9. 改动清单

| 层 | 文件 | 改动量 | 说明 |
|------|------|:--:|------|
| **TA** | `tbox_keystore_ta.h` | 小 | `CMD_PROVISION_DONGLE_MANIFEST`(19) + `CMD_SO_UNLOCK_CONFIRM`(18) 带 pubkey+sig 参数 |
| **TA** | `so_pin_mgr.c` | 大 | `so_provision_dongle_manifest()` RSA 验签 + 原子替换白名单；`so_unlock_confirm()` RSA 验签 + 白名单匹配原子操作 |
| **TA** | `crypto_ops.c` | 小 | 新增 `rsa_import_pubkey_from_der()` 将 DER 格式 RSA 公钥导入为 TEE 对象 |
| **TA** | `entry.c` | 小 | 新增 2 个 cmd handler + dispatch |
| **TA** | `trusted_server_pubkey.h` | 新建 | 硬编码 manifest 签名服务器的 RSA 公钥 DER |
| **TA** | `sub.mk` | +1 行 | — |
| **CA** | `keystore_client.c` | 中 | `--provision-dongle-manifest` + `--so-unlock` 更新为 RSA 签名参数 |
| **可信服务器** | `gen-manifest.sh` | 新建 | JSON→二进制 manifest 转换 |
| **可信服务器** | `sign-manifest.sh` | 新建 | RSA 签名 + 审计日志 |
| **工控机** | `provision_batch.sh` | 替换 | 切换到 `--provision-dongle-manifest` |

**不涉及**：`dongle/` 目录、`dongle_test`、`test_so_lifecycle.sh`（测试脚本调整参数即可）。

---

## 10. 实施步骤

| 步骤 | 内容 | 周期 |
|:--:|------|:--:|
| 1 | 采购 + 部署可信服务器（硬件 + LUKS + §2.3-2.4 软件） | 1 天 |
| 2 | 生成 manifest 签名 RSA 密钥对 + 公钥硬编码进 TA | 0.5 天 |
| 3 | IT 管理员初始化 YubiKey（§3.1：改 PIN/PUK + 生成 RSA-2048 密钥 + 自检） | 0.5 天 |
| 4 | 部署签名脚本到可信服务器（附录 A/B） | 0.5 天 |
| 5 | TA 实现 `CMD_PROVISION_DONGLE_MANIFEST` + `CMD_SO_UNLOCK_CONFIRM`（RSA 版） | 3 天 |
| 6 | CA 实现对应 CLI 命令 | 1 天 |
| 7 | 灌装脚本切换到 manifest 模式 | 0.5 天 |
| 8 | 测试环境端到端验证（灌装 + SO 解锁） | 2 天 |
| 9 | 产线试运行（与现有流程并行） | 1 周 |

**总工期**：约 3 周。

---

> 相关文档：
> - [24-so-pin-yubikey-unlock.md](24-so-pin-yubikey-unlock.md) — SO-PIN 双因子解锁协议（ECDSA 版历史记录）
> - [26-sgx-provisioning-attestation.md](26-sgx-provisioning-attestation.md) — SGX 远程证明方案（高级方案）
> - [25-yubikey-guide.md](25-yubikey-guide.md)、[27](27-yubikey-provisioning-trusted-server.md)、[28](28-yubikey-full-lifecycle.md) — 本文档已合并替代

---

## 附录 A：gen-manifest.sh（JSON → 二进制 manifest）

部署位置：`/opt/yubikey-signer/gen-manifest.sh`

```bash
#!/bin/bash
# ============================================================
# gen-manifest.sh — JSON → binary manifest converter
# Usage: ./gen-manifest.sh <manifest.json> <manifest.bin>
#
# Output binary format (little-endian):
#   [version:4][timestamp:4][count:4]
#   [entry × count: hash[32] + serial[4] + reserved[4]]
#   Total = 12 + count × 40 bytes (max 332)
# ============================================================
set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <manifest.json> <manifest.bin>"
    exit 1
fi

JSON="$1"; OUT="$2"

if [ ! -f "$JSON" ]; then
    echo "ERROR: $JSON not found"; exit 1
fi

VERSION=$(jq -r '.version' "$JSON")
TIMESTAMP=$(jq -r '.timestamp' "$JSON")
COUNT=$(jq -r '.dongles | length' "$JSON")

echo "Manifest: version=$VERSION ts=$TIMESTAMP dongles=$COUNT"

if [ "$COUNT" -lt 1 ]; then
    echo "ERROR: dongles array is empty"; exit 1
fi
if [ "$COUNT" -gt 8 ]; then
    echo "ERROR: max 8 dongles supported (got $COUNT)"; exit 1
fi

TMP=$(mktemp)

# Header
printf '%08x' "$VERSION"  | xxd -r -p | dd of="$TMP" bs=1 seek=0  conv=notrunc 2>/dev/null
printf '%08x' "$TIMESTAMP"| xxd -r -p | dd of="$TMP" bs=1 seek=4  conv=notrunc 2>/dev/null
printf '%08x' "$COUNT"    | xxd -r -p | dd of="$TMP" bs=1 seek=8  conv=notrunc 2>/dev/null

# Entries
OFFSET=12
for i in $(seq 0 $((COUNT - 1))); do
    HASH=$(jq -r ".dongles[$i].pubkey_sha256" "$JSON")
    SERIAL=$(jq -r ".dongles[$i].serial" "$JSON")

    if [ "${#HASH}" -ne 64 ]; then
        echo "ERROR: dongle[$i] pubkey_sha256 must be 64 hex chars"; rm -f "$TMP"; exit 1
    fi

    echo "$HASH" | xxd -r -p | dd of="$TMP" bs=1 seek=$OFFSET conv=notrunc 2>/dev/null
    OFFSET=$((OFFSET + 32))

    printf '%08x' "$SERIAL" | xxd -r -p | dd of="$TMP" bs=1 seek=$OFFSET conv=notrunc 2>/dev/null
    OFFSET=$((OFFSET + 4))

    printf '%08x' 0 | xxd -r -p | dd of="$TMP" bs=1 seek=$OFFSET conv=notrunc 2>/dev/null
    OFFSET=$((OFFSET + 4))

    echo "  dongle[$i]: hash=${HASH:0:16}... serial=$SERIAL"
done

mv "$TMP" "$OUT"
echo "✓ Manifest: $OUT ($((12 + COUNT * 40)) bytes)"
```

## 附录 B：sign-manifest.sh（RSA 签名 + 审计）

部署位置：`/opt/yubikey-signer/sign-manifest.sh`

```bash
#!/bin/bash
# ============================================================
# sign-manifest.sh — RSA sign manifest + audit log
# Usage: ./sign-manifest.sh <manifest.bin>
# ============================================================
set -e

MANIFEST="$1"
if [ -z "$MANIFEST" ]; then
    echo "Usage: $0 <manifest.bin>"; exit 1
fi
if [ ! -f "$MANIFEST" ]; then
    echo "ERROR: $MANIFEST not found"; exit 1
fi

KEY="/opt/yubikey-signer/keys/manifest_key.pem"
SIG="${MANIFEST}.sig"
VERIFY_KEY="/opt/yubikey-signer/keys/manifest_key_pub.der"
LOG="/opt/yubikey-signer/logs/signing.log"

if [ ! -f "$KEY" ]; then
    echo "ERROR: Private key not found: $KEY"; exit 1
fi

echo "Signing: $(basename "$MANIFEST")"
openssl dgst -sha256 -sign "$KEY" -out "$SIG" "$MANIFEST"
echo "  Output: $(basename "$SIG") ($(wc -c < "$SIG") bytes)"

echo "Self-verifying..."
if openssl dgst -sha256 -verify \
    <(openssl rsa -pubin -inform DER -in "$VERIFY_KEY" -pubout) \
    -signature "$SIG" "$MANIFEST" 2>&1; then
    echo "  ✓ Signature verified OK"
else
    echo "  ✗ SIGNATURE VERIFICATION FAILED — DO NOT DISTRIBUTE"
    rm -f "$SIG"; exit 1
fi

MANIFEST_SHA256=$(sha256sum "$MANIFEST" | awk '{print $1}')
mkdir -p "$(dirname "$LOG")"
cat >> "$LOG" << EOF
$(date -Iseconds) | $(basename "$MANIFEST") | sha256=$MANIFEST_SHA256 | operator=${SUDO_USER:-$USER} | status=OK
EOF
echo "  Audit: $LOG"
```

## 附录 C：manifest 二进制格式

TA 解析 manifest.bin 使用的格式，little-endian 字节序：

```
偏移    长度    字段          说明
0       4       version        uint32 LE, 单调递增 (≥1)
4       4       timestamp      uint32 LE, Unix 时间戳
8       4       count          白名单条目数 (1-8)
12     40×N     entries[]      每条 40 字节

条目格式 (40 字节):
  偏移  长度  字段
  0    32    pubkey_sha256    SHA-256(RSA-2048 pubkey DER)
  32    4    serial           uint32 LE, YubiKey 序列号
  36    4    reserved         保留 (填 0)

总大小: 12 + count × 40 字节 (max 332)
```
