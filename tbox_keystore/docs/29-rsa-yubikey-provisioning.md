# 29 — 基于 YubiKey RSA-2048 的产线灌装与 SO 解锁完整方案

## 概述

本文档描述 TBox 安全体系中 YubiKey 的**完整使用闭环**——从硬件采购、初始化、产线灌装到现场 SO 解锁。

**技术决策**：使用 YubiKey PIV Slot 9a 的 **RSA-2048** 密钥。TA 在 TEE 安全世界内同时完成 RSA 验签和公钥白名单匹配，攻击者即使替换了 CA 二进制且知道 SO-PIN，若未持有白名单中的 YubiKey，TA 验签失败 → 拒绝解锁。

**信任模型**：工控机不可信（第三方维护），安全官员不可信（傀儡/快递员），白名单签名权集中在 IT 管理员维护的物理隔离可信服务器上。

---

## 1. 角色定义

| 角色 | 可信度 | 职责 | 约束 |
|------|:--:|------|------|
| **IT 管理员** | 半可信（操作守则 + 双人操作 + 审计日志约束） | 在可信服务器上初始化 YubiKey、签名白名单、管理 RSA 密钥生命周期 | 物理访问可信服务器 |
| **可信服务器** | 物理隔离（全盘加密 Linux 服务器） | 读取 YubiKey 公钥、SHA-256 哈希、RSA-2048 私钥签名 manifest | 离线或隔离 VLAN；禁止互联网 |
| **安全官员** | 不可信 | 携带 YubiKey 到机房/现场；记忆 SO-PIN；现场插入 YubiKey 执行 SO 解锁 | 不操作任何软件命令（由 IT 管理员/CA 代为执行） |
| **工控机** | 不可信（第三方维护） | 下载签名 manifest，搬运到 TBox，执行灌装脚本 | 不接触任何私钥 |
| **TBox CA**（REE Linux 用户态） | 不可信 | 中转 challenge 到 YubiKey；将 YubiKey 签名和公钥提交给 TA；**可以被攻击者替换** | — |
| **TBox TA**（ARM TrustZone 安全世界） | **可信** | TA 内 RSA-2048 验签 + 白名单匹配 → 原子解锁 | OP-TEE 3.2；不可篡改 |

---

## 2. 硬件与软件准备

### 2.1 硬件清单

| 设备 | 数量 | 规格 | 用途 |
|------|:--:|------|------|
| **可信服务器** | 1 台 | x86-64, ≥4 GB RAM, ≥128 GB SSD, ≥2 USB | IT 管理员初始化 YubiKey + 签名 manifest |
| **YubiKey 4 USB-A** | N+1 把 | PIV RSA-2048 支持 | N = 安全官员人数；1 = 保险柜备用 |
| **工控机** | 1 台 | Linux, USB + 串口 | 产线灌装（第三方维护） |
| **TBox** | 批产数量 | ARM Cortex-A, OP-TEE 3.2 | 目标设备 |
| **安全官员笔记本** | 1 台 | Linux/macOS/Windows | 生成 SO-PIN（离线） |

### 2.2 可信服务器操作系统

Ubuntu Server 22.04 LTS，最小安装。**全盘 LUKS 加密**。物理断开互联网，或仅连接隔离 VLAN。

```bash
# 安装时选择:
#   - "Minimal installation"
#   - "Encrypt the LVM group with LUKS"
#   - 不自动安装更新
```

### 2.3 可信服务器软件安装

```bash
# 1. 更新包列表
sudo apt update

# 2. 安装 YubiKey Manager CLI
sudo apt-add-repository ppa:yubico/stable
sudo apt update
sudo apt install yubikey-manager

# 3. 验证 ykman 版本
ykman --version
# 预期: YubiKey Manager (ykman) version: 5.x.x

# 4. 安装 PC/SC 智能卡驱动（YubiKey CCID 接口必需）
sudo apt install pcscd libpcsclite1

# 5. 启动 pcscd 服务并设为开机自启
sudo systemctl enable pcscd
sudo systemctl start pcscd

# 6. 安装 OpenSSL（RSA 密钥生成、签名、公钥解析）
sudo apt install openssl

# 7. 安装辅助工具
sudo apt install xxd jq
```

### 2.4 USB 权限配置

Linux 下非 root 用户访问 YubiKey 需要 udev 规则。在生产环境中 IT 管理员使用 `it-admin` 用户操作。

```bash
# 1. 创建 udev 规则文件
sudo bash -c 'cat > /etc/udev/rules.d/70-yubikey.rules << EOF
# YubiKey 4/5 — CCID (PIV)
SUBSYSTEM=="usb", ATTR{idVendor}=="1050", ATTR{idProduct}=="0407", \
    MODE="0660", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="1050", ATTR{idProduct}=="0406", \
    MODE="0660", GROUP="plugdev"
# YubiKey 5 NFC
SUBSYSTEM=="usb", ATTR{idVendor}=="1050", ATTR{idProduct}=="0402", \
    MODE="0660", GROUP="plugdev"
EOF'

# 2. 重新加载 udev 规则
sudo udevadm control --reload-rules
sudo udevadm trigger

# 3. 创建 it-admin 用户并加入 plugdev 组
sudo useradd -m -s /bin/bash it-admin
sudo usermod -a -G plugdev it-admin

# 4. 注销 it-admin 用户并重新登录，使组生效
# 5. 验证（插入 YubiKey 后）
su - it-admin
ykman piv info
# 预期：显示 PIV 信息，不需要 sudo
```

### 2.5 创建签名工作目录

```bash
sudo mkdir -p /opt/yubikey-signer/{keys,manifests,logs}
sudo chown -R it-admin:it-admin /opt/yubikey-signer
```

### 2.6 验证安装清单

插入任意一把 YubiKey，逐一检查：

| 检查项 | 命令 | 预期结果 |
|------|------|------|
| ykman 可用 | `ykman --version` | ≥ 4.0 |
| pcscd 运行 | `systemctl status pcscd` | active (running) |
| YubiKey 识别 | `ykman info` | 显示设备型号和序列号 |
| PIV 接口正常 | `ykman piv info` | 显示 Slot 9a 信息 |
| 非 root 可访问 | `su - it-admin -c 'ykman info'` | 不需要 sudo |
| OpenSSL 可用 | `openssl version` | ≥ 1.1.1 |
| 工作目录就绪 | `ls /opt/yubikey-signer/` | 显示 keys/ manifests/ logs/ |

---

## 3. YubiKey 初始化

本章描述如何在可信服务器上将一把全新 YubiKey 初始化为可用的 SO 令牌。

### 3.1 出厂状态

一把全新 YubiKey 的 PIV 默认状态：

| 属性 | 出厂值 |
|------|------|
| Slot 9a 密钥算法 | ECDSA P-256（**不用，要删掉换成 RSA-2048**） |
| PIV PIN | `123456` |
| PIV PUK | `12345678` |
| Management Key | `010203040506070801020304050607080102030405060708`（48 字节 hex） |
| PIV PIN 剩余尝试次数 | 3 |
| PIV PUK 剩余尝试次数 | 无限 |

### 3.2 操作流程

**执行位置**：可信服务器  
**执行人**：IT 管理员  
**每把 YubiKey 执行一次**，约 3 分钟。

```bash
# =============================================
# 步骤 1: 插入 YubiKey，验证基本信息
# =============================================
ykman info
# 记录以下信息（用于后续审计）:
#   Device type: YubiKey 4
#   Serial number: 12345678
#   Firmware version: 4.3.4

# =============================================
# 步骤 2: 修改 PIV PIN 和 PUK
# =============================================

# 改 PIN（用户日常使用的 PIN）
ykman piv access change-pin --pin 123456 --new-pin <新PIN>
# 新 PIN: 6-8 位数字/字母，IT 管理员设定

# 改 PUK（解锁被锁 PIN 的管理密钥）
ykman piv access change-puk --puk 12345678 --new-puk <新PUK>
# 新 PUK: 8 位数字/字母

# =============================================
# 步骤 3: 删除 Slot 9a 出厂预置的 ECDSA 密钥
# =============================================
ykman piv delete 9a --pin <新PIN> --management-key 010203040506070801020304050607080102030405060708

# =============================================
# 步骤 4: 在 Slot 9a 生成 RSA-2048 密钥
# =============================================
ykman piv generate-key 9a -a RSA2048 \
    --pin "<新PIN>" \
    --management-key 010203040506070801020304050607080102030405060708

# =============================================
# 步骤 5: 生成自签名 X.509 证书（公钥载体，证书内容不重要）
# =============================================
ykman piv generate-certificate 9a \
    -s "CN=TBox SO Dongle $(ykman info | grep 'Serial number' | awk '{print $NF}')" \
    - \
    --pin "<新PIN>" \
    --management-key 010203040506070801020304050607080102030405060708

# =============================================
# 步骤 6: 验证 Slot 9a 已是 RSA-2048
# =============================================
ykman piv info
# 预期输出中 Slot 9a 行:
#   Algorithm: RSA2048
#   Subject DN: CN=TBox SO Dongle 12345678

# =============================================
# 步骤 7: 提取 RSA 公钥 DER
# =============================================
SERIAL=$(ykman info | grep 'Serial number' | awk '{print $NF}')

ykman piv export-certificate 9a - \
    | openssl x509 -pubkey -noout \
    | openssl pkey -pubin -outform DER \
    > /opt/yubikey-signer/manifests/yk-${SERIAL}-pub.der

# 验证公钥大小（RSA-2048 约 294 字节）
wc -c /opt/yubikey-signer/manifests/yk-${SERIAL}-pub.der
# 预期: ~294

# =============================================
# 步骤 8: 计算 SHA-256(公钥 DER)
# =============================================
sha256sum /opt/yubikey-signer/manifests/yk-${SERIAL}-pub.der \
    | awk '{print $1}' \
    > /opt/yubikey-signer/manifests/yk-${SERIAL}.hash

cat /opt/yubikey-signer/manifests/yk-${SERIAL}.hash
# 输出: 64 字符 hex（SHA-256 哈希值）

# =============================================
# 步骤 9: 测试 RSA 签名（自检验证——关键！）
# =============================================

# 9a. 生成测试数据
echo -n "test-challenge-$(date +%s)" | openssl dgst -sha256 -binary \
    > /tmp/tb-test-digest.bin

# 9b. YubiKey 签名
ykman piv sign 9a -s SHA256 /tmp/tb-test-digest.bin /tmp/tb-test-sig.der \
    --pin "<新PIN>"

# 9c. OpenSSL 验证签名
openssl dgst -sha256 -verify \
    <(openssl pkey -pubin -inform DER \
        -in /opt/yubikey-signer/manifests/yk-${SERIAL}-pub.der -pubout) \
    -signature /tmp/tb-test-sig.der \
    /tmp/tb-test-digest.bin
# 预期: Verified OK

# 如果不通过，检查步骤 4-5 是否正确执行

# =============================================
# 步骤 10: 拔掉 YubiKey，交还安全官员
# 记录: 序列号、初始化日期、PIV PIN/PUK（密封保管）
# =============================================

# 清理临时文件
rm -f /tmp/tb-test-digest.bin /tmp/tb-test-sig.der
```

> **重要**：第 9 步自检**必须通过**才能放行 YubiKey。它验证了"YubiKey 签名 → OpenSSL 验签"这条链，而 TA 内部的 `crypto_rsa_verify` 与 OpenSSL 执行相同的 RSA-2048 SHA-256 验签算法（均遵循 PKCS#1 v1.5），因此自检通过 = TA 验签也将通过。

---

## 4. 可信服务器密钥

可信服务器需要一对 RSA-2048 密钥，用于签名 manifest。私钥在服务器上，公钥硬编码进 TA。

### 4.1 生成密钥对

**执行位置**：可信服务器  
**执行一次**（服务器初始化时）

```bash
# 1. 生成 RSA-2048 私钥
openssl genpkey -algorithm RSA \
    -out /opt/yubikey-signer/keys/manifest_key.pem \
    -pkeyopt rsa_keygen_bits:2048

# 2. 提取公钥 DER（将硬编码进 TA 源码）
openssl rsa -pubout \
    -in /opt/yubikey-signer/keys/manifest_key.pem \
    -outform DER \
    -out /opt/yubikey-signer/keys/manifest_key_pub.der

# 3. 验证公钥大小
wc -c /opt/yubikey-signer/keys/manifest_key_pub.der
# 预期: ~294 字节

# 4. 验证密钥可用
echo "test" | openssl dgst -sha256 -sign /opt/yubikey-signer/keys/manifest_key.pem \
    > /tmp/test.sig
openssl dgst -sha256 -verify \
    <(openssl rsa -pubin -inform DER -in /opt/yubikey-signer/keys/manifest_key_pub.der -pubout) \
    -signature /tmp/test.sig <(echo "test")
# 预期: Verified OK
rm /tmp/test.sig
```

### 4.2 私钥保护

```bash
# 仅 root 可读
sudo chown root:root /opt/yubikey-signer/keys/manifest_key.pem
sudo chmod 400 /opt/yubikey-signer/keys/manifest_key.pem

# 建议: 额外 AES-256-CBC 加密，签名时手动输入密码
# openssl enc -aes-256-cbc -salt -pbkdf2 \
#     -in /opt/yubikey-signer/keys/manifest_key.pem \
#     -out /opt/yubikey-signer/keys/manifest_key.pem.enc
# （加密后的使用方式见附录 B 的 sign-manifest.sh）
```

### 4.3 公钥硬编码进 TA

新建 `ta/include/trusted_server_pubkey.h`：

```c
/*
 * RSA-2048 public key DER of the trusted provisioning server.
 * This key verifies the manifest signature: the manifest was
 * produced by the authorized IT administrator on the authorized
 * server.  Only manifests signed by the corresponding private
 * key are accepted by CMD_PROVISION_DONGLE_MANIFEST.
 */
static const uint8_t TRUSTED_SERVER_PUBKEY_DER[] = {
    /* Paste the xxd output of manifest_key_pub.der here.
     * Generate with: xxd -i manifest_key_pub.der
     * and replace the array content below. */
};
static const size_t TRUSTED_SERVER_PUBKEY_DER_LEN =
    sizeof(TRUSTED_SERVER_PUBKEY_DER);
```

### 4.4 本文档涉及的两种 RSA 密钥

存在两对完全独立的 RSA-2048 密钥，用途不同，不要混淆：

| 密钥对 | 私钥位置 | 公钥位置 | 作用 |
|------|------|------|------|
| **Manifest 签名密钥** | 可信服务器 `/opt/yubikey-signer/keys/manifest_key.pem` | TA 内硬编码 `TRUSTED_SERVER_PUBKEY_DER` | 签名 manifest；TA 验签证明"白名单确实来自可信服务器" |
| **YubiKey PIV Slot 9a 密钥** | YubiKey 硬件内部（永不导出） | manifest 白名单中（以 SHA-256 哈希形式存储） | 签名 challenge；TA 验签 + 白名单匹配证明"我持有已授权的 YubiKey" |

---

## 5. 白名单 Manifest 生成

### 5.1 准备工作

完成第 3 章（YubiKey 初始化）和第 4 章（可信服务器密钥）后，`/opt/yubikey-signer/` 目录结构如下：

```
/opt/yubikey-signer/
├── keys/
│   ├── manifest_key.pem          ← RSA-2048 私钥（签名用）
│   └── manifest_key_pub.der      ← RSA-2048 公钥（已硬编码进 TA）
├── manifests/
│   ├── yk-12345678-pub.der       ← YubiKey#0 公钥 DER
│   ├── yk-12345678.hash          ← YubiKey#0 SHA-256(公钥)
│   ├── yk-87654321-pub.der       ← YubiKey#1 公钥 DER
│   ├── yk-87654321.hash          ← YubiKey#1 SHA-256(公钥)
│   └── (每把 YubiKey 各 2 个文件)
└── logs/
    └── signing.log
```

### 5.2 构建 Manifest JSON

**执行位置**：可信服务器  
**执行人**：IT 管理员

```bash
cat > /opt/yubikey-signer/manifests/manifest_v1.json << 'EOF'
{
    "version": 1,
    "timestamp": TIMESTAMP_PLACEHOLDER,
    "generated_by": "trusted-server-01",
    "comment": "Production batch 2026-Q3, 2 YubiKeys (RSA-2048)",
    "dongles": [
        {
            "index": 0,
            "serial": SERIAL_0_PLACEHOLDER,
            "role": "primary-so",
            "pubkey_sha256": "HASH_0_PLACEHOLDER"
        },
        {
            "index": 1,
            "serial": SERIAL_1_PLACEHOLDER,
            "role": "backup-so",
            "pubkey_sha256": "HASH_1_PLACEHOLDER"
        }
    ]
}
EOF

# 填入实际值
TIMESTAMP=$(date +%s)
SERIAL_0=12345678
HASH_0=$(cat /opt/yubikey-signer/manifests/yk-${SERIAL_0}.hash)
SERIAL_1=87654321
HASH_1=$(cat /opt/yubikey-signer/manifests/yk-${SERIAL_1}.hash)

sed -i "s/TIMESTAMP_PLACEHOLDER/$TIMESTAMP/" \
    /opt/yubikey-signer/manifests/manifest_v1.json
sed -i "s/SERIAL_0_PLACEHOLDER/$SERIAL_0/" \
    /opt/yubikey-signer/manifests/manifest_v1.json
sed -i "s/HASH_0_PLACEHOLDER/$HASH_0/" \
    /opt/yubikey-signer/manifests/manifest_v1.json
sed -i "s/SERIAL_1_PLACEHOLDER/$SERIAL_1/" \
    /opt/yubikey-signer/manifests/manifest_v1.json
sed -i "s/HASH_1_PLACEHOLDER/$HASH_1/" \
    /opt/yubikey-signer/manifests/manifest_v1.json
```

### 5.3 生成二进制 Manifest 并签名

```bash
cd /opt/yubikey-signer

# 1. JSON → 二进制 manifest（使用附录 A gen-manifest.sh）
./gen-manifest.sh manifests/manifest_v1.json manifests/manifest_v1.bin

# 2. RSA-2048 SHA-256 签名
openssl dgst -sha256 -sign keys/manifest_key.pem \
    -out manifests/manifest_v1.sig \
    manifests/manifest_v1.bin

# 3. 自检验证（用 TA 将要使用的公钥——这是 TA 验签的预演）
openssl dgst -sha256 -verify \
    <(openssl rsa -pubin -inform DER -in keys/manifest_key_pub.der -pubout) \
    -signature manifests/manifest_v1.sig \
    manifests/manifest_v1.bin
# 预期: Verified OK
# ⚠ 如果不通过 → 检查私钥/公钥是否匹配 → 不要分发 manifest

# 4. 记录审计日志
MANIFEST_SHA256=$(sha256sum manifests/manifest_v1.bin | awk '{print $1}')
echo "$(date -Iseconds) | manifest_v1.bin | sha256=$MANIFEST_SHA256 | dongles=2 | operator=it-admin | status=OK" \
    >> logs/signing.log
```

---

## 6. 产线灌装

### 6.1 交付物

从可信服务器交付到工控机的文件：

| 文件 | 大小 | 内容 | 涉密？ | 传输方式 |
|------|:--:|------|:--:|------|
| `manifest_v1.bin` | 12 + N×40 字节 | 二进制白名单（版本号、时间戳、公钥哈希列表） | 否 | SCP/U盘/邮件 |
| `manifest_v1.sig` | 256 字节 | RSA-2048 SHA-256 签名 | 否 | 同上 |
| `batch-so-pin.txt` | 32 字节 hex | 本批次 SO-PIN | **是** | 安全官员→GPG→产线负责人 |

**关于 SO-PIN**：SO-PIN 由安全官员在**自己的离线笔记本**上用 `openssl rand -hex 32` 生成，通过 GPG 加密邮件发给产线负责人。可信服务器不生成 SO-PIN，安全官员与 IT 管理员职责分离。

### 6.2 工控机准备工作

工控机上创建临时工作目录 `/factory/`，灌装完成后销毁：

```
/factory/
├── manifest_v1.bin           # 可信服务器签名后的白名单
├── manifest_v1.sig           # RSA-2048 签名
├── batch-so-pin.txt          # 批次 SO-PIN（涉密）
├── devices.txt               # TBox 设备序列号列表
└── provision_batch.sh        # 灌装脚本
```

#### devices.txt 格式

纯文本，每行一个 TBox 序列号：

```
TBOX-PROD-2026Q3-00001
TBOX-PROD-2026Q3-00002
TBOX-PROD-2026Q3-00003
```

从产线 MES 系统导出，共 N 行（本批次设备数量）。

### 6.3 批量灌装脚本

```bash
#!/bin/bash
# /factory/provision_batch.sh
# 工控机上执行，循环灌装每台 TBox
set -e

MANIFEST_BIN="/factory/manifest_v1.bin"
MANIFEST_SIG="/factory/manifest_v1.sig"
SO_PIN=$(cat /factory/batch-so-pin.txt)
DEVICES="/factory/devices.txt"
LOG="/factory/provision-$(date +%Y%m%d-%H%M%S).log"

log() { echo "$@" | tee -a "$LOG"; }

log "=========================================="
log " TBox Batch Provisioning"
log " Manifest: $(basename $MANIFEST_BIN)"
log " Devices:  $(wc -l < $DEVICES) units"
log "=========================================="

PASS=0
FAIL=0

for device in $(cat "$DEVICES"); do
    log ""
    log "--- [$device] ---"

    # 每设备独立的 Provisioning PIN
    DEV_PIN=$(openssl rand -hex 16)

    # [1/6] 写入 Provisioning PIN
    log "  [1/6] Init PIN..."
    ssh root@${device} tbox_keystore --init-pin "$DEV_PIN"
    log "  [1/6] ✓"

    # [2/6] 生成 RSA 设备身份密钥
    log "  [2/6] Generate RSA key..."
    ssh root@${device} tbox_keystore --gen-rsa device-key \
        --size 2048 --sign --decrypt
    log "  [2/6] ✓ RSA-2048: device-key"

    # [3/6] 生成 AES OTA 密钥
    log "  [3/6] Generate AES key..."
    ssh root@${device} tbox_keystore --gen-aes ota-key \
        --size 256 --decrypt
    log "  [3/6] ✓ AES-256: ota-key"

    # [4/6] 导出设备公钥
    log "  [4/6] Export device public key..."
    ssh root@${device} tbox_keystore --export-pub device-key \
        --out /tmp/${device}-device-key.pub
    scp root@${device}:/tmp/${device}-device-key.pub /factory/keys/
    log "  [4/6] ✓"

    # [5/6] 灌装 SO-PIN + 签名白名单
    log "  [5/6] Provision SO-PIN + dongle manifest..."

    ssh root@${device} tbox_keystore --init-so-pin "$SO_PIN"

    scp "$MANIFEST_BIN" root@${device}:/tmp/manifest.bin
    scp "$MANIFEST_SIG" root@${device}:/tmp/manifest.sig

    # TA 内部: RSA_Verify(manifest, sig, TRUSTED_SERVER_PUBKEY)
    # 验签通过 → 白名单写入 SO_DONGLE_UUID 安全存储
    # 验签失败 → 拒绝 (TEE_ERROR_SIGNATURE_INVALID)
    ssh root@${device} tbox_keystore --provision-dongle-manifest \
        /tmp/manifest.bin /tmp/manifest.sig

    ssh root@${device} rm /tmp/manifest.bin /tmp/manifest.sig
    log "  [5/6] ✓"

    # [6/6] 锁定 TA
    log "  [6/6] Locking TA..."
    ssh root@${device} tbox_keystore --lock
    log "  [6/6] ✓ TA locked"

    PASS=$((PASS + 1))
    log "  ✅ [$device] Done ($PASS/$((PASS + FAIL)))"
done

log ""
log "=========================================="
log " Provisioning complete"
log " Pass: $PASS  Fail: $FAIL"
log "=========================================="

exit $FAIL
```

### 6.4 灌装后清理

```bash
# 1. 安全擦除涉密文件
shred -u /factory/batch-so-pin.txt

# 2. 签名文件可保留或删除（不涉密）
# rm /factory/manifest_v1.bin /factory/manifest_v1.sig

# 3. 归档灌装日志
cp /factory/provision-*.log /archive/provision-logs/
```

---

## 7. SO 解锁流程

### 7.1 协议总览

```
安全官员            TBox CA (REE)              TBox TA (TEE)            安全存储
────────            ────────────               ────────────             ────────

① 插入 YubiKey
   (USB)

② 输入 SO-PIN      ③ ──CMD_SO_UNLOCK_REQ──▶
                                                                    ④ SHA-256(PIN)
                                                                       与 SO_PIN_UUID 比较 ✓
                                                                    ⑤ 检查失败计数器
                                                                       检查冷却期 ✓
                                                                    ⑥ TEE_GenerateRandom()
                                                                       → challenge[32]
                                                                    ⑦ 读 SO_DONGLE_UUID
                                                                       → dongle_list
                       ◀──challenge + dongle_list──

                    ⑧ SHA-256(challenge)
                       → chg_hash[32]

                    ⑨ YubiKey 签名:         ← PIV Slot 9a
                       ykman piv sign 9a        RSA-2048 私钥
                       -s SHA256 chg_hash
                       → sig_der (256 B)

                    ⑩ 读 YubiKey 公钥:
                       ykman piv export-cert 9a
                       → pubkey_der (~294 B)

                    ⑪ ──CMD_SO_UNLOCK_CONFIRM──▶
                       param[0]: pubkey_der
                       param[1]: sig_der
                                                                    ⑫ 步骤 A: RSA-2048 验签
                                                                       crypto_rsa_verify(
                                                                         pubkey_der,
                                                                         chg_hash,
                                                                         sig_der)
                                                                       → 签名有效 ✓
                                                                        → 签名无效 ✗ → 拒绝

                                                                    ⑬ 步骤 B: 白名单匹配
                                                                       SHA-256(pubkey_der)
                                                                       ∈ 白名单[0..N] ?
                                                                       → 匹配 ✓
                                                                       → 不匹配 ✗ → 拒绝

                                                                    ⑭ 步骤 A ∧ 步骤 B 全满足
                                                                       → UNLOCKED
                                                                       失败计数器重置
                                                                       写保护解除

                       ◀──UNLOCKED──
```

### 7.2 命令行操作

**执行位置**：TBox  
**执行人**：安全官员（只做物理插拔 + 输入 SO-PIN）

```bash
# 安全官员将 YubiKey 插入 TBox USB 口

tbox_keystore --so-unlock --so-pin <SO-PIN> --dongle yubikey
# 预期输出:
#   TA challenge received. 2 dongle(s) registered.
#   [yubikey] Detected: YubiKey 4 (serial=12345678)
#   [dongle] Using: yubikey
#   ✓ SO unlock successful. TA is now UNLOCKED.
#     Remember: run --so-lock when maintenance is complete.

# 执行维护操作（密钥轮换等）
tbox_keystore --delete old-key
tbox_keystore --gen-rsa new-key --size 2048 --sign --decrypt

# 维护完成，重新锁定
tbox_keystore --so-lock
# TA re-locked. Write operations disabled.

# 安全官员拔掉 YubiKey
```

### 7.3 TA 内部核心逻辑

`ta/so_pin_mgr.c` 中的 `so_unlock_confirm()`——**整个安全模型的核心**：

```c
TEE_Result so_unlock_confirm(const uint8_t *pubkey_der, size_t der_len,
                             const uint8_t *sig_der,   size_t sig_len,
                             const uint8_t *challenge)
{
    TEE_ObjectHandle rsa_key = TEE_HANDLE_NULL;
    uint8_t pk_hash[32];
    uint8_t chg_hash[32];
    TEE_Result res;

    /* ---- 步骤 A: 导入公钥 + RSA-2048 SHA-256 验签 ---- */
    res = rsa_import_pubkey_from_der(pubkey_der, der_len, &rsa_key);
    if (res != TEE_SUCCESS)
        return res;

    res = so_sha256(challenge, 32, chg_hash, sizeof(chg_hash));
    if (res != TEE_SUCCESS)
        goto out;

    /* crypto_rsa_verify: OP-TEE 3.2 原生支持，PKCS#1 v1.5 SHA-256 */
    res = crypto_rsa_verify(rsa_key, 2048, chg_hash, 32, sig_der, sig_len);
    TEE_FreeTransientObject(rsa_key);
    rsa_key = TEE_HANDLE_NULL;

    if (res != TEE_SUCCESS) {
        EMSG("SO confirm: RSA signature INVALID");
        so_record_failure();
        return TEE_ERROR_SIGNATURE_INVALID;
    }

    /* ---- 步骤 B: SHA-256(pubkey) ∈ 白名单 ---- */
    res = so_sha256(pubkey_der, der_len, pk_hash, sizeof(pk_hash));
    if (res != TEE_SUCCESS)
        return res;

    struct so_dongle_list dl;
    so_dongle_load(&dl);

    for (uint32_t i = 0; i < dl.count; i++) {
        if (memcmp(pk_hash, dl.entries[i].pubkey_hash, 32) == 0) {
            /* 步骤 A ∧ 步骤 B 全部通过 → 原子解锁 */
            DMSG("SO unlock: RSA verified + whitelist[%u] matched → UNLOCKED", i);
            so_reset_consecutive();
            g_so_state = SO_STATE_UNLOCKED;
            // 持久化 SO_LOCK_UUID = 1
            { uint8_t f = 1; so_obj_delete(&SO_LOCK_UUID);
              so_obj_create(&SO_LOCK_UUID, &f, 1); }
            return TEE_SUCCESS;
        }
    }

    EMSG("SO confirm: pubkey NOT in whitelist (RSA sig was valid, but YubiKey not authorized)");
    so_record_failure();
    return TEE_ERROR_ACCESS_DENIED;
}
```

**关键保证**：步骤 A（RSA 验签，证明持有 YubiKey）和步骤 B（白名单匹配，证明 YubiKey 已授权）在**同一个 TA 函数中**执行，中间没有 CA（REE）可以切断的环节。步骤 A 失败 → 函数提前返回；步骤 A 通过 + 步骤 B 通过 → 解锁；步骤 A 通过 + 步骤 B 失败 → 也拒绝。

---

## 8. 安全分析

### 8.1 攻击者模型

| 攻击者 | 知道 SO-PIN？ | 有白名单中 YubiKey？ | 能替换 CA？ | 结果 | 原因 |
|------|:--:|:--:|:--:|------|------|
| 远程攻击者（网络） | 否 | — | — | **拒绝** | SO-PIN 在 TA 内 SHA-256 比对 |
| 工控机操作员 | 可能（经手 SO-PIN） | 否 | — | **拒绝** | 无 YubiKey 私钥，TA 验签失败 |
| 安全官员（有心作恶） | 是 | 只有自己的 YubiKey（在白名单中） | — | **合法通过** | 持有授权 YubiKey |
| 安全官员（有心作恶） | 是 | 尝试用未授权 YubiKey | — | **拒绝** | RSA 验签通过（YubiKey 真），但白名单不匹配 |
| 攻击者替换了 CA 二进制 | 是 | 否 | 是 | **拒绝** | CA 可跳过 YubiKey 调用，但**无法伪造 RSA 签名**——TA 验签失败 |
| 攻击者替换了 CA 二进制 | 是 | 知道 pubkey_der（从 manifest.bin 明文） | 是 | **拒绝** | 知道公钥 ≠ 持有私钥——RSA 验签失败 |
| IT 管理员 | — | 是（物理接触） | — | **可能** | 唯一高权限角色，依赖双人操作 + 审计日志约束 |
| 合法安全官员维护操作 | 是 | 是（授权 YubiKey） | — | **通过** ✓ | — |

### 8.2 关键保证

TA 内部安全存储了三样东西：

| 持久化对象 | 内容 | 谁写入 | TA 如何验证 |
|------|------|------|------|
| `SO_PIN_UUID` | SHA-256(SO-PIN) | `CMD_SO_PIN_INIT` | `CMD_SO_UNLOCK_REQ` 中比对 |
| `SO_DONGLE_UUID` | manifest 白名单 | `CMD_PROVISION_DONGLE_MANIFEST`（需可信服务器 RSA 签名） | `CMD_SO_UNLOCK_CONFIRM` 中 `SHA-256(pubkey) ∈ 白名单` |
| `SO_FAIL_UUID` | 失败计数器 | `so_pin_mgr.c` 内部 | 冷却期 / BRICKED 检查 |

TA 在 `CMD_SO_UNLOCK_CONFIRM` 中同时验证三项——SO-PIN（步骤 4）、RSA 签名（步骤 12A）、白名单（步骤 12B）——缺一不可。

---

## 9. TA 侧改动清单

| 文件 | 改动 | 内容 |
|------|:--:|------|
| `tbox_keystore_ta.h` | 小 | 新增 `CMD_PROVISION_DONGLE_MANIFEST`(19) + `CMD_SO_UNLOCK_CONFIRM`(18) 带 pubkey+sig 参数 |
| `so_pin_mgr.c` | 大 | 新增 `so_provision_dongle_manifest()`：RSA 验签 manifest + 原子替换白名单 + 版本号持久化<br>新增 `so_unlock_confirm()`：RSA 验签 + 白名单匹配原子操作 |
| `crypto_ops.c` | 中 | 新增 `rsa_import_pubkey_from_der()`：将 DER 格式 RSA-2048 公钥导入为 `TEE_ObjectHandle`（使用 `TEE_ATTR_RSA_MODULUS` + `TEE_ATTR_RSA_PUBLIC_EXPONENT`） |
| `entry.c` | 小 | 新增 2 个 cmd handler + dispatch |
| `trusted_server_pubkey.h` | 新建 | 硬编码可信服务器 RSA-2048 公钥 DER |
| `sub.mk` | +1 行 | — |

**不在 TA 侧改动**：`acl.c`、`keystore.c`、`pin_mgr.c`（不动）。

### rsa_import_pubkey_from_der 实现要点

RSA-2048 公钥 DER 结构是 `SEQUENCE { INTEGER(n), INTEGER(e) }`（PKCS#1 RSAPublicKey）。需要解析 DER 提取 modulus 和 public exponent，然后用 `TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY, 2048, ...)` + `TEE_PopulateTransientObject` 导入。与 ECDSA 公钥导入失败的原因不同——OP-TEE 3.2 支持 RSA 公钥的 transient object 分配和填充（RSA 是项目中已使用的算法）。

---

## 10. CA 侧改动清单

| 文件 | 改动 | 内容 |
|------|:--:|------|
| `keystore_client.c` | 中 | `--provision-dongle-manifest <bin> <sig>`：读取 manifest 文件 + 签名文件，打包传给 TA<br>`--so-unlock` 更新：读 YubiKey 公钥 + 签名 → `CMD_SO_UNLOCK_CONFIRM(pubkey_der, sig_der)` |

---

## 11. 实施步骤

| 步骤 | 内容 | 负责人 | 周期 |
|:--:|------|------|:--:|
| 1 | 采购 + 部署可信服务器（硬件 + LUKS + §2.3-2.5 软件安装） | IT 管理员 | 1 天 |
| 2 | 生成 manifest 签名 RSA 密钥对 + 公钥硬编码进 TA（§4） | 安全工程师 | 0.5 天 |
| 3 | 初始化每把 YubiKey（§3.2，改 PIN/PUK + 删 ECDSA + 生成 RSA-2048 + 自检） | IT 管理员 | 0.5 天/把 |
| 4 | 生成签名 manifest + 交付产线（§5-6） | IT 管理员 | 0.5 天 |
| 5 | TA 实现 `CMD_PROVISION_DONGLE_MANIFEST` + `CMD_SO_UNLOCK_CONFIRM`（RSA 版）（§9） | 安全工程师 | 4 天 |
| 6 | TA 实现 `rsa_import_pubkey_from_der()` | 安全工程师 | 包含于步骤 5 |
| 7 | CA 实现对应 CLI 命令（§10） | 安全工程师 | 1 天 |
| 8 | 测试环境端到端验证（灌装 + SO 解锁 + 错误路径） | 全员 | 2 天 |
| 9 | 产线试运行（与现有流程并行） | 产线 | 1 周 |

**总工期**：约 3 周。

---

## 12. 信息流转总图

```
┌─────────────────────────────────────────────────────────────────────────┐
│                   阶段 A: 灌装（一次性, 每批次 YubiKey）                    │
│                                                                         │
│  YubiKey 出厂  ──▶  可信服务器  ──▶  manifest.bin + .sig                │
│  (全新)             IT 管理员          (RSA-2048 签名)                    │
│                     ① 改 PIN/PUK                                        │
│                     ② 删 ECDSA, 生成 RSA-2048                            │
│                     ③ 提取公钥 → SHA-256                                 │
│                     ④ manifest 签名                                      │
│                                                                         │
│  manifest ──▶  工控机  ──▶  TBox TA                                     │
│  (安全通道)     (不可信)    ① RSA_Verify(manifest, sig, server_pubkey)   │
│                             ② 白名单 → SO_DONGLE_UUID                    │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│                   阶段 B: SO 解锁（日常维护, 每次维护执行一次）              │
│                                                                         │
│  安全官员  ──▶  TBox CA  ──▶  TBox TA                                   │
│  ① 插入 YubiKey  ③ CMD_SO_UNLOCK_REQ    ④ SHA-256(PIN) vs SO_PIN_UUID  │
│  ② 输入 SO-PIN       → challenge           ⑤ 检查失败计数器/冷却期        │
│                    ⑥ YubiKey 签名           ⑦ TEE_GenerateRandom→chg    │
│                       → sig_der             ⑧ 读白名单                   │
│                    ⑦ 读 YubiKey 公钥                                    │
│                       → pubkey_der                                       │
│                    ⑧ CMD_SO_UNLOCK_CONFIRM                              │
│                       (pubkey_der, sig_der)                              │
│                                             ⑨ crypto_rsa_verify(        │
│                                                   pubkey, chg, sig)     │
│                                                → 签名有效 ✓              │
│                                             ⑩ SHA-256(pubkey)           │
│                                                ∈ 白名单 ✓               │
│                                             ⑨∧⑩ → UNLOCKED             │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 附录 A：gen-manifest.sh

部署位置：`/opt/yubikey-signer/gen-manifest.sh`  
用途：将 JSON 格式的白名单描述转换为 TA 可解析的二进制 manifest

```bash
#!/bin/bash
# gen-manifest.sh — JSON → binary manifest
# Usage: ./gen-manifest.sh <manifest.json> <manifest.bin>
set -e
if [ $# -ne 2 ]; then echo "Usage: $0 <in.json> <out.bin>"; exit 1; fi
JSON="$1"; OUT="$2"
[ -f "$JSON" ] || { echo "ERROR: $JSON not found"; exit 1; }

V=$(jq -r '.version' "$JSON")
T=$(jq -r '.timestamp' "$JSON")
N=$(jq -r '.dongles | length' "$JSON")
echo "Manifest: v$V ts=$T dongles=$N"
[ "$N" -ge 1 ] || { echo "ERROR: empty dongles"; exit 1; }
[ "$N" -le 8 ] || { echo "ERROR: max 8 (got $N)"; exit 1; }

TMP=$(mktemp)
printf '%08x' "$V" | xxd -r -p | dd of="$TMP" bs=1 seek=0 conv=notrunc 2>/dev/null
printf '%08x' "$T" | xxd -r -p | dd of="$TMP" bs=1 seek=4 conv=notrunc 2>/dev/null
printf '%08x' "$N" | xxd -r -p | dd of="$TMP" bs=1 seek=8 conv=notrunc 2>/dev/null

OFF=12
for i in $(seq 0 $((N-1))); do
    H=$(jq -r ".dongles[$i].pubkey_sha256" "$JSON")
    S=$(jq -r ".dongles[$i].serial" "$JSON")
    [ "${#H}" -eq 64 ] || { echo "ERROR: dongle[$i] hash len=${#H}"; rm -f "$TMP"; exit 1; }
    echo "$H" | xxd -r -p | dd of="$TMP" bs=1 seek=$OFF conv=notrunc 2>/dev/null; OFF=$((OFF+32))
    printf '%08x' "$S" | xxd -r -p | dd of="$TMP" bs=1 seek=$OFF conv=notrunc 2>/dev/null; OFF=$((OFF+4))
    printf '%08x' 0  | xxd -r -p | dd of="$TMP" bs=1 seek=$OFF conv=notrunc 2>/dev/null; OFF=$((OFF+4))
    echo "  [$i] hash=${H:0:16}... serial=$S"
done
mv "$TMP" "$OUT"
echo "✓ $OUT ($((12+N*40)) bytes)"
```

## 附录 B：sign-manifest.sh

部署位置：`/opt/yubikey-signer/sign-manifest.sh`  
用途：RSA-2048 SHA-256 签名 + 自检 + 审计日志

```bash
#!/bin/bash
# sign-manifest.sh — RSA sign + audit
# Usage: ./sign-manifest.sh <manifest.bin>
set -e
M="$1"; [ -n "$M" ] || { echo "Usage: $0 <manifest.bin>"; exit 1; }
[ -f "$M" ] || { echo "ERROR: $M not found"; exit 1; }

KEY="/opt/yubikey-signer/keys/manifest_key.pem"
SIG="${M}.sig"
VK="/opt/yubikey-signer/keys/manifest_key_pub.der"
LOG="/opt/yubikey-signer/logs/signing.log"
[ -f "$KEY" ] || { echo "ERROR: $KEY not found"; exit 1; }

echo "Signing: $(basename $M)"
openssl dgst -sha256 -sign "$KEY" -out "$SIG" "$M"
echo "  → $(basename $SIG) ($(wc -c < $SIG) bytes)"

echo -n "Verify: "
if openssl dgst -sha256 -verify <(openssl rsa -pubin -inform DER -in "$VK" -pubout) \
    -signature "$SIG" "$M" >/dev/null 2>&1; then
    echo "OK"
else
    echo "FAILED — DO NOT DISTRIBUTE"; rm -f "$SIG"; exit 1
fi

mkdir -p "$(dirname "$LOG")"
echo "$(date -Iseconds) | $(basename $M) | sha256=$(sha256sum $M | awk '{print $1}') | op=${SUDO_USER:-$USER} | OK" >> "$LOG"
echo "  Audit: $LOG"
```

## 附录 C：Manifest 二进制格式

TA 解析 `manifest.bin` 使用的格式，little-endian 字节序：

```
偏移    长度    字段          说明
0       4       version        uint32 LE, 单调递增 ≥ 1
4       4       timestamp      uint32 LE, Unix 时间戳
8       4       count          白名单条目数 (1-8)
12     40×N     entries[]      每条 40 字节

条目格式 (40 字节):
  偏移  长度  字段
  0    32    pubkey_sha256    SHA-256(RSA-2048 pubkey DER)
  32    4    serial           uint32 LE, YubiKey 序列号
  36    4    reserved         保留 (填 0)

总大小: 12 + N × 40, max = 12 + 8 × 40 = 332 字节
```

版本号单调递增。TA 在 `SO_MANIFEST_VERSION_UUID` 中持久化当前版本号，拒绝低版本号的 manifest（Anti-rollback）。
