# 27 — 基于可信服务器的 YubiKey 灌装方案

## 摘要

当工控机为第三方维护且安全官员不可信时，将白名单签名权从产线完全移出，集中到一台**物理隔离的可信 Linux 服务器**。这台服务器代替 §26 方案 C 中的云端 SGX enclave，由 OEM IT 管理员直接管控。

**核心变化**：

- 安全官员：从"授权者"降级为"快递员"——只负责把 YubiKey 从采购带到机房，插上就走
- 工控机：完全不可信，只下载已签名白名单 + 搬运到 TBox
- 可信服务器：唯一授权方——读 YubiKey 公钥、SHA-256 哈希、RSA-2048 私钥签名白名单
- TA：硬编码可信服务器 RSA 公钥，验签白名单后才接受

```
采购 YubiKey
   │
   ▼
安全官员（快递员）→ 带到机房 → IT 管理员插到可信服务器
   │
   ▼
可信 Linux 服务器（唯一信任根）
  ├── ykman piv export-certificate 9a → pubkey DER
  ├── SHA-256(pubkey) → hash
  ├── 构建白名单 manifest
  ├── RSA-2048 私钥签名
  └── 输出: manifest.bin + manifest.sig
   │
   │  安全通道传输（U盘/加密邮件）
   ▼
工控机（不可信, 第三方）
  └── 下载/拷贝 manifest.bin + manifest.sig
      └── 灌装: --provision-dongle-manifest
   │
   ▼
TBox TA
  └── RSA_Verify(manifest, sig, trusted_server_pubkey)
      ├── ✓ → 白名单写入安全存储
      └── ✗ → 拒绝
```

---

## 1. 角色划分

| 角色 | 可信度 | 操作权限 | 说明 |
|------|:--:|------|------|
| **可信 Linux 服务器** | **唯一信任根** | 读 YubiKey 公钥, RSA 签名白名单 | 物理隔离 / 内网隔离 / 仅 IT 管理员访问 |
| **IT 管理员** | 半可信（操作守则约束） | 插拔 YubiKey, 执行签名脚本 | 双人操作、审计日志 |
| **安全官员** | **不可信** | 无——只负责带 YubiKey 到机房 | 快递员 |
| **工控机** | **不可信** | 无——只下载签名清单, 搬运到 TBox | 第三方维护 |
| **TBox TA** | 可信（ARM TrustZone） | 验签白名单, 写入安全存储 | 不可篡改 |

---

## 2. 可信服务器环境

### 2.1 硬件

| 要求 | 说明 |
|------|------|
| CPU | 任意 x86-64（无需 SGX），推荐 Intel NUC 或超微迷你服务器 |
| 内存 | ≥ 4 GB |
| 存储 | ≥ 128 GB SSD，全盘 LUKS 加密 |
| USB | ≥ 2 个 USB 2.0/3.0 端口 |
| 网络 | **物理断开**（离线操作）或仅连接隔离 VLAN，无互联网 |

### 2.2 操作系统

```bash
# Ubuntu Server 22.04 LTS (最小安装)
# 全盘加密: LUKS + LVM
# 仅安装必要软件包
```

### 2.3 软件安装

可信服务器操作系统为 **Ubuntu Server 22.04 LTS**，以下为完整安装步骤。

#### Linux (Ubuntu/Debian)

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

# 5. 安装 OpenSSL（用于解析公钥证书和 RSA 签名）
sudo apt install openssl

# 6. 安装签名脚本依赖
sudo apt install xxd jq

# 7. 插入 YubiKey 后验证识别
ykman piv info
# 如果能输出 PIV 信息 → 驱动安装成功
# 如果报 "No YubiKey detected" → 检查 pcscd 是否运行
```

### 2.4 USB 权限配置

Linux 下非 root 用户访问 YubiKey 需要配置 udev 规则（IT 管理员非 root 操作时必需）：

```bash
# 添加 udev 规则
sudo bash -c 'cat > /etc/udev/rules.d/70-yubikey.rules << EOF
# YubiKey 4/5 — CCID (PIV/OpenPGP)
SUBSYSTEM=="usb", ATTR{idVendor}=="1050", ATTR{idProduct}=="0407", MODE="0660", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="1050", ATTR{idProduct}=="0406", MODE="0660", GROUP="plugdev"
# YubiKey 5 NFC
SUBSYSTEM=="usb", ATTR{idVendor}=="1050", ATTR{idProduct}=="0402", MODE="0660", GROUP="plugdev"
EOF'

# 重新加载 udev
sudo udevadm control --reload-rules
sudo udevadm trigger

# 将 IT 管理员加入 plugdev 组
sudo usermod -a -G plugdev it-admin
# 注销重新登录后生效

# 验证权限（插入 YubiKey 后）
ykman piv info   # 不应要求 sudo
```

### 2.5 验证安装清单

所有软件安装完成后，逐一检查：

| 检查项 | 命令 | 预期结果 |
|------|------|------|
| ykman 可用 | `ykman --version` | ≥ 4.0 |
| pcscd 运行 | `systemctl status pcscd` | active (running) |
| YubiKey 识别 | `ykman info` | 显示设备型号和序列号 |
| PIV 接口正常 | `ykman piv info` | 显示 Slot 9a 信息（Algorithm: ECCP256） |
| USB 权限 | 非 root 运行 `ykman info` | 不需要 sudo |
| OpenSSL 可用 | `openssl version` | ≥ 1.1.1 |
| 签名目录存在 | `ls /opt/yubikey-signer/` | 显示 keys/ manifests/ logs/ 三个子目录 |

### 2.6 安全加固

```bash
# 1. 禁用网络（离线操作）
sudo systemctl stop NetworkManager
sudo systemctl disable NetworkManager

# 2. 仅允许 IT 管理员 SSH（如果留网络口）
# /etc/ssh/sshd_config:
#   PermitRootLogin no
#   AllowUsers it-admin
#   PasswordAuthentication no

# 3. 审计日志
sudo apt install auditd
sudo auditctl -w /opt/yubikey-signer/ -p wa -k yubikey_signer

# 4. 双人操作——物理钥匙 + 密码
# 服务器放在上锁机柜, 两把钥匙分给两人
```

### 2.7 签名脚本部署

```bash
# 在可信服务器上创建签名工作目录
sudo mkdir -p /opt/yubikey-signer/{keys,manifests,logs}
sudo chown -R it-admin:it-admin /opt/yubikey-signer

# 部署签名脚本（见 §4）
cp gen-manifest.sh sign-manifest.sh /opt/yubikey-signer/
chmod 700 /opt/yubikey-signer/*.sh
```

---

## 3. RSA 密钥生命周期

### 3.1 生成（一次性，在可信服务器上）

```bash
# 生成 RSA-2048 私钥（离线，物理隔离环境）
openssl genpkey -algorithm RSA -out /opt/yubikey-signer/keys/manifest_key.pem \
    -pkeyopt rsa_keygen_bits:2048

# 提取公钥（编译进 TA）
openssl rsa -pubout -in /opt/yubikey-signer/keys/manifest_key.pem \
    -outform DER -out /opt/yubikey-signer/keys/manifest_key_pub.der

# 验证
xxd /opt/yubikey-signer/keys/manifest_key_pub.der | head -5
```

### 3.2 私钥保护

```bash
# 私钥文件权限（仅 root 可读）
sudo chown root:root /opt/yubikey-signer/keys/manifest_key.pem
sudo chmod 400 /opt/yubikey-signer/keys/manifest_key.pem

# 建议额外加密：
# openssl enc -aes-256-cbc -salt \
#     -in manifest_key.pem -out manifest_key.pem.enc
# 解密密码由 IT 管理员手动输入（每次签名时）
```

### 3.3 公钥硬编码进 TA

`ta/so_pin_mgr.c` 或新建 `ta/trusted_server_pubkey.h`：

```c
/* RSA-2048 public key DER of the trusted provisioning server.
 * Generated once at server setup.  Only this key can sign valid
 * dongle manifests accepted by CMD_PROVISION_DONGLE_MANIFEST. */
static const uint8_t TRUSTED_SERVER_PUBKEY_DER[] = {
    /* paste xxd output of manifest_key_pub.der here */
};
static const size_t TRUSTED_SERVER_PUBKEY_DER_LEN =
    sizeof(TRUSTED_SERVER_PUBKEY_DER);
```

### 3.4 密钥轮换

| 场景 | 操作 |
|------|------|
| 私钥泄露 | 紧急生成新密钥对 → 重新编译 TA（公钥更新）→ 所有 TBox 重新灌装 |
| 定期轮换（2 年） | 同上，计划内维护 |
| 迁移备份 | 私钥加密后拷贝到离线 U 盘，U 盘存保险柜 |

---

## 4. 可信服务器操作流程

### 4.1 读取 YubiKey 公钥

**执行位置**：`[可信服务器]` — IT 管理员

```bash
# =============================================
# 1. 安全官员将 YubiKey 交给 IT 管理员
#    IT 管理员插入可信服务器 USB 口
# =============================================
# (物理操作)

# =============================================
# 2. 验证 YubiKey 真实性
# =============================================
[可信服务器]$ ykman info
# 核对序列号是否在采购清单中

# =============================================
# 3. 读取 Slot 9a 设备证书（含公钥）
# =============================================
[可信服务器]$ ykman piv export-certificate 9a - \
    > /opt/yubikey-signer/manifests/yk-$(ykman info | grep Serial | awk '{print $NF}').cer

# =============================================
# 4. ISM 提取纯公钥并计算哈希
# =============================================
[可信服务器]$ openssl x509 -pubkey -noout \
    -in /opt/yubikey-signer/manifests/yk-12345678.cer \
    | openssl pkey -pubin -outform DER \
    > /opt/yubikey-signer/manifests/yk-12345678-pub.der

[可信服务器]$ sha256sum /opt/yubikey-signer/manifests/yk-12345678-pub.der \
    | awk '{print $1}' \
    > /opt/yubikey-signer/manifests/yk-12345678.hash

# =============================================
# 5. 拔掉 YubiKey → 交还安全官员
# =============================================
```

### 4.2 签名白名单

**执行位置**：`[可信服务器]` — IT 管理员

```bash
# =============================================
# 1. 构建白名单 manifest（JSON 或二进制格式）
# =============================================
cat > /opt/yubikey-signer/manifests/manifest_v1.json << EOF
{
    "version": 1,
    "timestamp": $(date +%s),
    "generated_by": "trusted-server-01",
    "comment": "Production batch 2026-Q3, 2 YubiKeys",
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

# =============================================
# 2. 转换为二进制格式（TA 解析更简单）
# =============================================
# manifest.bin 格式:
#   [version:4][timestamp:4][count:4]
#   [entry0: hash[32] + serial[4] + reserved[4]]
#   [entry1: hash[32] + serial[4] + reserved[4]]
#   ...
# 由 gen-manifest.sh 脚本自动完成

[可信服务器]$ /opt/yubikey-signer/gen-manifest.sh \
    /opt/yubikey-signer/manifests/manifest_v1.json \
    /opt/yubikey-signer/manifests/manifest_v1.bin

# =============================================
# 3. RSA-2048 SHA-256 签名
# =============================================
[可信服务器]$ openssl dgst -sha256 -sign \
    /opt/yubikey-signer/keys/manifest_key.pem \
    -out /opt/yubikey-signer/manifests/manifest_v1.sig \
    /opt/yubikey-signer/manifests/manifest_v1.bin

# =============================================
# 4. 验证签名（自检）
# =============================================
[可信服务器]$ openssl dgst -sha256 -verify \
    /opt/yubikey-signer/keys/manifest_key_pub.der \
    -signature /opt/yubikey-signer/manifests/manifest_v1.sig \
    /opt/yubikey-signer/manifests/manifest_v1.bin
# 预期: Verified OK

# =============================================
# 5. 记录审计日志
# =============================================
[可信服务器]$ echo "$(date -Iseconds) | manifest_v1 | $(sha256sum manifest_v1.bin | awk '{print $1}') | IT-Admin:alice" \
    >> /opt/yubikey-signer/logs/signing.log
```

### 4.3 交付给工厂

**传输方式**（按安全要求选择）：

| 方式 | 适用 | 说明 |
|------|:--:|------|
| 加密 U 盘 | 常规 | IT 管理员亲手交给产线负责人 |
| SFTP（隔离 VLAN） | 有网络 | 可信服务器临时开网络口 → 推送到工厂 SFTP |
| 加密邮件 | 远程工厂 | `manifest_v1.bin.gpg` + `manifest_v1.sig.gpg` |

**不需要保密的内容**：`manifest.bin`（公钥哈希 + 序列号），只验签不加密。
**签名不可篡改**：工厂或安全官员修改 manifest.bin 任意字节 → TA 验签失败。

---

## 5. 产线灌装

### 5.1 准备工作

产线灌装前，工控机需要以下文件。这些文件由不同角色提前准备，通过**独立安全通道**传输到工控机。

#### 工控机目录结构

```
/factory/                        ← 工控机本地临时目录（灌装完成后擦除）
├── manifest_v1.bin              ← 可信服务器签名的白名单（公钥哈希等信息，不涉密）
├── manifest_v1.sig              ← 可信服务器 RSA-2048 签名（篡改即失效）
├── batch-so-pin.txt             ← 本批次 SO-PIN（32 字节 hex，涉密）
├── devices.txt                  ← 本批次 TBox 设备序列号列表
└── provision_batch.sh           ← 灌装脚本（本节内容）
```

#### 文件详解

| 文件 | 内容 | 谁生成 | 传输方式 | 涉密 |
|------|------|------|------|:--:|
| `manifest_v1.bin` | 二进制白名单：版本号 + 时间戳 + 每把 YubiKey 的 SHA-256(公钥) + 序列号 | 可信服务器 IT 管理员 | SCP / 加密 U 盘 / 加密邮件 | 否（公钥哈希不能反推私钥） |
| `manifest_v1.sig` | RSA-2048 SHA-256 签名（对 `manifest_v1.bin` 签名） | 可信服务器 IT 管理员 | 同上 | 否（无对应公钥无法验签） |
| `batch-so-pin.txt` | 32 字节 hex 字符串，本批次共用，例如 `f1e2d3c4b5a60718293a4b5c6d7e8f90` | **安全官员**在自己的离线笔记本上用 `openssl rand -hex 32` 生成 | GPG 加密邮件发给产线负责人；或密码管理器共享 | **是** |
| `devices.txt` | 每行一个 TBox 设备序列号，例如 `TBOX-PROD-00001` | 产线 MES 系统导出 | 工控机本地生成 / MES 下发 | 否 |

**为什么 SO-PIN 不由可信服务器生成**：
可信服务器的职责是"决定哪些 YubiKey 合法"。SO-PIN 是"掌握密码的那个人才能解锁"，属于安全官员的个人凭证。两者职责分离：服务器管硬件 YubiKey 白名单，安全官员管密码。即使服务器被攻破，没有 SO-PIN 也无法解锁设备。

### 5.2 下载签名清单

**执行位置**：`[工控机]` — 第三方维护，完全不可信

```bash
# =============================================
# 1. 在工控机上创建临时工作目录
# =============================================
[工控机]$ mkdir -p /factory
[工控机]$ cd /factory

# =============================================
# 2. 从可信服务器下载签名后的白名单
# =============================================
# 方式 A: SCP（可信服务器临时开网络口）
[工控机]$ scp -P 2222 it-admin@trusted-server:/opt/yubikey-signer/manifests/manifest_v1.bin .
[工控机]$ scp -P 2222 it-admin@trusted-server:/opt/yubikey-signer/manifests/manifest_v1.sig .

# 方式 B: 加密 U 盘（IT 管理员亲自交给产线负责人）
[工控机]$ mount /dev/sdb1 /mnt/usb
[工控机]$ cp /mnt/usb/manifest_v1.* .
[工控机]$ umount /mnt/usb

# 方式 C: 加密邮件附件（GPG 解密后拷贝到 /factory/）
# (工控机上执行)
[工控机]$ gpg --decrypt manifest_v1.bin.gpg > /factory/manifest_v1.bin
[工控机]$ cp /secure/location/manifest_v1.sig /factory/

# =============================================
# 3. 校验文件完整性（可选但建议）
# =============================================
[工控机]$ ls -la /factory/manifest_v1.*
# 检查文件大小：.bin 约 80-300 字节，.sig 约 256 字节

[工控机]$ sha256sum /factory/manifest_v1.bin
# 与可信服务器上的 sha256sum 比对（IT 管理员提前给出来）
```

**注意**：工控机只能拿到 `manifest_v1.bin` **明文**（公钥哈希 + 序列号），没有任何秘密。篡改任意字节 → TA 验签失败。不需要 GPG 加密传输。

### 5.3 准备其他灌装文件

**执行位置**：`[产线负责人笔记本]` 或 `[工控机]`

```bash
# =============================================
# 1. 部署 SO-PIN（产线负责人用安全官员给的密文解密）
# =============================================
# 安全官员通过 GPG 加密邮件发来 SO-PIN：
#   邮件内容: batch-so-pin.txt.gpg
#   加密给: 产线负责人的 GPG 公钥
#
# 产线负责人在自己笔记本上解密（不要直接在工控机上操作）:
[笔记本]$ gpg --decrypt batch-so-pin.txt.gpg > batch-so-pin.txt
# 内容示例（32 字节 hex）:
#   f1e2d3c4b5a60718293a4b5c6d7e8f90

# 将解密后的 SO-PIN 通过 USB 或临时网络传到工控机：
[笔记本]$ scp batch-so-pin.txt factory@workstation:/factory/

# =============================================
# 2. 准备设备列表（产线 MES 系统导出）
# =============================================
# devices.txt — 本批次待灌装的 TBox 设备序列号
# 每行一个序列号，例如：
#   TBOX-PROD-2026Q3-00001
#   TBOX-PROD-2026Q3-00002
#   TBOX-PROD-2026Q3-00003
#   ...

# 从 MES 导出：
[工控机]$ curl -s "http://mes.internal/api/devices?batch=2026Q3" \
    -H "Authorization: Bearer <token>" \
    | jq -r '.devices[].serial' > /factory/devices.txt

# 检查:
[工控机]$ wc -l /factory/devices.txt
# 预期: 本批次设备数量（如 5000）

# =============================================
# 3. 部署灌装脚本
# =============================================
[工控机]$ cp provision_batch.sh /factory/
[工控机]$ chmod +x /factory/provision_batch.sh
```

### 5.4 执行批量灌装

**执行位置**：`[工控机]` — 不可信

```bash
#!/bin/bash
# =============================================
# /factory/provision_batch.sh
# 本脚本在工控机上运行，通过串口连每台 TBox 执行灌装
# =============================================
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

PASS=0
FAIL=0

for device_serial in $(cat "$DEVICES"); do
    echo "" | tee -a "$LOG"
    echo "--- [$device_serial] Provisioning ---" | tee -a "$LOG"

    # ===========================================
    # 每台设备独立生成 Provisioning PIN
    # ===========================================
    # 每台设备的 Provisioning PIN 不同（设备身份凭证）；
    # SO-PIN 是同一批次共享的（安全官员身份凭证）。
    DEV_PIN=$(openssl rand -hex 16)
    # 确保 DEV_PIN=SO_PIN 不同
    if [ "$DEV_PIN" = "$SO_PIN" ]; then
        DEV_PIN=$(openssl rand -hex 16)
    fi

    # ===========================================
    # 连接设备（串口 / USB Ethernet / ADB）
    # ===========================================
    # 具体连接方式取决于产线工装——
    # 以下假设 tbox_keystore 命令已在 TBox 上部署，
    # 通过串口发送命令到 TBox。
    #
    # 简化写法：假设 TBox 已通过 USB Ethernet 接入工控机，
    # 设备 IP 从序列号映射得出：
    #   TBOX_IP=$(device_lookup $device_serial)
    #   CMD="ssh root@$TBOX_IP"

    # ⚠️ 实际产线需替换为真实 TBox 连接方式
    CMD=""   # 如果有 SSH: CMD="ssh root@$TBOX_IP"
              # 如果有串口: CMD="serial_send /dev/ttyUSB0"
              # 如果有 ADB: CMD="adb shell"

    # ===========================================
    # 步骤 1: 写入设备独立 Provisioning PIN
    # ===========================================
    echo "  [1/6] Init PIN..." | tee -a "$LOG"
    $CMD tbox_keystore --init-pin "$DEV_PIN"
    echo "  [1/6] ✓ PIN initialized" | tee -a "$LOG"

    # ===========================================
    # 步骤 2-3: 生成设备密钥
    # ===========================================
    echo "  [2/6] Generate RSA key..." | tee -a "$LOG"
    $CMD tbox_keystore --gen-rsa device-key --size 2048 --sign --decrypt
    echo "  [2/6] ✓ RSA-2048 key: device-key" | tee -a "$LOG"

    echo "  [3/6] Generate AES key..." | tee -a "$LOG"
    $CMD tbox_keystore --gen-aes ota-key --size 256 --decrypt
    echo "  [3/6] ✓ AES-256 key: ota-key" | tee -a "$LOG"

    # ===========================================
    # 步骤 4: 导出设备公钥（用于向 CA 签发证书）
    # ===========================================
    echo "  [4/6] Export public key..." | tee -a "$LOG"
    $CMD tbox_keystore --export-pub device-key --out /tmp/${device_serial}-device-key.pub
    # 将公钥文件从 TBox 拉到工控机存档
    # scp root@$TBOX_IP:/tmp/${device_serial}-device-key.pub /factory/keys/
    echo "  [4/6] ✓ Public key exported" | tee -a "$LOG"

    # ===========================================
    # 步骤 5: SO-PIN + 签名白名单灌装
    # ===========================================
    echo "  [5/6] Provision SO-PIN + dongle manifest..." | tee -a "$LOG"

    # 5a: 写入 SO-PIN
    $CMD tbox_keystore --init-so-pin "$SO_PIN"

    # 5b: 将签名白名单传到 TBox 临时目录
    scp "$MANIFEST_BIN" root@TBOX_IP:/tmp/manifest.bin
    scp "$MANIFEST_SIG" root@TBOX_IP:/tmp/manifest.sig

    # 5c: 灌装签名白名单（TA 内部 RSA 验签）
    #   TA 用硬编码的 TRUSTED_SERVER_PUBKEY 验签 manifest.bin
    #   → 验签通过：白名单写入安全存储（SO_DONGLE_UUID）
    #   → 验签失败：拒绝，返回 TEE_ERROR_SIGNATURE_INVALID
    $CMD tbox_keystore --provision-dongle-manifest \
        /tmp/manifest.bin \
        /tmp/manifest.sig

    # 5d: 擦除 TBox 上的临时文件
    $CMD rm /tmp/manifest.bin /tmp/manifest.sig
    echo "  [5/6] ✓ SO-PIN + dongle manifest provisioned" | tee -a "$LOG"

    # ===========================================
    # 步骤 6: 锁定 TA
    # ===========================================
    echo "  [6/6] Locking TA..." | tee -a "$LOG"
    $CMD tbox_keystore --lock
    echo "  [6/6] ✓ TA locked" | tee -a "$LOG"

    # ===========================================
    # 记录
    # ===========================================
    PASS=$((PASS + 1))
    echo "  ✅ [$device_serial] Done ($PASS/$((PASS+FAIL)))" | tee -a "$LOG"
done

# ===============================================
# 灌装完成
# ===============================================
echo "" | tee -a "$LOG"
echo "=========================================="  | tee -a "$LOG"
echo " Provisioning complete"                       | tee -a "$LOG"
echo " Pass: $PASS  Fail: $FAIL"                    | tee -a "$LOG"
echo "=========================================="  | tee -a "$LOG"

exit $FAIL
```

### 5.5 灌装后清理

**执行位置**：`[工控机]`

```bash
# =============================================
# 1. 擦除工控机上的涉密文件
# =============================================
# SO-PIN 是涉密文件，必须安全擦除
[工控机]$ shred -u /factory/batch-so-pin.txt

# =============================================
# 2. 签名清单可以保留或删除
# =============================================
# manifest_v1.bin 和 .sig 不涉密（公钥哈希 + 签名），
# 可以保留存档用于审计；
# 如果需要删除：
[工控机]$ shred -u /factory/manifest_v1.bin /factory/manifest_v1.sig

# =============================================
# 3. 归档灌装日志
# =============================================
[工控机]$ cp /factory/provision-*.log /archive/provision-logs/
[工控机]$ rm /factory/provision-*.log /factory/provision_batch.sh
```

**安全保证**：即使工控机上的 `manifest_v1.bin` 被篡改后传给 TA，TA 内部 RSA-2048 SHA-256 验签会立即发现签名不匹配并拒绝。工控机没有任何私钥，无法生成合法签名。

---

## 6. TA 侧实现

### 6.1 新增命令

在 `ta/include/tbox_keystore_ta.h` 中新增：

```c
/*
 * CMD_PROVISION_DONGLE_MANIFEST — Provision dongle whitelist
 * from trusted-server-signed manifest.
 * param[0] (memref) manifest binary
 * param[1] (memref) RSA-2048 SHA-256 signature
 */
#define CMD_PROVISION_DONGLE_MANIFEST  19
```

### 6.2 TA 处理逻辑

`ta/so_pin_mgr.c` 新增函数：

```c
/*
 * Provision the entire dongle whitelist from a signed manifest.
 *
 * manifest format:
 *   [version:4 LE][timestamp:4 LE][count:4 LE]
 *   [entry × count: hash[32] + serial[4] + reserved[4]]
 *
 * 1. Verify RSA-2048 SHA-256 signature using hardcoded trusted server pubkey
 * 2. Check version >= current stored version (anti-rollback)
 * 3. Atomically replace entire whitelist
 */
TEE_Result so_provision_dongle_manifest(
    const uint8_t *manifest, size_t manifest_len,
    const uint8_t *signature, size_t signature_len)
{
    // 1. Import hardcoded trusted server RSA public key
    //    (from TRUSTED_SERVER_PUBKEY_DER compile-time constant)

    // 2. crypto_rsa_verify(pubkey, 2048, manifest, manifest_len,
    //                      signature, signature_len)

    // 3. Parse manifest: check version, timestamp, count

    // 4. so_dongle_save() — atomically replace whitelist

    // 5. Update stored version for anti-rollback

    return TEE_SUCCESS;
}
```

### 6.3 防回滚

白名单 `manifest.version` 单调递增，TA 内部记录 `g_manifest_version` 到 `SO_MANIFEST_VERSION_UUID` 持久化对象。每次接受新 manifest → `version > g_manifest_version`。工厂不能用旧版本的白名单覆盖新版本。

---

## 7. 需要改动

| 层 | 文件 | 改动 | 说明 |
|------|------|------|------|
| **TA** | `tbox_keystore_ta.h` | +5 行 | `CMD_PROVISION_DONGLE_MANIFEST`(19) |
| **TA** | `so_pin_mgr.c` | +80 行 | `so_provision_dongle_manifest()` + 版本号持久化 |
| **TA** | `trusted_server_pubkey.h` | **新建** | 硬编码可信服务器 RSA 公钥 DER |
| **TA** | `entry.c` | +15 行 | cmd handler + dispatch |
| **CA** | `keystore_client.c` | +30 行 | `--provision-dongle-manifest` 命令 |
| **可信服务器** | `gen-manifest.sh` | **新建** | JSON → 二进制 manifest 转换脚本 |
| **可信服务器** | `sign-manifest.sh` | **新建** | RSA 签名脚本（含审计日志） |
| **工控机** | 灌装脚本 | 替换单条命令 | `--provision-dongle-from-file` → `--provision-dongle-manifest` |

**不涉及**：

- `dongle/` 目录 — 不动
- `dongle_test` — 不动
- `test_so_lifecycle.sh` — 不动
- 现有的 `--provision-dongle` 和 `--provision-dongle-from-file` — 保留，开发/调试继续用

---

## 8. 安全分析

### 8.1 威胁模型

| 攻击者 | 攻击 | 是否可防 | 机制 |
|------|------|:--:|------|
| 安全官员 | 用个人 YubiKey 调包 | ✓ | 只有 IT 管理员能操作可信服务器；安全官员物理上不接触服务器 |
| 工控机 | 替换 manifest 中的 pubkey hash | ✓ | RSA 签名验证 — TA 拒绝 |
| 工控机 | 重放旧版本 manifest | ✓ | 版本号 anti-rollback |
| 工控机 | 注入额外非法 YubiKey | ✓ | 同上 |
| 工控机 | 拒绝服务（不发灌装命令） | ✗ | 无解（但无安全影响，只能物理阻止出厂） |
| IT 管理员 | 恶意签名 | ✗ 部分 | 双人操作 + 审计日志可追溯；无技术手段防止管理员作恶 |
| 可信服务器被盗 | 私钥泄露 | ✗ | 物理安全 + 全盘加密；应急密钥轮换流程 |

### 8.2 与 §26 方案对比

| 维度 | §26 方案 C（云端 SGX） | 本方案（可信服务器） |
|------|------|------|
| 信任根 | SGX enclave 硬件 | 物理隔离 Linux 服务器 |
| 安全等级 | 极高（enclave 远程证明可验证） | 高（依赖物理安全 + 操作守则） |
| IT 管理员威胁 | 看不到 enclave 私钥 | 能看到但需双人操作 |
| 实现成本 | 高（SGX SDK + enclave 开发 6-8 周） | 低（一台 Linux + shell 脚本，1 天） |
| 远程证明 | ✓ | ✗ |
| 适合阶段 | 长期目标（最高安全） | 立即部署（最低成本） |

---

## 9. 实施步骤

| 步骤 | 内容 | 负责人 | 周期 |
|:--:|------|------|:--:|
| 1 | 采购+部署可信服务器（硬件 + LUKS + 软件） | IT 管理员 | 1 天 |
| 2 | 生成 RSA 密钥对 + 公钥硬编码进 TA | 安全工程师 | 0.5 天 |
| 3 | 部署签名脚本到可信服务器 | IT 管理员 | 0.5 天 |
| 4 | TA 实现 `CMD_PROVISION_DONGLE_MANIFEST` | 安全工程师 | 2 天 |
| 5 | CA 实现 `--provision-dongle-manifest` | 安全工程师 | 1 天 |
| 6 | 灌装脚本切换到 `--provision-dongle-manifest` | 产线工程师 | 0.5 天 |
| 7 | 测试环境端到端验证 | 全员 | 1 天 |
| 8 | 产线试运行（与现有流程并行） | 产线 | 1 周 |

**总工期**：约 2 周（含测试），不含可信服务器采购周期。

---

> 相关文档：
> - [24-so-pin-yubikey-unlock.md](24-so-pin-yubikey-unlock.md) — SO-PIN 双因子解锁完整方案
> - [25-yubikey-guide.md](25-yubikey-guide.md) — YubiKey 选型与使用指南
> - [26-sgx-provisioning-attestation.md](26-sgx-provisioning-attestation.md) — SGX 远程证明方案（含方案 C 云端 SGX 详细对比）
> - [07-provisioning-procedure.md](07-provisioning-procedure.md) — 产线灌装详细流程

---

## 附录 A：gen-manifest.sh

**部署位置**：`/opt/yubikey-signer/gen-manifest.sh`（可信服务器上）  
**用途**：将 JSON 格式的白名单描述文件转换为 TA 可解析的二进制 manifest

```bash
#!/bin/bash
# ============================================================
# gen-manifest.sh — JSON → binary manifest converter
#
# Usage:
#   ./gen-manifest.sh <manifest.json> <manifest.bin>
#
# Input JSON format:
# {
#   "version": 1,
#   "timestamp": 1720000000,
#   "generated_by": "trusted-server-01",
#   "comment": "...",
#   "dongles": [
#     { "index": 0, "serial": 12345678, "role": "primary-so",
#       "pubkey_sha256": "abcd1234..." },
#     ...
#   ]
# }
#
# Output binary format (little-endian):
#   [version:4][timestamp:4][count:4]
#   [entry × count: hash[32] + serial[4] + reserved[4]]
#   Total = 12 + count × 40 bytes
# ============================================================
set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <manifest.json> <manifest.bin>"
    exit 1
fi

JSON="$1"
OUT="$2"

# ---- Validate input ----
if [ ! -f "$JSON" ]; then
    echo "ERROR: $JSON not found"
    exit 1
fi

# ---- Parse JSON fields ----
VERSION=$(jq -r '.version' "$JSON")
TIMESTAMP=$(jq -r '.timestamp' "$JSON")
COUNT=$(jq -r '.dongles | length' "$JSON")

echo "Manifest: version=$VERSION ts=$TIMESTAMP dongles=$COUNT"

# ---- Validate count ----
if [ "$COUNT" -lt 1 ]; then
    echo "ERROR: dongles array is empty"
    exit 1
fi
if [ "$COUNT" -gt 8 ]; then
    echo "ERROR: max 8 dongles supported (got $COUNT)"
    exit 1
fi

# ---- Write binary manifest ----
# Use a temp file to avoid partial writes
TMP=$(mktemp)

# Header: version (4 bytes LE)
printf '%08x' "$VERSION" | xxd -r -p | dd of="$TMP" bs=1 seek=0 conv=notrunc 2>/dev/null

# Header: timestamp (4 bytes LE)
printf '%08x' "$TIMESTAMP" | xxd -r -p | dd of="$TMP" bs=1 seek=4 conv=notrunc 2>/dev/null

# Header: count (4 bytes LE)
printf '%08x' "$COUNT" | xxd -r -p | dd of="$TMP" bs=1 seek=8 conv=notrunc 2>/dev/null

# Entries: hash[32] + serial[4] + reserved[4] = 40 bytes each
OFFSET=12
for i in $(seq 0 $((COUNT - 1))); do
    HASH=$(jq -r ".dongles[$i].pubkey_sha256" "$JSON")
    SERIAL=$(jq -r ".dongles[$i].serial" "$JSON")

    # Validate hash length
    if [ "${#HASH}" -ne 64 ]; then
        echo "ERROR: dongle[$i] pubkey_sha256 must be 64 hex chars (got ${#HASH})"
        rm -f "$TMP"
        exit 1
    fi

    # Write hash (32 bytes)
    echo "$HASH" | xxd -r -p | dd of="$TMP" bs=1 seek=$OFFSET conv=notrunc 2>/dev/null
    OFFSET=$((OFFSET + 32))

    # Write serial number (4 bytes LE)
    printf '%08x' "$SERIAL" | xxd -r -p | dd of="$TMP" bs=1 seek=$OFFSET conv=notrunc 2>/dev/null
    OFFSET=$((OFFSET + 4))

    # Write reserved (4 bytes, zero)
    printf '%08x' 0 | xxd -r -p | dd of="$TMP" bs=1 seek=$OFFSET conv=notrunc 2>/dev/null
    OFFSET=$((OFFSET + 4))

    echo "  dongle[$i]: hash=${HASH:0:16}... serial=$SERIAL"
done

# ---- Finalize ----
mv "$TMP" "$OUT"
TOTAL=$((12 + COUNT * 40))
echo ""
echo "✓ Manifest written: $OUT ($TOTAL bytes, $COUNT dongles)"
echo "  sha256: $(sha256sum "$OUT" | awk '{print $1}')"
```

---

## 附录 B：sign-manifest.sh

**部署位置**：`/opt/yubikey-signer/sign-manifest.sh`（可信服务器上）  
**用途**：对二进制 manifest 进行 RSA-2048 SHA-256 签名，并记录审计日志

```bash
#!/bin/bash
# ============================================================
# sign-manifest.sh — RSA sign a manifest + audit log
#
# Usage:
#   ./sign-manifest.sh <manifest.bin> [--with-password]
#
# Prerequisites:
#   - RSA private key at /opt/yubikey-signer/keys/manifest_key.pem
#   - OpenSSL ≥ 1.1.1
#   - 审计日志目录 /opt/yubikey-signer/logs/
#
# Output:
#   <manifest.bin>.sig — RSA-2048 SHA-256 signature (256 bytes)
#   signing.log       — 追加审计条目
# ============================================================
set -e

MANIFEST="$1"
USE_PW="${2:-}"

if [ -z "$MANIFEST" ]; then
    echo "Usage: $0 <manifest.bin> [--with-password]"
    exit 1
fi

if [ ! -f "$MANIFEST" ]; then
    echo "ERROR: $MANIFEST not found"
    exit 1
fi

KEY="/opt/yubikey-signer/keys/manifest_key.pem"
SIG="${MANIFEST}.sig"
LOG="/opt/yubikey-signer/logs/signing.log"
VERIFY_KEY="/opt/yubikey-signer/keys/manifest_key_pub.der"

# ---- Check private key ----
if [ ! -f "$KEY" ]; then
    echo "ERROR: Private key not found: $KEY"
    exit 1
fi

# ---- Sign ----
echo "Signing: $(basename "$MANIFEST")"
echo "  Key:    $KEY"

if [ "$USE_PW" = "--with-password" ]; then
    # Private key is encrypted (AES-256-CBC), prompt for password
    openssl dgst -sha256 -sign "$KEY" \
        -out "$SIG" \
        "$MANIFEST"
else
    # Private key is unencrypted
    openssl dgst -sha256 -sign "$KEY" \
        -out "$SIG" \
        "$MANIFEST"
fi

echo "  Output: $(basename "$SIG") ($(wc -c < "$SIG") bytes)"

# ---- Self-verify ----
echo ""
echo "Self-verifying..."
if openssl dgst -sha256 -verify "$VERIFY_KEY" \
    -signature "$SIG" \
    "$MANIFEST" 2>&1; then
    echo "  ✓ Signature verified OK"
else
    echo "  ✗ SIGNATURE VERIFICATION FAILED — DO NOT DISTRIBUTE"
    rm -f "$SIG"
    exit 1
fi

# ---- Audit log ----
MANIFEST_SHA256=$(sha256sum "$MANIFEST" | awk '{print $1}')
SIG_SHA256=$(sha256sum "$SIG" | awk '{print $1}')
OPERATOR="${SUDO_USER:-$USER}"

mkdir -p "$(dirname "$LOG")"
cat >> "$LOG" << EOF
$(date -Iseconds) | $(basename "$MANIFEST") | manifest_sha256=$MANIFEST_SHA256 | sig_sha256=$SIG_SHA256 | operator=$OPERATOR | status=OK
EOF

echo ""
echo "  Audit log: $LOG"
```

---

## 附录 C：manifest 二进制格式规范

TA 解析 `manifest.bin` 时使用的二进制格式（little-endian 字节序）：

```
字节偏移    长度    字段          说明
─────────────────────────────────────────────
0         4       version        uint32 LE，单调递增（从 1 开始）
4         4       timestamp      uint32 LE，Unix 时间戳
8         4       count          uint32 LE，白名单条目数（1-8）
12       40×N     entries[]      每条 40 字节

条目格式（40 字节）：
  偏移    长度    字段
  ─────────────────────
  0      32      pubkey_sha256    SHA-256(pubkey DER)
  32      4      serial           uint32 LE，YubiKey 序列号
  36      4      reserved         保留（填 0）
─────────────────────────────────────────────
总大小: 12 + count × 40 字节
最大: 12 + 8 × 40 = 332 字节
```

**版本号规则**：

| 版本 | 说明 |
|:--:|------|
| 1 | 初始版本：hash[32] + serial[4] + reserved[4] |
| ≥ 2 | 保留扩展（如增加 YubiKey 设备证书 hash、有效期字段等） |

TA 拒绝接受版本号为 0 或版本号小于当前已存储版本的 manifest（Anti-rollback）。
