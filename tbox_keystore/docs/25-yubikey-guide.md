# 25 — YubiKey 选型与使用指南

## 1. 产品线概述

Yubico 公司的硬件安全令牌产品线主要包含两个世代：

| 世代 | 生命周期 | 状态 | 代表型号 |
|------|------|:--:|------|
| **YubiKey 4** | 2015–2019 | 已停产，库存可购 | YubiKey 4 (USB-A), YubiKey 4 Nano (超小型), YubiKey 4C (USB-C) |
| **YubiKey 5** | 2018–至今 | 在产 | YubiKey 5 NFC, YubiKey 5C NFC, YubiKey 5 Nano, YubiKey 5C Nano, YubiKey 5Ci (Lightning+USB-C) |

**形态选择**（与功能无关，仅物理接口不同）：

| 形态 | 说明 | 适用场景 |
|------|------|------|
| USB-A | 标准 USB Type-A | 工控机、笔记本 |
| USB-C | USB Type-C | 新型笔记本、TBox 设备 |
| Nano | 超小型，几乎不凸出 | 长期插在设备上 |
| NFC | 支持近场通信 | 移动设备、无 USB 场景 |

## 2. 功能详解

YubiKey 内部集成了多个独立的小程序（applet），通过不同接口协议对外提供服务。4 代和 5 代支持的协议不完全相同。

### 2.1 PIV（Personal Identity Verification）

| 项目 | 说明 |
|------|------|
| **标准** | FIPS 201 / NIST SP 800-73 |
| **协议** | PC/SC (CCID) |
| **功能** | 基于 X.509 证书的身份认证；4 个 PIV Slot (9a/9c/9d/9e)，每个 Slot 可存储独立的 RSA 2048 或 ECC P-256/P-384 密钥对 + X.509 证书 |
| **典型用途** | 美国政府 CAC 卡替代、企业 Windows 登录、TLS 双向认证 |
| **4 代 vs 5 代** | **完全一致**。RSA 2048、ECDSA P-256/P-384 均支持；Slot 分配和命令集相同 |
| **本项目使用** | **是；核心功能** |

**PIV Slot 说明**：

| Slot | ID | 默认密钥 | 典型用途 | 本项目 |
|------|:--:|------|------|:--:|
| 9a | `0x9A` | P-256 (出厂预置) | PIV Authentication — 持卡人身份认证 | ✓ 使用 |
| 9c | `0x9C` | P-256 (出厂预置) | Digital Signature — 文档/邮件数字签名 | 不使用 |
| 9d | `0x9D` | P-256 (出厂预置) | Key Management — 加密/解密密钥 | 不使用 |
| 9e | `0x9E` | P-256 (出厂预置) | Card Authentication — 物理门禁 | 不使用 |

本项目只用 **Slot 9a**，原因是：
- 出厂预置密钥，无需手动生成（简化产线流程）
- 语义上最匹配 SO 身份认证（"Security Officer Authentication"）
- `ykman piv info` 可直接读取公钥，无需额外配置

### 2.2 FIDO U2F

| 项目 | 说明 |
|------|------|
| **标准** | FIDO U2F (Universal 2nd Factor) |
| **协议** | HID 报文 |
| **功能** | 基于 Challenge-Response 的第二因子认证；YubiKey 内部为每个注册站点生成独立密钥对（ECDSA P-256），无法跨站点追踪 |
| **典型用途** | Google/GitHub/Dropbox 等网站的双因子登录 |
| **4 代 vs 5 代** | **4 代已支持**，5 代完全一致 |
| **本项目使用** | 不使用（U2F 密钥由 YubiKey 内部自动生成，无法被外部读取或控制，不适合 SO 解锁场景） |

### 2.3 FIDO2 / WebAuthn

| 项目 | 说明 |
|------|------|
| **标准** | FIDO2 (含 WebAuthn + CTAP) |
| **协议** | HID CTAPHID / NFC CTAP |
| **功能** | 无密码登录；支持 Resident Key（存储在 YubiKey 中，最多 25 个）和 Non-Resident Key（加密后存在服务端）；支持 PIN 保护 |
| **典型用途** | Microsoft 无密码登录、Passkey |
| **4 代 vs 5 代** | **4 代不支持**。FIDO2 是 5 代新增的核心卖点 |
| **本项目使用** | 不使用（面向 Web 应用，非设备管理场景） |

### 2.4 OATH

| 项目 | 说明 |
|------|------|
| **标准** | OATH TOTP (RFC 6238) / HOTP (RFC 4226) |
| **协议** | 通过 `ykman oath` 子命令管理 |
| **功能** | 替代手机 Authenticator App 的 TOTP 动态验证码；YubiKey 内部存储共享密钥（最多 32 个），按时间生成 6-8 位数字码 |
| **典型用途** | GitHub/GitLab 的 2FA 验证码、VPN 登录的动态令牌 |
| **4 代 vs 5 代** | **4 代已支持 Yubico OTP 但 OATH HOTP/TOTP 需 Yubico Authenticator App 配合**；5 代 OATH 功能完全一致 |
| **本项目使用** | 不使用（与 SO 解锁无关） |

### 2.5 OpenPGP

| 项目 | 说明 |
|------|------|
| **标准** | OpenPGP Card 3.4 |
| **协议** | PC/SC 或 GnuPG `scdaemon` |
| **功能** | YubiKey 作为 OpenPGP 智能卡，存储 PGP 密钥（Sign/Encrypt/Authentication 三个 Slot）；支持 RSA 2048/4096 和 ECC P-256/P-384/P-521 |
| **典型用途** | Git commit 签名、邮件加密 (GPG)、SSH 登录 (gpg-agent) |
| **4 代 vs 5 代** | **完全一致**。RSA 4096 和 Curve25519 (ed25519/x25519) 在 5 代新增支持，但 4 代已支持本项目所需的 ECC P-256 |
| **本项目使用** | 不使用（PIV 接口比 OpenPGP 更适合设备管理场景；PIV 支持出厂预置密钥，无需手动生成） |

### 2.6 OTP（Yubico OTP + Static Password + Challenge-Response）

| 项目 | 说明 |
|------|------|
| **标准** | Yubico 私有协议 |
| **协议** | HID 键盘模拟 |
| **功能** | Slot 1 和 Slot 2 可独立配置为三种模式之一：(a) **Yubico OTP** — 按一下输出 44 字符一次性密码，在线验证；(b) **Static Password** — 输出固定密码字符串；(c) **HMAC-SHA1 Challenge-Response** — 接收 64 字节 challenge，输出 20 字节 HMAC-SHA1 响应 |
| **典型用途** | Yubico OTP 用于 YubiCloud 登录；Static Password 用于前置固定字符串；HMAC-SHA1 用于本地离线验证 |
| **4 代 vs 5 代** | **完全一致** |
| **本项目使用** | 不使用（HMAC-SHA1 不足以替代 ECDSA P-256；签名长度 20 字节太短） |

### 2.7 NFC

| 项目 | 说明 |
|------|------|
| **标准** | ISO 14443 Type A (NFC Forum Type 4 Tag) |
| **功能** | 通过 NFC 提供与 USB 相同的所有功能（PIV/FIDO/FIDO2/OATH/OpenPGP/OTP） |
| **典型用途** | Android/iOS 手机上的 FIDO2/U2F 认证 |
| **4 代 vs 5 代** | **4 代不支持**。NFC 功能仅在 5 代 NFC 型号（YubiKey 5 NFC / 5C NFC）上可用 |
| **本项目使用** | 不使用（TBox/工控机均有 USB 口，无需 NFC） |

## 3. 4 代 vs 5 代功能对比总表

| 功能 | YubiKey 4 | YubiKey 5 | 本项目需要 |
|------|:--:|:--:|:--:|
| **PIV** (ECDSA P-256) | ✓ | ✓ | **是** |
| **PIV** (RSA 2048/4096) | ✓ | ✓ | 否 |
| **PIV** (ECC P-384) | ✓ | ✓ | 否 |
| **FIDO U2F** | ✓ | ✓ | 否 |
| **FIDO2 / WebAuthn** | ✗ | ✓ | 否 |
| **OpenPGP** (RSA/ECC) | ✓ | ✓ | 否 |
| **OpenPGP** (Ed25519/X25519) | ✗ | ✓ | 否 |
| **OATH TOTP/HOTP** | ✓ | ✓ | 否 |
| **Yubico OTP** | ✓ | ✓ | 否 |
| **HMAC-SHA1 Challenge-Response** | ✓ | ✓ | 否 |
| **NFC** | ✗ | ✓ (NFC 型号) | 否 |
| **固件更新** | 不再更新 | 持续更新 | — |
| **参考单价** | $25–35 (库存) | $45–55 | — |

**结论：本项目仅需 PIV ECDSA P-256，4 代完全满足，推荐使用 4 代以降低成本。**

## 4. 选型建议

### 4.1 推荐型号：YubiKey 4 (USB-A)

| 维度 | 评价 |
|------|------|
| **功能** | PIV ECDSA P-256 在 4 代和 5 代上完全一致 |
| **成本** | 4 代库存价约 ¥180–260 元 vs 5 代 ¥325–400 元；每把节省 40% |
| **风险** | 4 代已停产，需提前批量采购并备货；固件不会再有安全更新（但 PIV 协议成熟稳定，风险极低） |
| **适用场景** | 安全官员日常维护、产线灌装公钥注册 |

### 4.2 备选型号

| 场景 | 推荐 | 原因 |
|------|------|------|
| 安全官员（主） | YubiKey 4 USB-A | 成本低，功能满足 |
| 安全官员（备） | YubiKey 4 USB-A | 同型号，统一管理 |
| 笔记本没有 USB-A | YubiKey 5C NFC | 4C 库存极少，5C 容易买到 |
| TBox 长期插 Nano | YubiKey 5 Nano | 4 Nano 极少见，5 Nano 容易买到 |

### 4.3 采购注意事项

- **一次采购足够数量**：N+1 把（N = 安全官员人数，1 = 备用保险柜保管）
- **要求供应商提供批次证明**：确保全部来自同一生产批次，公钥格式一致
- **到货验证**：每把用 `ykman piv info` 验证 Slot 9a 公钥存在且格式正确
- **防伪检查**：YubiKey 官网有序列号验证工具，确认非山寨品

## 5. 前置条件

在操作 YubiKey 之前，确保以下环境准备就绪。

### 5.1 硬件要求

| 场景 | 设备 | USB 接口 | 操作系统 |
|------|------|:--:|------|
| 安全官员初始化 YubiKey | **安全官员笔记本** | USB-A 或 USB-C | Windows 10+ / macOS 12+ / Linux (Ubuntu 20.04+) |
| 工厂产线导出公钥 | **工控机** | USB-A | Linux（产线标准镜像） |
| 现场 SO 解锁（场景 A） | **TBox 设备** | USB-A（需 TBox 有 USB Host） | TBox Linux |
| 现场 SO 解锁（场景 B） | **安全官员笔记本**（SSH 连 TBox） | USB-A 或 USB-C | 同安全官员笔记本 |

### 5.2 软件安装（安全官员笔记本 + 工控机均需）

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

# 5. 安装 OpenSSL（用于解析公钥证书）
sudo apt install openssl

# 6. 插入 YubiKey 后验证识别
ykman piv info
# 如果能输出 PIV 信息 → 驱动安装成功
# 如果报 "No YubiKey detected" → 检查 pcscd 是否运行
```

#### Windows 10+

```powershell
# 1. 下载安装 YubiKey Manager
#    https://www.yubico.com/support/download/yubikey-manager/
#    或使用 winget:
winget install Yubico.YubiKeyManager

# 2. 安装后打开 PowerShell 验证
ykman piv info
```

#### macOS

```bash
# 使用 Homebrew
brew install ykman
# 验证
ykman piv info
```

### 5.3 USB 权限配置（Linux 必须）

Linux 下非 root 用户访问 YubiKey 需要配置 udev 规则：

```bash
# 添加 udev 规则（在安全官员笔记本和工控机上各执行一次）
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

# 将自己加入 plugdev 组
sudo usermod -a -G plugdev $USER
# 注销重新登录后生效

# 验证权限（插入 YubiKey 后）
ykman piv info   # 不应要求 sudo
```

### 5.4 验证安装清单

所有环境安装完成后，逐一检查：

| 检查项 | 命令 | 预期结果 |
|------|------|------|
| ykman 可用 | `ykman --version` | ≥ 4.0 |
| pcscd 运行 | `systemctl status pcscd` | active (running) |
| YubiKey 识别 | `ykman info` | 显示设备信息 |
| PIV 接口正常 | `ykman piv info` | 显示 Slot 9a 信息 |
| USB 权限 | 非 root 运行 `ykman info` | 不需要 sudo |

---

## 6. 完整操作流程

> **标注说明**：每个命令前标注执行位置：
> - `[笔记本]` = 安全官员的笔记本
> - `[工控机]` = 产线工控机
> - `[TBox]` = 目标设备（QEMU 或真机）

### 6.1 安全官员开箱初始化

**执行位置**：`[笔记本]` — 安全官员的个人笔记本（Linux/macOS/Windows）

拿到新 YubiKey 后**一次性操作**。

```bash
# =============================================
# 步骤 1: 验证 YubiKey 基本信息
# =============================================
[笔记本]$ ykman info
# 预期输出:
# Device type: YubiKey 4 / YubiKey 5
# Serial number: 12345678
# Firmware version: 4.3.4 / 5.4.3
# Form factor: Keychain (USB-A)
# Enabled USB interfaces: OTP+FIDO+CCID

# =============================================
# 步骤 2: 验证 PIV Slot 9a 公钥存在
# =============================================
[笔记本]$ ykman piv info
# PIV version: 4.4.8
# Slot 9a:
#   Algorithm: ECCP256
#   Subject DN: CN=Yubico PIV Authentication

# =============================================
# 步骤 3: 查看 Slot 9a 公钥格式
# =============================================
[笔记本]$ ykman piv export-certificate 9a - | openssl x509 -text -noout | head -15
# 预期: Public Key Algorithm: id-ecPublicKey
#        Public-Key: (256 bit)

# =============================================
# 步骤 4: 修改 PIV PIN（非常重要！）
# =============================================
# 默认 PIV PIN:  123456
# 默认 PIV PUK:  12345678
# 第一步：改 PIN（持卡人日常使用的 PIN）
[笔记本]$ ykman piv access change-pin
# Enter current PIN: 123456
# Enter new PIN: <SO 自行设定的新 PIN>

# 第二步：改 PUK（解锁被锁 PIN 的管理密钥）
[笔记本]$ ykman piv access change-puk
# Enter current PUK: 12345678
# Enter new PUK: <SO 自行设定的新 PUK>

# =============================================
# 步骤 5: (可选) 修改 Management Key
# =============================================
# 默认 Management Key: 0102030405060708...（48 位 hex）
# Management Key 用于导入证书/密钥等高级操作
# 本项目不需要修改，保留默认即可
```

**完成后**：YubiKey 此时已可以交付使用。PIV PIN 由安全官员记忆，PUK 记录后密封保管。

### 6.2 工厂产线 — 导出公钥

**执行位置**：`[工控机]` — 产线工控机（Linux，已安装 $5.2 软件）

YubiKey 只需插拔**一次**，导出公钥到文件后开始批量灌装。

```bash
# =============================================
# 步骤 1: 安全官员将 YubiKey 插入工控机 USB 口
# =============================================
# (物理操作 — 安全官员在场)

# =============================================
# 步骤 2: 导出 Slot 9a 公钥（约 30 秒）
# =============================================
[工控机]$ cd /factory
[工控机]$ ykman piv export-certificate 9a - 2>/dev/null | \
    openssl x509 -pubkey -noout 2>/dev/null | \
    openssl pkey -pubin -outform DER 2>/dev/null \
    > so-dongle-0.der

[工控机]$ xxd so-dongle-0.der | head -3
# 验证导出文件非空

# =============================================
# 步骤 3: 拔掉 YubiKey
# =============================================
# 交还安全官员保管
# 后续灌装循环不再需要 YubiKey 在场
```

### 6.3 工厂产线 — 批量灌装

**执行位置**：`[工控机]` — 产线工控机（YubiKey 不需要在场）

```bash
[工控机]$ SO_PIN=$(cat /factory/batch-so-pin.txt)

for device_serial in $(cat /factory/devices.txt); do
    echo "=== Provisioning device: $device_serial ==="

    DEV_PIN=$(openssl rand -hex 16)

    # 灌装设备身份（串口/USB Ethernet 连 TBox 执行）
    tbox_keystore --init-pin $DEV_PIN
    tbox_keystore --gen-rsa device-key --size 2048 --sign --decrypt
    tbox_keystore --gen-aes ota-key --size 256 --decrypt
    tbox_keystore --export-pub device-key \
        --out ${device_serial}-device-key.pub

    # 灌装 SO-PIN + Dongle 白名单
    tbox_keystore --init-so-pin $SO_PIN
    tbox_keystore --provision-dongle-from-file so-dongle-0.der

    # 锁定 TA
    tbox_keystore --lock

    echo "  → Done. Pubkey: ${device_serial}-device-key.pub"
done
```

**注意**：`tbox_keystore` 命令通过串口/USB Ethernet/ADB 发送到 TBox 上执行——不在工控机本地执行。

### 6.4 开发/调试阶段（ykman CLI fallback）

**执行位置**：`[TBox]` — QEMU 或开发板，YubiKey 插在 TBox USB 口

`dongle_yubikey.c` 默认使用 ykman CLI 子进程模式。

```bash
# 确保 TBox 上 ykman 已安装（步骤同 §5.2）
[TBox]$ which ykman
/usr/bin/ykman

# 如果没有物理 YubiKey，使用 dummy 后端替代
[TBox]$ tbox_keystore --provision-dongle --dongle dummy

# 有物理 YubiKey 时使用 yubikey 后端
[TBox]$ tbox_keystore --so-unlock --so-pin <PIN> --dongle yubikey
```

**编译选项**：

```bash
# 开发环境（默认）：ykman CLI fallback + dummy
[笔记本]$ cd host
[笔记本]$ make DONGLE_BACKENDS="dongle_dummy dongle_yubikey"

# 量产环境：libykpiv 直连（见 §6.5）
[笔记本]$ make DONGLE_BACKENDS="dongle_yubikey" CFLAGS_EXTRA="-DWITH_LIBYKPIV=1"
```

### 6.5 量产阶段（libykpiv 直连模式）

**执行位置**：编译在 `[笔记本]`，运行在 `[TBox]`

量产不依赖 ykman CLI，CA 通过 libykpiv 直接 USB 通信，无子进程开销。

```bash
# =============================================
# 编译 CA（在安全官员笔记本上交叉编译）
# =============================================
[笔记本]$ cd host
[笔记本]$ make \
    CROSS_COMPILE=aarch64-linux-gnu- \
    DONGLE_BACKENDS="dongle_yubikey" \
    CFLAGS_EXTRA="-DWITH_LIBYKPIV=1" \
    LDADD_EXTRA="-lykpiv"

# =============================================
# 部署到 TBox
# =============================================
[笔记本]$ scp tbox_keystore root@<tbox-ip>:/usr/bin/

# =============================================
# TBox 上验证 libykpiv 连接
# =============================================
[TBox]$ tbox_keystore --provision-dongle --dongle yubikey
# 内部调用: ykpiv_connect() → ykpiv_get_cert() → CMD_PROVISION_DONGLE
```

**libykpiv vs ykman CLI 对比**：

| 维度 | ykman CLI fallback | libykpiv 直连 |
|------|:--:|:--:|
| 通信方式 | `popen("ykman...")` 子进程 | 直接 USB 通信 |
| 性能 | ~500ms/签名 | ~50ms/签名 |
| TBox 依赖 | ykman CLI + pcscd | libykpiv.so |
| 适用场景 | 开发 / 调试 | 量产 / 真机 |
| 默认 | ✓ | 需显式编译 |

### 6.6 现场 SO 解锁操作

**场景 A**：TBox 有 USB Host，YubiKey 直插 TBox
**场景 B**：TBox 无 USB Host，YubiKey 插安全官员笔记本，远程连 TBox（当前不支持，需 CA 代理扩展）

```bash
# =============================================
# 场景 A: YubiKey 直插 TBox
# =============================================

# [物理操作] 安全官员将 YubiKey 插入 TBox USB 口

[TBox]$ tbox_keystore --so-unlock --so-pin <SO-PIN> --dongle yubikey
# 预期输出:
# TA challenge received. 2 dongle(s) registered.
# [yubikey] Detected: YubiKey 4 (serial=12345678)
# [dongle] Using: yubikey
# [CA] ECDSA signature VERIFIED OK
# ✓ SO unlock successful. TA is now UNLOCKED.

# [执行维护操作]
[TBox]$ tbox_keystore --delete old-key
[TBox]$ tbox_keystore --gen-rsa new-key --size 2048 --sign --decrypt

# [维护完成，重新锁定]
[TBox]$ tbox_keystore --so-lock
# TA re-locked. Write operations disabled.

# [物理操作] 安全官员拔掉 YubiKey

# =============================================
# 场景 B: TBox 无 USB Host（当前架构不支持）
# =============================================
# 期望的远程流程（需要 CA 代理模式扩展，计划 Phase 3）：
#   1. YubiKey 插在安全官员笔记本上
#   2. 笔记本 SSH 连入 TBox
#   3. 笔记本上运行 ykman piv sign，拿到签名
#   4. 通过 SSH 把签名传给 TBox 上的 tbox_keystore
```

### 6.7 YubiKey 丢失/损坏应急流程

**执行位置**：`[笔记本]`（注册新 YubiKey）/ `[TBox]`（使用备用解锁）/ `[工控机]`（重新灌装）

| 场景 | 操作 | 执行位置 |
|------|------|:--:|
| **主 YubiKey 丢失** | 使用备用 YubiKey（`--dongle-index 1`）解锁 → 删除主 YubiKey 的白名单 → 注册新备用 | `[TBox]` + `[笔记本]` |
| **主 + 备用同时丢失** | 所有设备永久无法 SO 解锁 → **返厂重新灌装**（从 §6.2 开始重做） | `[工控机]` |
| **YubiKey 物理损坏** | 同丢失流程；损坏 YubiKey 物理销毁 | — |
| **忘记 PIV PIN** | 使用 PUK 解锁 → 重置 PIN（3 次 PIN 失败 → 需 PUK；PUK 无限次失败 → YubiKey 永久锁定需 `ykman piv reset`） | `[笔记本]` |

**必备应急物资**（公司保险柜保管）：

| 物品 | 数量 | 说明 |
|------|:--:|------|
| 备用 YubiKey | 1+ 把 | 已注册到所有设备白名单 |
| 主 SO-PIN | 1 份 | 密封信封，安全官员主管持有 |
| PIV PIN + PUK | 1 份 | 密封信封 |
| 应急程序手册 | 1 份 | 纸质打印 |

## 7. 常见问题

### 7.1 PIV PIN 被锁定

```bash
# 查看剩余尝试次数
ykman piv info | grep "PIN tries"

# 使用 PUK 解锁 PIN（需要知道 PUK）
ykman piv access unblock-pin
# Enter PUK: ********
# Enter new PIN: ********

# 如果 PUK 也被锁定（输错次数过多），唯一办法是重置 PIV applet
# ⚠️ 重置会清除所有 Slot 密钥和证书！
ykman piv reset
# 重置后需要重新注册公钥到 TBox 白名单
```

### 7.2 如何批量管理多把 YubiKey

```bash
# 导出所有 YubiKey 的公钥（在工控机上逐一插拔）
for i in 0 1 2 3; do
    echo "Insert YubiKey #$i and press Enter..."
    read
    ykman piv export-certificate 9a - 2>/dev/null | \
        openssl x509 -pubkey -noout 2>/dev/null | \
        openssl pkey -pubin -outform DER 2>/dev/null \
        > so-dongle-$i.der
    echo "  → so-dongle-$i.der saved"
done

# 批量注册到设备（每台 TBox）
for der in so-dongle-*.der; do
    tbox_keystore --provision-dongle-from-file "$der"
done

# 标记每把 YubiKey 用途
# YubiKey #0 — 贴标签"主安全官员"
# YubiKey #1 — 贴标签"备用 — 保险柜"
# YubiKey #2 — 贴标签"审计"
```

### 7.3 开发环境没有 YubiKey

使用 dummy dongle 完全替代，无需任何硬件：

```bash
# 生成模拟密钥
cd host && make gen-dummy-key

# 使用 dummy 后端
tbox_keystore --init-so-pin <SO-PIN>
tbox_keystore --provision-dongle --dongle dummy
tbox_keystore --so-unlock --so-pin <SO-PIN> --dongle dummy
```

## 8. 未来发展

当 OP-TEE 升级到支持 ECDSA transient object 的版本后，CA 侧 ECDSA 验证可移回 TA 侧（恢复 `CMD_SO_UNLOCK_VERIFY` 流程），进一步提升安全性。详见 [24-so-pin-yubikey-unlock.md](24-so-pin-yubikey-unlock.md)。

---

> 相关文档：
> - [24-so-pin-yubikey-unlock.md](24-so-pin-yubikey-unlock.md) — SO-PIN 双因子解锁完整方案
> - [host/dongle/dongle_ops.h](../host/dongle/dongle_ops.h) — dongle 抽象层接口
> - [host/dongle/dongle_yubikey.c](../host/dongle/dongle_yubikey.c) — YubiKey 后端实现
