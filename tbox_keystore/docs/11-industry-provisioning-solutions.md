# 行业通用工厂密钥灌装方案

## 概述

工厂密钥灌装（Factory Key Provisioning）是指在生产线上将每台设备的唯一密钥安全地写入产品的安全存储中。本文从**行业规范、角色分工、开发任务、实施流程**四个维度给出完整方案。

---

## 一、行业标准体系

### 主要标准与规范

```
GlobalPlatform TEE                    GlobalPlatform SE
┌─────────────────────┐              ┌─────────────────────┐
│ TEE Internal API    │              │ SE Access Control    │
│ TEE Client API      │              │ (GlobalPlatform 2.3) │
│ TEE Secure Storage  │              │ ISD / SSD / CASD     │
│ PKCS#11 TA (GP TEE) │              │ 密钥预置标准          │
└─────────────────────┘              └─────────────────────┘
         │                                    │
         └──────────┬─────────────────────────┘
                    │
          ┌─────────▼──────────┐
          │  产线灌装标准          │
          │  ├─ NIST SP 800-90A │
          │  ├─ FIPS 140-3      │
          │  ├─ CC EAL4+        │
          │  └─ 国密 GM/T 0009  │
          └────────────────────┘
```

### 四种行业公认的灌装模式

```
模式 A: TEE 内生密钥（最安全）
  密钥在 TEE 安全环境内生成，私钥**永远不离开 TEE**
  适用: 设备身份密钥、TLS 客户端证书

模式 B: KMS 加密注入
  KMS 生成密钥 → 用设备公钥加密 → 经 USB/网络传输 → TEE 内解密写入
  适用: 对称密钥、需要灾备恢复的场景

模式 C: 安全元件预置
  在芯片封测阶段将密钥写入 eFuse/OTP，出厂已固化
  适用: HUK、Root CA 公钥、芯片认证密钥

模式 D: 产线 CA 签发
  设备在 TEE 内生密钥对 → 导出公钥 → 产线 CA 签名 → 回写证书
  适用: 设备证书链、X.509 PKI 体系
```

---

## 二、角色分工与开发任务

### 角色全景图

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  SoC/芯片厂   │    │  OEM/设备厂  │    │  CA 运营方    │
│  提供:        │    │  提供:       │    │  提供:        │
│  ├─ HUK      │    │  ├─ 产线设备 │    │  ├─ 根证书    │
│  ├─ eFuse    │    │  ├─ 工装夹具 │    │  ├─ 证书签发  │
│  ├─ 安全启动  │    │  ├─ 灌装脚本 │    │  └─ CRL 吊销  │
│  └─ TRNG     │    │  └─ 测试验证 │    │              │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                   │
       └────────┬──────────┴─────────┬─────────┘
                │                    │
       ┌────────▼────────┐  ┌───────▼────────┐
       │  密钥管理系统(KMS) │  │ 产线系统集成商   │
       │  提供:           │  │  提供:          │
       │  ├─ 密钥生成     │  │  ├─ USB 通信    │
       │  ├─ 密钥包装     │  │  ├─ 扫码对接    │
       │  ├─ 密钥库       │  │  ├─ MES 对接    │
       │  └─ 审计日志     │  │  └─ 异常处理    │
       └────────────────┘  └────────────────┘
```

---

### 各角色详细职责与开发内容

#### 1. SoC/芯片厂商

| 开发项 | 详细说明 | 交付物 |
|--------|----------|--------|
| HUK 烧录 | 在封测阶段将 128-bit HUK 写入 eFuse，每芯片唯一 | eFuse 烧录脚本 |
| 安全启动 | 实现 BootROM → uboot → OP-TEE → Linux 签名验证链 | 公钥 Hash 烧录 |
| Debug 锁定 | 熔断 JTAG/SWD 调试接口 | 熔丝控制脚本 |
| HUK 读取接口 | 提供 Secure World 可调用的 HUK 读取 API | `tee_otp_get_hw_unique_key()` |

**开发内容：**

```c
/* 芯片厂商需要实现的平台代码 */
/* 文件: optee_os/core/arch/arm/plat-<chip>/main.c */

// 1. HUK 读取（从 eFuse 控制器）
void tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
    /* 调用芯片厂商提供的 HAL 接口 */
    efuse_controller_read(EFUSE_BANK_HUK, 0,
                          hwkey->data, sizeof(hwkey->data));

    /* 注意: 如果 efuse 未烧录或读取失败，必须 panic */
    if (!is_efuse_programmed(EFUSE_BANK_HUK))
        panic("HUK not programmed!");
}

// 2. Die ID 读取
int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
    return efuse_controller_read(EFUSE_BANK_DIE_ID, 0, buffer, len);
}

// 3. 安全启动公钥
// 在 chip 的链接脚本中嵌入 Root CA 公钥
// 或从 eFuse 读取公钥 Hash 进行验证
```

---

#### 2. OEM/设备厂商

| 开发项 | 详细说明 | 交付物 |
|--------|----------|--------|
| OP-TEE 集成 | 移植 optee_os 到目标硬件 | 编译好的 optee_os 镜像 |
| PKCS#11 TA 配置 | 编译配置 `CFG_PKCS11_TA=y` | PKCS#11 TA 二进制 |
| optee_client | 编译 libteec + tee-supplicant | `libteec.so`、`tee-supplicant` |
| 灌装客户端 | 实现 provision-client (initramfs) | `provision-client` 二进制 |
| 灌装脚本 | 产线工控机侧灌装控制脚本 | `provision.sh` |
| TA 签名密钥 | 生成并保护 TA 签名私钥 | TA 签名证书 |
| 产线工装 | USB 通信、扫码枪对接、继电器控制 | 工装硬件 + 驱动 |

**开发内容：**

```bash
# OEM 需要编写的产线灌装脚本
# 文件: factory/provision.sh (工控机侧)

#!/bin/bash
# 产线灌装主控脚本
set -e

DEVICE_SERIAL=$(scan_barcode)               # 扫码枪读取序列号
check_serial_in_mes "$DEVICE_SERIAL"         # 校验序列号

usb_connect "$DEVICE_SERIAL"                 # USB 连接设备

# 步骤 1: 解锁 Token
send_command "provision-client --init-token \
    --so-pin $(kms_get_so_pin)"

# 步骤 2: 设置设备 User PIN
DEVICE_PIN=$(openssl rand -hex 16)           # 生成随机 PIN
send_command "provision-client --init-pin \
    --user-pin $DEVICE_PIN"

# 步骤 3: 生成设备密钥对（TEE 内生）
send_command "provision-client --gen-key \
    --key-type rsa:2048 \
    --label device-key"

# 步骤 4: 导出公钥请求证书
PUBKEY=$(send_command "provision-client --export-pubkey \
    --label device-key")
DEVICE_CERT=$(kms_sign_cert "$PUBKEY" "$DEVICE_SERIAL")
send_command "provision-client --import-cert \
    --value '$DEVICE_CERT'"

# 步骤 5: 注入对称密钥
OTA_KEY=$(kms_generate_aes256 "$DEVICE_SERIAL")
WRAPPED_KEY=$(kms_wrap_key "$OTA_KEY" "$PUBKEY")
send_command "provision-client --unwrap-key \
    --wrapped '$WRAPPED_KEY' \
    --label ota-key"

# 步骤 6: 锁定 Token
send_command "provision-client --lock-token"

# 步骤 7: 验证验证
verify_provision "$DEVICE_SERIAL"

# 步骤 8: 上报 MES
report_to_mes "$DEVICE_SERIAL" "PASS"

usb_disconnect
```

---

#### 3. 密钥管理系统 (KMS)

| 开发项 | 详细说明 | 交付物 |
|--------|----------|--------|
| 密钥生成 | 安全随机数生成器（符合 NIST SP 800-90A） | KMS 服务 |
| 密钥包装 | RSA-OAEP / AES-KW 等包装算法 | 密钥包装 API |
| 密钥存储 | HSM 或加密数据库存储主密钥 | 密钥库 |
| 设备密钥映射 | 序列号 ↔ 密钥映射关系管理 | 数据库表 |
| 安全通道 | TLS 双向认证 + 产线网络隔离 | 通信证书 |
| 审计日志 | 所有密钥操作记录 | 审计系统 |

**开发内容：**

```python
# KMS 核心服务（Python 伪代码）
# 文件: kms_server/app.py

from flask import Flask, request
from hsm import HSM
from crypto_utils import wrap_rsa_oaep

app = Flask(__name__)
hsm = HSM()

@app.route("/api/v1/provision/device-key", methods=["POST"])
def generate_device_key():
    """
    为设备生成密钥对
    产线工控机调用此接口获取设备公钥对应的证书
    """
    req = request.json
    device_serial = req["serial"]
    device_pubkey = req["pubkey"]

    # 1. 生成设备证书
    cert = ca_sign_csr(device_pubkey, device_serial)

    # 2. 生成 OTA 对称密钥
    ota_key = hsm.generate_aes(256)
    wrapped_ota_key = wrap_rsa_oaep(ota_key, device_pubkey)

    # 3. 记录审计日志
    audit_log(f"provision device {device_serial}: "
              f"cert issued, ota key wrapped")

    return {
        "device_cert": cert.decode("utf-8"),
        "wrapped_ota_key": wrapped_ota_key.hex(),
    }

@app.route("/api/v1/verify", methods=["POST"])
def verify_provision():
    """
    验证灌装结果
    """
    req = request.json
    device_serial = req["serial"]
    signature = req["signature"]
    device_cert = db.get_cert(device_serial)

    if verify_signature(device_cert, "verify test", signature):
        return {"status": "PASS"}
    else:
        return {"status": "FAIL"}
```

---

#### 4. CA 运营方

| 开发项 | 详细说明 | 交付物 |
|--------|----------|--------|
| Root CA 搭建 | 离线根证书生成 + 安全存储 | Root CA 证书（自签名） |
| 签发子 CA | 产线专用子 CA 证书 | 子 CA 证书 |
| 设备证书模板 | 定义证书字段：SN、OEM、设备类型等 | 证书模板 |
| OCSP 服务 | 证书状态在线查询（可选） | OCSP 响应服务 |
| CRL 发布 | 证书吊销列表 | CRL 文件 |

**开发内容：**

```bash
# CA 搭建脚本（产线 CA）
# 文件: ca/setup_production_ca.sh

#!/bin/bash
# 注意: Root CA 必须在离线环境中操作！

# 1. 生成 Root CA（离线）
openssl genrsa -aes256 -out root_ca.key 4096
openssl req -x509 -new -key root_ca.key \
    -days 3650 -out root_ca.crt \
    -subj "/C=CN/O=TBOX OEM/CN=TBOX Root CA"

# 2. 生成产线子 CA
openssl genrsa -aes256 -out factory_ca.key 2048
openssl req -new -key factory_ca.key \
    -out factory_ca.csr \
    -subj "/C=CN/O=TBOX OEM/CN=TBOX Factory CA"

# 3. Root CA 签子 CA（离线操作）
openssl x509 -req -in factory_ca.csr \
    -CA root_ca.crt -CAkey root_ca.key \
    -CAcreateserial -out factory_ca.crt \
    -days 1825 -extensions v3_ca \
    -extfile <(echo "[v3_ca]\nbasicConstraints=CA:TRUE")

# 4. 产线工控机上存放子 CA 证书和私钥（硬件加密保护）
# 子 CA 私钥可以存储在 USB Token 或 HSM 中
```

---

#### 5. 产线系统集成商

| 开发项 | 详细说明 | 交付物 |
|--------|----------|--------|
| USB 通信层 | USB Gadget 驱动 / CDC-ECM / RNDIS | 通信驱动 |
| 扫码枪对接 | 串口/USB 扫码枪数据解析 | 扫码模块 |
| MES 对接 | 产线执行系统接口（序列号校验、结果上报） | MES 客户端 |
| 可视化界面 | 工控机 GUI（操作指引、状态指示） | 灌装软件 |
| 异常处理 | 超时重试、掉电恢复、不良品标记 | 错误处理模块 |

---

## 三、四种灌装模式详细流程

### 模式 A: TEE 内生密钥（最安全，推荐）

```
  ┌── 安全世界 (TEE) ──┐        ┌── 产线工控机 ──┐
  │                     │        │                │
  │  ① PKCS#11 TA 加载  │        │  ② 发送 C_GenerateKeyPair  │
  │     init_persistent │◀───────│     请求(+SO PIN)          │
  │     等待灌装        │        │                             │
  │                     │        │                             │
  │  ③ TEE TRNG 生成    │        │                             │
  │     RSA 2048 密钥对 │        │                             │
  │                     │        │                             │
  │  ④ 私钥 → RPMB     │        │                             │
  │     (FEK 加密存储)  │        │                             │
  │                     │        │                             │
  │  ⑤ 返回公钥(n, e)  │───────▶│  ⑥ 公钥 → KMS 请求证书     │
  │                     │        │                             │
  │  ⑧ 接收 + 存储证书  │◀───────│  ⑦ KMS 返回设备证书        │
  │                     │        │                             │
  │  ⑨ Token 锁定只读   │        │  ⑩ 验证签名 + 报告 MES    │
  │                     │        │                             │
  └─────────────────────┘        └─────────────────────────────┘

  私钥流向: 生成 → TEE 内存 → RPMB 加密存储
            ↓ 永不离开 TEE

  开发要点:
  ├── TA 侧: 实现 C_GenerateKeyPair 命令处理
  ├── CA 侧: 实现 PKCS#11 URI + C_FindObjects 的密钥选择
  └── 产线侧: provision-client 封装 PKCS#11 命令
```

---

### 模式 B: KMS 加密注入（需要灾备场景）

```
  ┌── 密钥管理系统 ──┐      ┌── 产线工控机 ──┐      ┌── TEE ──┐
  │                  │      │                │      │         │
  │  ① 生成 AES-256  │      │                │      │         │
  │     OTA 密钥     │      │                │      │         │
  │                  │      │                │      │         │
  │  ② 获取设备公钥  │◀─────│  ②a 从 TEE 导出 │     │  ②b 内生 │
  │     (RSA-OAEP)   │      │     公钥        │◀────│   密钥对 │
  │                  │      │                │      │         │
  │  ③ RSA-OAEP 加密│      │                │      │         │
  │     密钥明文     │      │                │      │         │
  │          ↓       │      │                │      │         │
  │    enc_key =     │──────│  ④ 加密密钥     │─────▶│  ⑤ C_Unwrap│
  │    RSA-OAEP(     │      │     通过 USB    │      │   TEE 内   │
  │      ota_key,    │      │     传输        │      │   解密 +   │
  │      pubkey)     │      │                │      │   存储     │
  │                  │      │                │      │         │
  └──────────────────┘      └────────────────┘      └─────────┘

  密钥流向: KMS 生成 → RSA-OAEP 加密 → USB 传输 → TEE 解密 → RPMB
            ↓ 传输过程中全程密文

  关键安全设计:
  ├── 必须使用 RSA-OAEP（非 PKCS#1 v1.5）防 padding oracle 攻击
  ├── 传输密钥一次性使用，用后丢弃
  └── KMS 侧可以保留加密后的密钥副本用于灾备恢复
```

---

### 模式 C: 芯片级预置（封测阶段）

```
  ┌─────────────────────────────────────────────────────────┐
  │  半导体封测厂                                              │
  │                                                         │
  │  Wafer 测试 → 划片 → 封装 → 终测                          │
  │                              │                           │
  │                     ┌────────▼────────┐                  │
  │                     │  终测阶段写入:   │                  │
  │                     │  ├─ HUK (eFuse) │                  │
  │                     │  ├─ Root CA 公钥 │                  │
  │                     │  ├─ 芯片序列号   │                  │
  │                     │  ├─ Debug 锁定   │                  │
  │                     │  └─ 测试向量     │                  │
  │                     └────────┬────────┘                  │
  │                              │                           │
  │                    ┌─────────▼──────────┐                │
  │                    │  HUK 数据库映射表    │                │
  │                    │  ChipID → HUK Hash  │                │
  │                    │  → 出厂绑定记录     │                │
  │                    └────────────────────┘                │
  └─────────────────────────────────────────────────────────┘
                              │
                              ▼
  ┌─────────────────────────────────────────────────────────┐
  │  OEM SMT 贴片后:                                         │
  │                                                         │
  │  SoC 已具备: HUK + 安全启动 + Debug 锁定                  │
  │  → 只需要 SMT 后做模式 A 或 B 的密钥灌装                  │
  └─────────────────────────────────────────────────────────┘

  开发要求:
  ├── 芯片厂商提供 eFuse 烧录工具和脚本
  ├── 封测厂需要安全环境（加密室）
  └── HUK 数据库必须严格保护，仅限 RMA 时查询
```

---

### 模式 D: 产线 CA 签发完整 PKI 体系

```
                          ┌──────────────┐
                          │  离线 Root CA │
                          │  (HSM 保护)   │
                          └──────┬───────┘
                                 │ 自签名
                                 ▼
                    ┌─────────────────────┐
                    │  产线子 CA           │
                    │  (工控机 HSM / Token)│
                    └──────┬──────┬───────┘
                           │      │
              ┌────────────┘      └────────────┐
              ▼                                 ▼
  ┌─────────────────────┐          ┌─────────────────────┐
  │  产线 1: 设备证书    │          │  产线 2: 设备证书    │
  │  TBOX-001           │          │  TBOX-002           │
  │  签发:              │          │  签发:              │
  │  Subject:           │          │  Subject:           │
  │   CN=TBOX-001       │          │   CN=TBOX-002       │
  │   x509 v3:          │          │   x509 v3:          │
  │   TLS-Client        │          │   TLS-Client        │
  └─────────────────────┘          └─────────────────────┘

  设备证书内容:
  ├── Subject: CN = 设备序列号
  ├── SubjectAltName: TBOX-<序列号>
  ├── KeyUsage: digitalSignature, keyEncipherment
  ├── ExtendedKeyUsage: TLS Web Client Authentication
  └── Validity: 10 年

  开发要点:
  ├── CA 侧: 配置证书模板、有效期策略、CRL/OCSP
  ├── 设备侧: 支持 PKCS#11 URI 引用证书
  └── 产线侧: CSR 生成和证书导入自动化
```

---

## 四、四种模式对比选型

### 选型矩阵

| 维度 | A. TEE 内生 | B. KMS 注入 | C. 芯片预置 | D. CA 签发 |
|------|:----------:|:----------:|:----------:|:----------:|
| **私钥是否离 TEE** | ❌ 永不 | ✅ 密文传输后入 TEE | ❌ 芯片出厂已锁定 | ❌ 内生后导出公钥 |
| **密钥灾备恢复** | ❌ 不可恢复 | ✅ KMS 可恢复 | ❌ 不可恢复 | ✅ 证书可重签 |
| **产线吞吐量** | ★★★★ | ★★★ | ★★★★★ | ★★★★ |
| **产线复杂度** | ★★★ | ★★★★ | ★ | ★★★ |
| **设备唯一性** | ✅ HUK 绑定 | ✅ HUK 绑定 | ✅ eFuse 唯一 | ✅ 密钥唯一 |
| **防回滚能力** | ✅ RPMB | ✅ RPMB | ✅ eFuse OTP | ✅ RPMB |
| **安全等级** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **适用的密钥类型** | RSA/EC 非对称 | AES 对称密钥 | HUK/RootCA 公钥 | X.509 证书 |

### tbox 推荐组合方案

```
┌──────────────────────────────────────────────────────────────┐
│  tbox 量产推荐: 模式 A + C + D 组合                            │
│                                                              │
│  芯片封测阶段 (模式 C):                                       │
│  ├── HUK 写入 eFuse                                          │
│  ├── Root CA 公钥写入 eFuse                                   │
│  └── Debug 锁定                                               │
│                                                              │
│  产线灌装阶段 (模式 A + D):                                   │
│  ├── TEE 内生 RSA-2048 设备密钥对                              │
│  ├── 导出公钥 → 产线 CA 签发 X.509 证书                       │
│  ├── KMS 生成 OTA AES-256 密钥 → CIP_Unwrap 注入              │
│  └── Token 锁定为只读                                          │
│                                                              │
│  备选机制 (模式 B):                                           │
│  └── KMS 保留 OTA 密钥加密副本，用于 RMA 换板时恢复             │
└──────────────────────────────────────────────────────────────┘
```

---

## 五、各角色开发工作量估算

| 角色 | 开发项 | 预估人月 | 关键技能 |
|------|--------|---------|----------|
| **SoC 芯片厂** | eFuse 烧录工具 | 2 人月 | 芯片底层驱动 |
| | HUK 读取 API | 1 人月 | OP-TEE 平台移植 |
| | 安全启动链 | 3 人月 | BootROM + uboot |
| **OEM 设备厂** | optee_os 移植 | 3 人月 | ARM TrustZone |
| | PKCS#11 TA 集成 | 1 人月 | OP-TEE 构建 |
| | provision-client | 2 人月 | C/PKCS#11/libs |
| | 产线灌装脚本 | 1 人月 | Shell/Python |
| | 工装 USB 通信 | 1 人月 | USB Gadget |
| **KMS** | 密钥生成服务 | 2 人月 | HSM/密码学 |
| | 密钥包装 API | 1 人月 | RSA-OAEP/AES-KW |
| | 设备密钥数据库 | 1 人月 | PostgreSQL/加密存储 |
| | 审计日志 | 0.5 人月 | ELK/安全审计 |
| **CA** | Root CA 搭建 | 0.5 人月 | OpenSSL PKI |
| | 证书模板配置 | 0.5 人月 | X.509 v3 |
| | OCSP/CRL | 1 人月 | Web 服务 |
| **产线集成** | MES 对接 | 1 人月 | REST API |
| | GUI 界面 | 1 人月 | PyQt/Electron |
| | 异常处理框架 | 1 人月 | 状态机/容错 |
| **测试验证** | 产线测试 | 2 人月 | 自动化测试 |
| | 安全审计 | 1 人月 | 渗透测试/代码审计 |
| | 可靠性测试 | 1 人月 | 压力/老化测试 |
| **合计** | | **~25 人月** | |

---

## 六、产线架构总图

```
                         ┌──────────────────────────┐
                         │    企业 CA (离线)          │
                         │  Root CA + 子 CA          │
                         │  HSM 硬件保护              │
                         └────────────┬─────────────┘
                                      │ 定期签发并分发
                                      │ 产线子 CA 证书
                                      ▼
┌──────────────┐         ┌──────────────────────────┐
│  密钥管理系统  │         │    产线管理服务器           │
│  (KMS)       │◄────────│  ┌──────────────────┐    │
│  ┌────────┐  │  TLS    │  │ MES 对接         │    │
│  │HSM     │  │ 双向    │  │ 序列号管理        │    │
│  │密钥存储 │  │ 认证    │  │ 结果记录          │    │
│  └────────┘  │         │  └──────────────────┘    │
│  ┌────────┐  │         └───────────┬──────────────┘
│  │密钥生成 │  │                     │
│  │密钥包装 │  │                     │ 以太网
│  │审计日志 │  │                     │
│  └────────┘  │         ┌───────────▼──────────────┐
└──────────────┘         │     产线工控机 (x N)       │
                          │  ┌────────────────────┐  │
                          │  │ 灌装控制软件         │  │
                          │  │  ├─ USB 通信模块    │  │
                          │  │  ├─ 扫码枪驱动      │  │
                          │  │  ├─ 脚本引擎        │  │
                          │  │  └─ GUI 界面        │  │
                          │  └────────────────────┘  │
                          │  ┌────────────────────┐  │
                          │  │ 安全组件            │  │
                          │  │  ├─ 子 CA 私钥      │  │
                          │  │  │  (USB Token)    │  │
                          │  │  └─ KMS 客户端证书  │  │
                          │  └────────────────────┘  │
                          └───────────┬──────────────┘
                                      │ USB (RNDIS/CDC-ECM)
                    ┌─────────────────┼─────────────────┐
                    │                 │                   │
          ┌─────────▼─────┐  ┌───────▼────────┐  ┌──────▼─────────┐
          │ tbox 设备 1    │  │ tbox 设备 2    │  │ tbox 设备 N    │
          │ ┌───────────┐ │  │ ┌───────────┐  │  │ ┌───────────┐  │
          │ │ TEE       │ │  │ │ TEE       │  │  │ │ TEE       │  │
          │ │ PKCS#11 TA│ │  │ │ PKCS#11 TA│  │  │ │ PKCS#11 TA│  │
          │ │ 密钥注入   │ │  │ │ 密钥注入   │  │  │ │ 密钥注入   │  │
          │ └───────────┘ │  │ └───────────┘  │  │ └───────────┘  │
          └───────────────┘  └───────────────┘  └─────────────────┘

            产线环境要求:
            ├── 网络物理隔离（不连互联网）
            ├── 加密室 / 安全区域
            ├── UPS 不间断电源
            ├── 视频监控全覆盖
            └── 人员权限卡 + 双人操作
```

---

## 七、文档关联

| 本方案组件 | 对应 docs 文件 |
|------------|----------------|
| OP-TEE PKCS#11 TA 架构 | [02-pkcs11-route.md](02-pkcs11-route.md) |
| 密钥存储机制 | [05-key-storage.md](05-key-storage.md) |
| 系统能力要求 | [06-provisioning-requirements.md](06-provisioning-requirements.md) |
| 产线灌装流程 | [07-provisioning-procedure.md](07-provisioning-procedure.md) |
| 安全约束 | [08-provisioning-security.md](08-provisioning-security.md) |
| PIN 管理 | [09-pin-management.md](09-pin-management.md) |
| 多密钥访问控制 | [10-multiple-keys-access-control.md](10-multiple-keys-access-control.md) |
