# TBox 安全服务产品说明书

> 版本：v1.0 | 日期：2026-07-22 | 适用范围：基于 OP-TEE 的 TBox 车联网终端
>
> **产品定义**：TBox 安全服务是一套运行在 ARM TrustZone 可信执行环境中的密钥管理与密码学运算系统，为上层 HTTPS 和 MQTTS 通信提供端到端的硬件级安全能力。

---

## 第一章：产品概述

### 1.1 产品定义

TBox 安全服务在车载终端 SoC 的 ARM TrustZone 安全区域中运行，利用 OP-TEE 操作系统和自研密钥管理 TA（Trusted Application），为设备提供以下核心安全能力：

- **密钥生成与存储**：在安全区域内部生成 RSA/AES/SM2 等密钥，私钥永不出安全域
- **密码学运算**：RSA 签名/验签、AES 加解密、RSA PKCS#1 解密等操作在 TEE 内完成
- **TLS 双向认证**：通过 OpenSSL ENGINE 标准接口将密码学操作接入 HTTPS 和 MQTTS 协议栈
- **产线一机一密**：每台设备在工厂灌装唯一密钥，配合 CA 证书体系实现设备身份认证

### 1.2 核心价值

| 价值 | 说明 |
|------|------|
| **密钥不出安全域** | 私钥在 TEE 内生成、使用、销毁全生命周期不离开 ARM TrustZone |
| **标准协议兼容** | 通过 OpenSSL ENGINE API 无缝接入，应用层代码无需修改 |
| **一机一密** | 每台设备唯一密钥，设备身份可认证、可追踪、可吊销 |
| **硬件信任根** | 基于 SoC eFuse 中 HUK（硬件唯一密钥）的加密链，绑定芯片不可迁移 |
| **车规级合规** | 架构对齐 ISO 21434 / WP.29 UN R155，支持国密算法扩展 |

### 1.3 产品组件全景图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          TBox 安全服务产品组件                                │
│                                                                             │
│  ┌───────────────────────────┐  ┌───────────────────────────────────────┐  │
│  │   应用层                    │  │   证书 & 密钥管理                      │  │
│  │                           │  │                                       │  │
│  │  ┌──────┐ ┌────────────┐ │  │  ┌──────────┐  ┌───────────────────┐  │  │
│  │  │HTTPS  │ │ MQTTS      │ │  │  │ Root CA  │  │ KMS 密钥管理系统   │  │  │
│  │  │curl / │ │ paho +     │ │  │  │ 签发证书 │  │ 设备序列号↔公钥    │  │  │
│  │  │nginx  │ │ callback   │ │  │  └──────────┘  └───────────────────┘  │  │
│  │  └──┬───┘ └─────┬──────┘ │  │                                       │  │
│  │     │           │        │  └───────────────────────────────────────┘  │
│  │     └─────┬─────┘        │                                             │
│  │           │ OpenSSL EVP  │                                             │
│  └───────────┼──────────────┘                                             │
│              ▼                                                             │
│  ┌───────────────────────────┐  ┌───────────────────────────────────────┐  │
│  │   ENGINE 层 (REE)          │  │   TA 层 (Secure World)                │  │
│  │                           │  │                                       │  │
│  │  e_tbox_keystore.so       │  │  tbox_keystore TA                     │  │
│  │  ├─ RSA 签名/验签/解密     │  │  ├─ 密钥生成/导入/导出/销毁           │  │
│  │  ├─ TEEC 会话管理          │  │  ├─ PIN 管理 + Lock 机制              │  │
│  │  └─ 密钥 label → UUID 映射 │  │  ├─ 访问控制 (ACL)                    │  │
│  │              │            │  │  └─ TEE Internal API 密码学运算       │  │
│  └──────────────┼────────────┘  └────────────────┬──────────────────────┘  │
│                 │ TEEC / SMC                     │                         │
│                 └────────────────────────────────┘                         │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │   硬件层                                                               │  │
│  │   SoC eFuse (HUK)  ─── Secure Boot Chain  ─── RPMB / REE FS 安全存储  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 第二章：安全架构

### 2.1 可信执行环境

TBox 安全服务构建在 ARM TrustZone 技术之上。TrustZone 将 SoC 分为两个世界：

| | 普通世界（REE / Normal World） | 安全世界（TEE / Secure World） |
|------|------|------|
| 操作系统 | Linux | OP-TEE OS |
| CPU 模式 | Non-Secure | Secure (S-EL1) |
| 内存访问 | 仅 REE 内存 | REE 内存 + Secure RAM |
| 密钥可见性 | 仅公钥、label 字符串 | 全部密钥材料 |

REE 和 TEE 之间通过 SMC（Secure Monitor Call）指令通信。REE 侧应用使用 GP TEE Client API（libteec），TEE 侧 TA 使用 GP TEE Internal Core API。

### 2.2 密钥存储加密链

密钥在安全存储中全程密文保护，加密链根植于 SoC 的硬件唯一密钥：

```
SoC eFuse (HUK) — 硬件唯一密钥，每芯片不同，REE 无法访问
        │
        ▼
SSK = HMAC-SHA256(HUK, ChipID || "OP-TEE Secure Storage")
        │  安全存储密钥，OP-TEE 启动时生成，仅存于 Secure RAM
        ▼
TSK = HMAC-SHA256(SSK, TA_UUID)
        │  每个 TA 独立密钥，不同 TA 无法解密彼此的持久化对象
        ▼
FEK = PRNG() — 每个文件一个随机密钥
        │  用 TSK 加密存储于文件头
        ▼
数据 = AES-GCM-Encrypt(FEK, 密钥明文)
        │  每文件独立的 AES-256-GCM 加密 + 认证标签防篡改
        ▼
物理存储: /data/tee/<N> (REE FS)  或  eMMC RPMB 分区
```

**安全保证**：即使攻击者 dump 了 REE 侧全部文件系统，得到的也只是 AES-GCM 密文块。没有 HUK 无法派生出任何解密密钥。

### 2.3 密钥操作路径

以 TLS 握手签名（CertificateVerify）为例的完整调用链：

```
TLS 应用 (SSL_connect)
  → OpenSSL EVP_DigestSign
    → RSA_sign
      → e_tbox_keystore.so → rsa_sign 回调
        → TEEC_InvokeCommand(CMD_SIGN, "client-key", digest)
          → SMC #0 (CPU 切换到 Secure World)
            → OP-TEE Core → tbox_keystore TA
              → keystore_load("client-key") → 从安全存储恢复密钥
              → TEE_AsymmetricSignDigest(TEE_ALG_RSASSA_PKCS1_V1_5_SHA256)
                → 硬件 Crypto Cell / 软件 mbedTLS 执行 m^d mod n
                  ← 签名结果
```

### 2.4 安全启动信任链

```
BootROM (片上 ROM, 不可篡改)
  → 验证 SPL / U-Boot 签名 (公钥 Hash 来自 eFuse)
    → 验证 OP-TEE OS 签名
      → 验证 TA 签名
        → 验证 Linux Kernel + initramfs 签名
```

每级镜像的签名由上一级验证，信任锚固定在 SoC eFuse 中，形成不可绕过的信任链。

### 2.5 安全边界总结

| 攻击面 | 防护 | 等级 |
|--------|------|:---:|
| REE 直接读安全存储文件 | AES-GCM 加密，密钥在 TEE 内 | 机密性 ✅ |
| REE 篡改安全存储文件 | GCM 认证标签校验 | 完整性 ✅ |
| 物理 dump eMMC | 密钥链绑定 SoC HUK | 硬件绑定 ✅ |
| 替换 TA 二进制 | TA 签名验签 | 防篡改 ✅ |
| 回滚旧密钥文件 | RPMB 硬件写计数器 | 防回滚 ✅ |
| 恶意应用调用 TA | PIN + Lock 访问控制 | 访问控制 ✅ |

---

## 第三章：应用场景

### 3.1 场景总览

```
┌──────────────────────────────────────────────────────────────┐
│  云端                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────────┐ │
│  │ TLS Server   │  │ EMQX Broker │  │ KMS 密钥管理系统      │ │
│  │ (nginx/etc.) │  │ :8883       │  │ 设备注册 + 证书管理   │ │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬───────────┘ │
│         │                │                     │             │
│         │       TLS 双向认证 (1.2)              │             │
│         │    设备私钥操作在 TEE 内               │             │
│         │                │                     │             │
├─────────┼────────────────┼─────────────────────┼─────────────┤
│  管道   │  HTTPS GET/POST │  MQTT PUB/SUB       │  证书签发    │
├─────────┼────────────────┼─────────────────────┼─────────────┤
│  设备   │                │                     │             │
│  ┌──────┴──────┐  ┌─────┴────────┐  ┌─────────┴───────────┐ │
│  │ https_client │  │ mqtts_pub    │  │ gen_csr (ENGINE签名)│ │
│  │ curl --engine│  │ mqtts_sub    │  │ root-ca 签发证书     │ │
│  └──────┬──────┘  └─────┬────────┘  └─────────────────────┘ │
│         │               │                                    │
│         └───────┬───────┘                                    │
│                 ▼                                            │
│  ┌──────────────────────────────┐                            │
│  │ e_tbox_keystore.so (ENGINE)  │                            │
│  │ TEEC → SMC → OP-TEE → TA     │                            │
│  │ 私钥永不出 TEE               │                            │
│  └──────────────────────────────┘                            │
└──────────────────────────────────────────────────────────────┘
```

### 3.2 HTTPS 双向认证

设备通过标准 `openssl s_client` 或自研 https 客户端与云端 TLS 服务器建立双向认证连接。

**集成方式（应用代码零改动）：**

```c
// 一行切换：密钥操作自动路由到 TA
ENGINE_load_tbox_keystore();
ENGINE *e = ENGINE_by_id("tbox_keystore");
EVP_PKEY *pkey = ENGINE_load_private_key(e, "tls-key", NULL, NULL);
SSL_CTX_use_PrivateKey(ctx, pkey);
// 后续 TLS 握手自动使用 TEE 密钥
```

**测试验证：** `https_client` 程序通过 ENGINE 加载 TA 密钥，成功完成对 `openssl s_server` 的 HTTPS GET 请求。

### 3.3 MQTTS 双向认证

设备通过 paho.mqtt.c 库连接 EMQX Broker，TLS 层私钥操作通过 ENGINE 回调完成。

**集成方式：** paho 源码打最小补丁（新增 `SSLSocket_setExternalConfigCallback`），设置 `privateKey = "__EXTERNAL_CONFIG__"` 后 paho 自动调用 ENGINE 回调注入 TEE 凭据。

**支持的 MQTT 操作：** CONNECT、PUBLISH、SUBSCRIBE、PINGREQ、DISCONNECT，全部承载在 TEE 保护的 TLS 通道之上。

### 3.4 多业务密钥管理

不同业务使用独立密钥，label 前缀隔离：

| 业务 | Key Label | 证书 | 用途 |
|------|-----------|------|------|
| TLS 服务 | `tls-key` | tls.crt | HTTPS 双向认证 |
| OTA 升级 | `ota-key` | ota.crt | OTA 包签名验证 |
| 日志加密 | `log-key` | — | AES 对称加密 |
| MQTT 发布 | `pub-key` | pub.crt | 遥测数据上传 |
| MQTT 订阅 | `sub-key` | sub.crt | 远程指令接收 |

每个 key 可选权限位：`PERM_SIGN`、`PERM_VERIFY`、`PERM_ENCRYPT`、`PERM_DECRYPT`、`PERM_EXPORT_PUB`。

---

## 第四章：产线灌装方案

### 4.1 灌装流程

```
工厂工控机                          TBox 设备
    │                                  │
    ├─[1] 扫码序列号 ──────────────────►│ 上电，进入灌装模式
    ├─[2] 验证 HUK Hash ◄──────────────┤ 发送 ChipID + HUK 指纹
    │                                  │
    ├─[3] 发送 PIN ────────────────────►│ TA: --init-pin <PROVISION_PIN>
    │                                  │   PIN SHA-256 持久化到安全存储
    │                                  │
    ├─[4] 发送密钥生成指令 ─────────────►│ TA: --gen-rsa tls-key --gen-rsa ota-key
    │                                  │   密钥在 TEE 内生成，序列化落盘
    │                                  │
    ├─[5] 导出公钥 ◄───────────────────┤ TA: --export-pub → pubkey
    │    签发设备证书 ─────────────────►│
    │    KMS 注册 {序列号, 公钥, 证书}   │
    │                                  │
    ├─[6] 发送 Lock ───────────────────►│ TA: --lock (永久锁定写入)
    │                                  │
    └─[7] 断电，取走设备                 │
```

单台设备灌装耗时：约 8-15 秒。

### 4.2 证书签发流程

采用 Root CA 链式信任模型：

```
Root CA (自签名, root-ca.crt)
  │
  ├── gen_csr "tls-key" → tls.csr → 签发 → tls.crt
  ├── gen_csr "pub-key" → pub.csr → 签发 → pub.crt
  └── gen_csr "sub-key" → sub.csr → 签发 → sub.crt
```

- CSR（证书签名请求）由 `gen_csr` 工具通过 ENGINE 加载 TA 私钥签名
- Root CA 离线保管在工厂 HSM 或 KMS 中
- 设备证书部署到设备，Root CA 证书同时部署到设备和云端

### 4.3 灌装安全约束

| 约束 | 措施 |
|------|------|
| 物理安全 | 工厂车间门禁 + 摄像头监控 |
| 网络安全 | 工控机与设备直连 USB/专用 VLAN，不接入公网 |
| PIN 管理 | 灌装 PIN 由 KMS 生成，灌装完成后立即废弃 |
| Lock 机制 | 灌装完成后 TA 永久锁定，禁止新增/删除密钥 |
| 审计日志 | 每个设备的灌装记录包含时间戳、操作员、序列号、公钥指纹 |

---

## 第五章：开发集成

### 5.1 ENGINE SDK

**SDK 组成：**

| 组件 | 文件 | 用途 |
|------|------|------|
| ENGINE 共享库 | `libe_tbox_keystore.so` | 链接到应用进程，注册 OpenSSL ENGINE |
| TA 二进制 | `f8e9209a-*.ta` | 部署到 `/lib/optee_armtz/`，在 Secure World 运行 |
| 公开头文件 | `tbox_keystore_ta.h` | UUID、命令 ID 定义 |
| CA 工具 | `tbox_keystore` CLI | 命令行密钥管理（灌装、查询、签名等） |

**编译依赖：**

```
应用
├── libssl.so.1.1 + libcrypto.so.1.1   (OpenSSL 1.1.x)
├── libe_tbox_keystore.so               (ENGINE)
└── libpaho-mqtt3cs.so                  (MQTTS 场景，带补丁)
```

### 5.2 HTTPS 集成

应用层使用标准 OpenSSL API，仅需在 SSL_CTX 初始化时按 3.2 节方式加载 ENGINE 私钥。应用代码无需任何业务逻辑修改。

### 5.3 MQTTS 集成

```c
// 1. 注册外部 SSL 配置回调
SSLSocket_setExternalConfigCallback(tbox_ssl_config);

// 2. 创建 paho 客户端（ssl:// 触发 TLS 路径）
MQTTClient_create(&client, "ssl://broker:8883", "tbox-device", ...);

// 3. privateKey = "__EXTERNAL_CONFIG__" 触发回调
MQTTClient_SSLOptions ssl_opts = MQTTClient_SSLOptions_initializer;
ssl_opts.privateKey = "__EXTERNAL_CONFIG__";

// 4. 连接 — paho 内部调用回调 → ENGINE → TA 完成 TLS 握手
MQTTClient_connect(client, &conn_opts);

// 5. 正常 pub/sub
MQTTClient_publishMessage(client, topic, &msg, &token);
```

### 5.4 应用部署流水线

```
编译机 (x86-64)
  ├── 交叉编译 TA (aarch64-linux-gnu-gcc)
  ├── 交叉编译 ENGINE .so
  └── 交叉编译应用 (链接 ENGINE + paho)
       │
       ▼
  部署到 TBox 设备
  ├── TA → /lib/optee_armtz/
  ├── ENGINE → /usr/lib/
  ├── 应用 → /usr/bin/
  └── 证书 → /etc/tbox/certs/
```

---

## 第六章：运维与恢复

### 6.1 密钥生命周期状态机

```
UNSET ───init-pin──► SET ───gen-keys──► READY ───lock──► LOCKED ───final-lock──► FINAL
                         │                               │
                         └── 可生成/导入/删除 ────────────┘
```

| 状态 | 生成密钥 | 删除密钥 | 签名/验签 | 加解密 |
|------|:---:|:---:|:---:|:---:|
| UNSET | ❌ | ❌ | ❌ | ❌ |
| SET | ✅ | ✅ | ✅ | ✅ |
| LOCKED | ❌ | ❌ | ✅ | ✅ |
| FINAL | ❌ | ❌ | ✅ | ✅ |

### 6.2 误操作恢复机制

```
Lv0: 开发逃生    → 改 UUID 重新编译 TA / rm -rf /data/tee/*
Lv1: 产线窗口期 → 工控机签名 unlock 命令（N 小时内有效）
Lv2: SO PIN 恢复 → 管理员 PIN 验证后解锁（出厂前未 final-lock）
Lv3: RMA 物理恢复 → 设备退回工厂，HSM 签名恢复镜像
Lv4: 不可恢复     → final-lock 后彻底锁定，无恢复路径
```

### 6.3 设备退役与密钥销毁

1. 云端 KMS 吊销设备证书 → CRL/OCSP 生效
2. 设备端删除所有 TA 持久化对象
3. 安全存储分区擦除（REE FS: `rm -rf /data/tee/*` / RPMB: 硬件重置）
4. 审计日志记录销毁操作

### 6.4 常见故障排查

| 现象 | 检查点 |
|------|--------|
| ENGINE init 失败 | `ls /lib/optee_armtz/*.ta` 确认 TA 已部署 |
| `Key not found` | `tbox_keystore --info <label>` 确认密钥已灌装 |
| TLS 握手失败 | 检查证书是否由同一 Root CA 签发，时钟是否同步 |
| MQTT CONNECT 失败 | 先测 TCP (`telnet broker port`)，再查证书验证 |
| 跨进程冲突 | 每进程只访问自己的 key label，避免并发操作同一持久化对象 |

---

## 第七章：安全与合规

### 7.1 威胁模型

| 威胁 | 攻击面 | 防护 |
|------|--------|------|
| 提取私钥 | REE 内存 dump | 私钥仅在 TEE Secure RAM，REE 不可见 |
| 替换密钥 | 篡改安全存储文件 | AES-GCM 完整性校验 |
| 重放攻击 | 回滚旧密钥文件 | RPMB 硬件写计数器 |
| 伪造设备 | 克隆设备证书 | HUK 硬件绑定，换芯片失效 |
| 供应链攻击 | 替换 TA 二进制 | Secure Boot 验签链 |
| 侧信道攻击 | 时序/功耗分析 | HW Crypto Cell 常数时间运算 |

### 7.2 法规对齐

| 法规 | 要求 | 实现 |
|------|------|------|
| ISO 21434 | 道路车辆网络安全 | TARA 威胁分析 + 安全启动 + 密钥管理审计 |
| WP.29 UN R155 | 车辆网络安全认证 | OTA 安全更新 + 事件响应 |
| GDPR | 个人数据保护 | 密钥销毁证明 + 设备退役流程 |
| 国密 GM/T | 商用密码 | 架构支持 SM2/SM3/SM4 扩展 |

### 7.3 审计与可追溯性

- 产线灌装：每台设备记录 {时间, 序列号, 操作员, 公钥指纹}
- 设备证书：KMS 签发日志
- 密钥操作：TA 内每次 unlock/delete 递增计数器
- 设备退役：销毁操作写入 KMS 审计日志

---

## 附录 A：技术指标

| 指标 | 值 |
|------|-----|
| RSA-2048 签名延迟 | < 50 ms（TEE 内运算） |
| RSA-2048 密钥存储 | ~3 KB / 个 |
| 最大密钥数量 | 受安全存储分区大小限制（典型 ~100 个） |
| OpenSSL 版本 | 1.1.1w |
| paho.mqtt.c 版本 | 1.3.16（带补丁） |
| 安全存储后端 | REE FS（开发）/ RPMB（量产） |
| 并发模型 | OP-TEE 3.2: 每进程独立 session + session 缓存 |

---

## 附录 B：术语表

| 术语 | 说明 |
|------|------|
| TEE | Trusted Execution Environment，可信执行环境 |
| REE | Rich Execution Environment，普通执行环境（Linux） |
| TA | Trusted Application，运行在 TEE 中的应用程序 |
| CA | Client Application，运行在 REE 中调用 TA 的程序 |
| HUK | Hardware Unique Key，SoC eFuse 中的硬件唯一密钥 |
| SSK | Secure Storage Key，由 HUK 派生的安全存储密钥 |
| TSK | TA Storage Key，每个 TA 独立的存储密钥 |
| FEK | File Encryption Key，每个持久化文件一个的加密密钥 |
| ENGINE | OpenSSL 的扩展机制，用于将密码学操作外挂到外部硬件 |
| RPMB | Replay Protected Memory Block，eMMC 防回滚安全分区 |
| KMS | Key Management System，密钥管理系统 |

---

## 附录 C：相关技术文档

| 文档 | 内容 |
|------|------|
| [01-architecture-overview.md](01-architecture-overview.md) | 五种实现方案对比与选型 |
| [05-key-storage.md](05-key-storage.md) | 密钥 TEE 内存储机制详解 |
| [07-provisioning-procedure.md](07-provisioning-procedure.md) | 产线灌装详细流程 |
| [13-openssl-engine-integration.md](13-openssl-engine-integration.md) | ENGINE 集成完整方案 |
| [14-brick-recovery-and-best-practices.md](14-brick-recovery-and-best-practices.md) | 变砖场景与救砖方案 |
| [15-engine-debug-issues.md](15-engine-debug-issues.md) | ENGINE 调试 15 个问题全记录 |
| [16-multi-process-concurrency-analysis.md](16-multi-process-concurrency-analysis.md) | 多进程并发分析 |
| [18-mqtt-mutual-auth-demo.md](18-mqtt-mutual-auth-demo.md) | MQTT 双向认证方案 |
| [20-mqtts-debug-issues.md](20-mqtts-debug-issues.md) | MQTTS 调试 7 个问题全记录 |
| [engine/README.md](../engine/README.md) | ENGINE 构建说明 |
| [mqtts/README.md](../mqtts/README.md) | MQTTS 构建说明 |
