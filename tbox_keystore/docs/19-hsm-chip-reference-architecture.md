# 他人架构参考：HSM 安全芯片支撑 MQTTS 方案

> **来源**：网络搜集，BYD T-Box 项目基于 QUECTEL AG519M / MT2731 平台的 MQTTS SDK 对外交付文档
> **方案**：华大 CIU98B 独立安全芯片 + 定制 paho 补丁 + HSM ENGINE
> **文档原名**：`19-waibu.md`
> **本文档用途**：作为参考架构，与我们的 OP-TEE + tbox_keystore ENGINE 方案做对比分析

---

## 我们的架构 vs. 参考架构：异同分析

### 一句话总结

**架构思想相同，实现路径不同。** 两者都是"私钥在安全硬件内、REE 只拿到公钥、通过 OpenSSL 标准注入路径完成 TLS"，但安全硬件的形态和 TLS 层的接入方式不同。

### 对比总表

| 维度 | 参考架构（HSM 芯片） | 我们的架构（OP-TEE TA） |
|------|---------------------|------------------------|
| **安全硬件** | 华大 CIU98B 独立 HSM 芯片 | ARM TrustZone + OP-TEE |
| **私钥存储** | 芯片出厂烧录，不可更改 | TA 内 TEE_GenerateKey 生成，持久化到 REE FS / RPMB |
| **私钥操作** | HSM ENGINE（厂商 SDK `libhedsdk_ciu98b.so`） | 自研 tbox_keystore TA + `TEE_AsymmetricSignDigest` 等 |
| **ENGINE 形态** | 芯片厂商提供，通过 `libnlsafe.so` / `libtbox_delivery.so` 封装 | 自研 `e_tbox_keystore.so`，直接 TEEC → SMC → TA |
| **TLS 接入方式** | ① 改造 paho 源码加 `SSLSocket_setExternalConfigCallback` ② 回调中调 `ConfigSSLWithHsm(ctx)` 注入凭据 | ① 不改 paho ② OPENSSL_ENGINE 标准机制：`ENGINE_load_private_key` → ENGINE 回调 → TEEC → TA ③ TLS 层自控，paho 只用 TCP |
| **OpenSSL 版本** | 1.1.x（`libssl.so.1.1`） | 1.1.1w |
| **证书架构** | CA 链：Root CA → Sub CA → Device Cert | 自签名证书（当前 demo 阶段） |
| **目标应用** | MQTT over TLS（MQTTS） | MQTT over TLS / HTTPS / 通用 TLS |
| **SDK 形态** | 交付 .so + .h，三方链接即用 | 开源 TA + ENGINE 源码，交叉编译后部署 |
| **CPU 架构** | ARM 32-bit hard-float (cortexa7) | ARM 64-bit (aarch64) |
| **并发能力** | HSM 芯片内部串行化 | OP-TEE 3.2 REE FS 有限制，需 keyd 方案 |
| **密钥生命周期管理** | 芯片出厂定死，不可轮换 | 可生成、导入、删除、支持 OTA 密钥轮换 |

### 相同之处

```
目标一致:
  私钥全生命周期不出安全硬件
  上层应用只需调 OpenSSL 标准 API
  TLS 双向认证由安全硬件完成私钥操作

路径一致:
  应用 → OpenSSL → ENGINE → 安全硬件
  证书 + 私钥注入 SSL_CTX 由 ENGINE 自动完成
  应用层不持有私钥明文
```

### 不同之处

**1. 安全硬件形态**

- 参考：独立 HSM 芯片（华大 CIU98B），通过芯片厂商的 SDK 访问，`libhedsdk_ciu98b.so` → `libnlsafe.so` → `libtbox_delivery.so` 层层封装
- 我们：ARM TrustZone，OP-TEE OS + 自研 TA，通过 GP TEE Client API → SMC 指令访问

**2. paho 的 TLS 层接入方式**

```
参考架构:
  paho 改源码 → SSLSocket_setExternalConfigCallback(cb)
  paho 内部建 SSL_CTX → 检测到 "__EXTERNAL_CONFIG__"
  → 调 cb(ctx) → ConfigSSLWithHsm(ctx)
  → HSM ENGINE 自动提供私钥操作

我们的架构（方案 A — 当前）:
  paho 不改 → paho 只用 TCP 模式
  自己创建 SSL_CTX + ENGINE_load_private_key
  自己 SSL_connect → 走 ENGINE → TA
  SSL fd 传给 paho（或自实现 MQTT 协议）
```

参考架构的 paho 补丁方案很巧妙——在 `SSL_CTX` 创建之后、TLS 握手之前插入回调，由 HSM 封装库完成证书/私钥/CA 的注入。这是另一个维度的"不修改应用代码"。

**3. 证书体系**

- 参考：有 Root CA → Sub CA → Device Cert 的链式信任，由芯片内 `kCA` + `kSubCert` + `kDevicePrivateRsaCert` 三个槽位支持
- 我们：当前 demo 用自签名证书，生产可扩展到 CA 链架构

**4. 商业 vs 自研**

- 参考：SDK 以黑盒 .so 交付，三方只调 API，不清楚内部实现
- 我们：TA 和 ENGINE 全部开源，审计、调试、定制完全可控

### 关键启示

参考架构中 **paho 外部 SSL 配置回调** 的设计值得借鉴：

```
我们的方案 B（可替代当前的自控 TLS）:
  1. 给 paho 打最小补丁：新增 SSLSocket_setExternalConfigCallback
  2. 回调中调我们自己的 ENGINE 注册函数
  3. paho 内部建 SSL_CTX → 回调 → 我们注入 ENGINE key + cert + CA
  4. paho 仍用标准 MQTTClient_connect 完成 TLS + MQTT 协议层
```

这与我们在 [18-mqtt-mutual-auth-demo.md](18-mqtt-mutual-auth-demo.md) 中设计的"自控 TLS + 手动 MQTT 协议"方案是互补的两种路径——前者不依赖 paho TLS 层（零依赖），后者最大化复用 paho 能力（改动最小）。选用哪个取决于项目对 paho 功能的依赖程度。

---

以下是原始参考文档内容：

---

# MQTTS HSM SDK 对外交付说明

> 适用范围：基于 QUECTEL AG519M / MT2731 平台的 BYD T-Box 项目
> 目标读者：需要在本设备上开发 MQTTS（MQTT over TLS）客户端的三方应用开发者
> 源码路径：
> - HSM C 封装：`QUECTEL_AG519M_MT2731/meta/meta-byd/recipes-tbox/router/files/apps/delivery/src/utl_for_hsm_c.cpp`
> - 头文件：`QUECTEL_AG519M_MT2731/meta/meta-byd/recipes-tbox/router/files/apps/delivery/include/tbox/UtlForHsm.h`
> 文档版本：v3.1  2026-07-07

---

## 1. 概述

本 SDK 用于在设备上开发 MQTTS 客户端：**设备证书 / 私钥 / CA 链存储在 HSM
安全芯片中，明文私钥不出芯片**，由本 SDK 把这些材料注入 paho-mqtt-c 的
`SSL_CTX`，完成 TLS 双向认证。

包含两个组件：

| 组件 | 库                  | 头文件                       | 作用                                       |
|------|---------------------|------------------------------|--------------------------------------------|
| HSM  | `libtbox_delivery.so`   | `tbox/UtlForHsm.h`           | 初始化芯片 + 把芯片凭据注入 `SSL_CTX*`     |
| MQTT | `libpaho-mqtt3cs.so`（推荐）/ `libpaho-mqtt3as.so` | `MQTTClient.h` / `paho/SSLSocket.h` | 已打 BYD 补丁的 paho-mqtt-c 1.3.16，支持外部 SSL 配置回调 |

> `libtbox_delivery.so` 是 T-Box 的统一交付库，除了 HSM 接口外还包含 CAN / UDS / IPC / Zip / Curl 等 C 接口。本 SDK 只用到其中 HSM 部分（`InitHsm` / `ConfigSSLWithHsm`）。如需了解 delivery 全部能力，参见 `tbox/delivery.h`。

### 1.1 工作原理（关键）

paho-mqtt-c 原生只支持从文件加载证书 / 私钥。本 SDK 提供的 paho 库已带 BYD
扩展，新增两个能力：

1. `SSLSocket_setExternalConfigCallback(cb)` —— 注册一个外部 SSL 配置回调
   `int (*)(SSL_CTX* ctx)`。
2. 当 `MQTTClient_SSLOptions.privateKey` 被设为字符串 `"__EXTERNAL_CONFIG__"`
   时，paho 在内部建好 `SSL_CTX` 后会调上述回调，而**不**去读文件。

应用侧回调里调 `ConfigSSLWithHsm(ctx)`，由 HSM 把设备证书 / 私钥 / CA
链注入 `SSL_CTX`。这样：

- 应用完全不接触明文私钥；
- paho 仍按标准 `MQTTClient_connect` 流程做 TLS 握手与 MQTT 协议层；
- 三方只需 `#include` 本 SDK 头文件并链接本 SDK 自带的 `.so`，无需自行编译
  paho 或打补丁。

### 1.2 调用流程总览

```
┌──────────────────────────────────────────────────────────────┐
│ 1. InitHsm()                                     ← 本 SDK    │
│    初始化 HSM 安全芯片                                         │
│                                                              │
│ 2. SSLSocket_setExternalConfigCallback(my_cb)    ← paho 补丁  │
│    注册外部 SSL 配置回调；my_cb 内部调 ConfigSSLWithHsm        │
│                                                              │
│ 3. MQTTClient_create(...,"mqtts://host:port",...) ← paho     │
│    MQTTClient_setCallbacks(...)                              │
│                                                              │
│ 4. connectOptions.ssl->privateKey = "__EXTERNAL_CONFIG__"    │
│    MQTTClient_connect(client, &opts)            ← paho        │
│    paho 内部建 SSL_CTX → 调 my_cb → HSM 注入凭据 → TLS 握手  │
│                                                              │
│ 5. MQTTClient_subscribe / publishMessage / yield ← paho      │
│                                                              │
│ 6. MQTTClient_disconnect / destroy                           │
└──────────────────────────────────────────────────────────────┘
```
---

## 2. 交付物清单

```
mqtts_sdk_release/
├── include/
│   ├── tbox/                        # T-Box 交付库头文件
│   │   ├── UtlForHsm.h              # ← 声明 InitHsm / ConfigSSLWithHsm
│   │   ├── UtlForCurl.h             #  其它工具接口（非本 SDK 必须）
│   │   ├── UtlForZip.h
│   │   ├── delivery.h               #  完整 delivery C 接口
│   │   └── tbox_export.h            #  动态导出宏
│   ├── MQTTClient.h                 # paho 公开 API（顶层）
│   ├── MQTTAsync.h
│   ├── MQTTClientPersistence.h
│   ├── MQTTProperties.h
│   ├── MQTTReasonCodes.h
│   ├── MQTTSubscribeOpts.h
│   ├── MQTTExportDeclarations.h
│   └── paho/                        # paho 内部头（含补丁新增）
│       ├── SSLSocket.h              # ← 声明 SSLSocket_setExternalConfigCallback
│       └── ...（其它内部头，paho 自身使用的声明）
├── lib/
│   ├── libtbox_delivery.so          # T-Box 交付库（含 HSM → SSL_CTX 封装）
│   ├── librouter_common.so          # tbox_delivery 直接依赖，随 SDK 打包
│   ├── libpaho-mqtt3cs.so*          # 推荐：同步 + SSL（已带 BYD 补丁）
│   ├── libpaho-mqtt3as.so*          # 异步 + SSL
│   ├── libpaho-mqtt3c.so*           # 同步、明文（仅调试用）
│   └── libpaho-mqtt3a.so*           # 异步、明文
├── docs/
│   └── README.md                    # 本文档
└── examples/
    ├── paho_mqtts_demo.c            # 完整示例
    └── Makefile
```

### 2.1 库变体选择

| 库                    | API 模式 | TLS | 用途                                  |
|-----------------------|----------|-----|---------------------------------------|
| `libpaho-mqtt3cs.so`  | 同步     | 是  | **推荐**：与 HSM 配合最直接           |
| `libpaho-mqtt3as.so`  | 异步     | 是  | 事件回调 / 多 topic                   |
| `libpaho-mqtt3c.so`   | 同步     | 否  | 内网明文调试，**不走 HSM**            |
| `libpaho-mqtt3a.so`   | 异步     | 否  | 同上                                  |

> 与 HSM 配合**必须**选 `*cs` 或 `*as`（带 `s` 的 SSL 变体）。

### 2.2 平台与依赖

- 体系结构：ARM 32-bit hard-float (`cortexa7hf-neon-vfpv4`)
- OS：Linux
- OpenSSL：**必须 1.1.x**（`libssl.so.1.1` / `libcrypto.so.1.1`），不可与 3.x 混用
- paho-mqtt-c：1.3.16（已带 BYD 扩展，本 SDK 自带）

| 库                  | 是否随 SDK 打包 | 来源                 | 备注                                         |
|---------------------|-----------------|----------------------|----------------------------------------------|
| `libtbox_delivery.so` | 是              | T-Box delivery 库    | HSM → SSL_CTX 封装 + 其它工具接口            |
| `librouter_common.so` | 是              | T-Box router 公共库  | `libtbox_delivery.so` NEEDED，随 SDK 打包    |
| `libpaho-mqtt3cs.so` 等 | 是              | paho-mqtt-c 1.3.16   | 带外部配置回调补丁                           |
| `libssl.so.1.1`     | 否              | OpenSSL              | 设备镜像已自带                               |
| `libcrypto.so.1.1`  | 否              | OpenSSL              | 设备镜像已自带                               |
| `libnlnlog.so` / `libnlutils.so` / `libnlsafe.so` / `libnlipc.so` / `libminizip.so` | 否 | 平台 NL 中间件 | `librouter_common.so` NEEDED，设备镜像已自带 |
| `libhedsdk_ciu98b.so` | 否              | HSM 厂商 SDK         | 华大 CIU98B 驱动，由 `libnlsafe.so` 运行时加载 |
| `libstdc++.so.6` / `libpthread.so` / `libc.so.6` | 否 | 系统库   | glibc / libstdc++                            |

> 链接命令只需：`-ltbox_delivery -lpaho-mqtt3cs -lssl -lcrypto -lpthread`
> NL 系列库由 `librouter_common.so` 自动 NEEDED，应用无需显式链接。

---

## 3. API 参考

### 3.1 HSM 接口（`tbox/UtlForHsm.h`）

所有函数由 `libtbox_delivery.so` 导出（`TBOX_DLL_EXPORT`），C ABI。

```c
#include <openssl/ssl.h>
#include <tbox/UtlForHsm.h>

/* 类型 */
typedef enum { OTA_KEY, OTA_CERT, OTA_CA_CERT } HsmFileId;
typedef enum { kCBC, kECB, kCFB, kOFB } SysMode;

/* 生命周期 */
int InitHsm(void);

/* 单项凭据读取（细粒度诊断用） */
int             LoadFileFromHsmCache(HsmFileId id, void* data, size_t data_len, bool use_cache);
X509*           LoadCertFromHsmChip(HsmFileId id, bool use_cache);
EVP_PKEY*       LoadEvpKeyFromHsmChip(HsmFileId id, bool use_cache);
RSA*            LoadRsaKeyFromHsmCache(HsmFileId id, bool priv);
EC_KEY*         LoadEcKeyFromHsmCache(HsmFileId id, bool use_cache);          /* 当前为 stub，返回 nullptr */
EVP_CIPHER_CTX* LoadEvpCipherFromHsmCache(HsmFileId id, int sys_mode,
                                          void* iv, size_t iv_len,
                                          int pad_mode, bool encrypt);        /* 当前为 stub，返回 nullptr */

/* SSL_CTX 一次性装配（MQTTS 用） */
int ConfigSSLWithHsm(SSL_CTX* ctx);
```

#### `HsmFileId` 枚举

| 取值         | 对应芯片内文件                       |
|--------------|--------------------------------------|
| `OTA_KEY`    | 设备 RSA 私钥（`kDevicePrivateRsaKey`，经 HSM engine） |
| `OTA_CERT`   | 设备证书（`kDevicePrivateRsaCert`）  |
| `OTA_CA_CERT`| 根 CA（`kCA`）                       |

> 子 CA（`kSubCert`）当前未通过 `HsmFileId` 暴露，仅 `ConfigSSLWithHsm` 内部使用。

#### `InitHsm`

初始化 HSM 安全芯片（华大 CIU98B），准备密钥 / 证书读取能力。多次调用幂等。

| 返回值 | 含义                             |
|--------|----------------------------------|
| 0      | 成功（芯片初始化并 engine 就绪） |
| -1     | 失败：芯片未识别 / 初始化失败 / engine 加载失败 |

线程安全：内部加锁，多线程首次调用安全。
典型时机：进程启动后、第一次建 MQTTS 连接之前调一次。

#### `ConfigSSLWithHsm`

从 HSM 装入以下材料到调用方传入的 `SSL_CTX`：

- 设备证书（`kDevicePrivateRsaCert`）
- 设备私钥（`kDevicePrivateRsaKey`，经 HSM engine 使用，明文不出芯片）
- 子 CA（`kSubCert`）
- 根 CA（`kCA`）

并完成 `SSL_CTX_use_certificate` / `SSL_CTX_use_PrivateKey` /
`SSL_CTX_check_private_key` / `X509_STORE` 信任链构造。

| 返回值 | 含义                                          |
|--------|-----------------------------------------------|
| 0      | 成功                                          |
| 非 0   | 内部各阶段失败（芯片未就绪 / 证书 / 私钥 / 信任链构造等） |

> 通常 0 之外的返回都意味着生产烧录异常或芯片损坏，应用应拒绝启动 MQTTS。
> 如需定位是哪一项失败，改用下面单项读取函数分别尝试。

#### `LoadFileFromHsmCache`

按 `HsmFileId` 把芯片内对应文件的原始字节读到 `data` 缓冲区，最多 `data_len` 字节。

| 参数       | 说明                                   |
|------------|----------------------------------------|
| `id`       | `HsmFileId`，见上表                    |
| `data`     | 调用方分配的缓冲区                     |
| `data_len` | 缓冲区容量                             |
| `use_cache`| true 用进程内缓存，false 强制重读芯片  |


| 返回值 | 含义                       |
|--------|----------------------------|
| ≥ 0    | 实际拷贝字节数             |
| -1     | 文件为空或 `data_len == 0` |

#### `LoadCertFromHsmChip`

读取并解析 X.509 证书。返回的 `X509*` 由调用方持有，用完需 `X509_free` 释放。

| 返回值 | 含义                       |
|--------|----------------------------|
| 非 nullptr | 成功（调用方负责 `X509_free`） |
| nullptr    | 解析失败 / 文件不存在 |

#### `LoadEvpKeyFromHsmChip`

读取设备私钥到 `EVP_PKEY*`（通过 HSM engine，明文不出芯片）。返回值调用方持有，用完 `EVP_PKEY_free` 释放。

| 返回值 | 含义                       |
|--------|----------------------------|
| 非 nullptr | 成功（调用方负责 `EVP_PKEY_free`） |
| nullptr    | engine 未就绪 / key 加载失败 |

> 当前实现只有 `OTA_KEY` 对应 `kDevicePrivateRsaKey` 槽位有效，其它 `HsmFileId` 返回 nullptr。

#### `LoadRsaKeyFromHsmCache`

从缓存读取 RSA 私钥或公钥。

| 参数    | 说明                    |
|---------|-------------------------|
| `id`    | `HsmFileId`             |
| `priv`  | true=私钥，false=公钥   |

| 返回值 | 含义                                                |
|--------|-----------------------------------------------------|
| 非 nullptr | 成功（`RSA_free` 释放）                        |
| nullptr    | 缓存未命中 / 解析失败                              |

#### `LoadEcKeyFromHsmCache` / `LoadEvpCipherFromHsmCache`

> **当前为 stub**，直接返回 `nullptr`，未实现。EC 密钥与对称加密通道暂不可用，留给后续版本。

### 3.2 paho 外部配置回调（`paho/SSLSocket.h`）

补丁新增声明：

```c
typedef int (*SSLSocket_externalConfigCallback)(SSL_CTX* ctx);
void SSLSocket_setExternalConfigCallback(SSLSocket_externalConfigCallback cb);
```

- 调一次 `SSLSocket_setExternalConfigCallback(my_cb)` 全局生效；
- 当 `MQTTClient_SSLOptions.privateKey == "__EXTERNAL_CONFIG__"` 时，paho 在
  `SSL_CTX_new` 之后调 `my_cb(ctx)`；回调返回 0 视为成功，非 0 视为失败。
- 回调里调 `ConfigSSLWithHsm(ctx)` 即可。

### 3.3 paho 标准 API（`MQTTClient.h`）

本 SDK 不修改 paho 公开 API；使用方式与上游 paho-mqtt-c 1.3.16 一致：
`MQTTClient_create` / `MQTTClient_setCallbacks` / `MQTTClient_connect` /
`MQTTClient_subscribe` / `MQTTClient_publishMessage` /
`MQTTClient_receive` / `MQTTClient_disconnect` / `MQTTClient_destroy`。

---

---

## 4. 示例

`examples/paho_mqtts_demo.c` 是最小 MQTTS 客户端：初始化 HSM → 注册外部 SSL 回调 → 连 broker → 订阅 + 发布一条消息 → Ctrl-C 退出。

### 4.1 编译

```bash
cd examples
make                                   # host gcc 语法检查
make CC=arm-poky-linux-gnueabi-gcc     # 交叉编译
```

### 4.2 运行

```bash
# lib/* 已部署到 /usr/lib/：
paho_mqtts_demo mqtts://broker.example.com:8883 [topic]

# 就地（不部署 .so）：
LD_LIBRARY_PATH=../lib ./paho_mqtts_demo mqtts://127.0.0.1:8883
```

### 4.3 集成到自有工程

Makefile 片段：

```makefile
SDK_DIR := /path/to/mqtts_sdk_release
CFLAGS  += -I$(SDK_DIR)/include
LDFLAGS += -L$(SDK_DIR)/lib -Wl,-rpath,$(SDK_DIR)/lib
LIBS    := -ltbox_delivery -lpaho-mqtt3cs -lssl -lcrypto -lpthread
```

CMake 片段：

```cmake
set(MQTTS_SDK_DIR "/path/to/mqtts_sdk_release")
include_directories(${MQTTS_SDK_DIR}/include)
link_directories(${MQTTS_SDK_DIR}/lib)
target_link_libraries(your_app tbox_delivery paho-mqtt3cs ssl crypto pthread)
set_target_properties(your_app PROPERTIES
    BUILD_RPATH ${MQTTS_SDK_DIR}/lib
    INSTALL_RPATH ${MQTTS_SDK_DIR}/lib)
```

---

## 5. 约束与排错

### 5.1 OpenSSL 版本

`libtbox_delivery.so` 与 `libpaho-mqtt3cs.so` 都链接 OpenSSL 1.1.x
（`libssl.so.1.1` / `libcrypto.so.1.1`）。应用侧必须使用同一大版本，**不要在
同一进程里混用 OpenSSL 3.x 与本 SDK**，否则 `SSL_CTX` 结构体布局不一致会触发
段错误。

### 5.2 必须用 `mqtts://` 或 `ssl://` scheme

paho 只有在 URI 为 `mqtts://` / `ssl://` / `tls://` 时才会走 SSL 路径并触发外
部回调。`tcp://` / `mqtt://` 不会触发。

### 5.3 `__EXTERNAL_CONFIG__` 字符串不可省略

`MQTTClient_SSLOptions.privateKey` 必须设为字符串 `"__EXTERNAL_CONFIG__"`，
paho 补丁才会调外部回调。若同时设置了 `trustStore` / `keyStore` / `CApath`，
paho 仍会走原生文件加载路径——**不要**与 `__EXTERNAL_CONFIG__` 混用。CA 信任
链已由 `ConfigSSLWithHsm` 装入 `SSL_CTX`，无需在 SSLOptions 重复配置。

### 5.4 `MQTTClient_SSLOptions.struct_version`

参考代码使用 `struct_version = 5`（paho 1.3.16 支持）。低版本 struct 不含
`privateKey` 字段或行为不同，请勿降级。

### 5.5 HSM 错误码排错

| 现象 / 返回值                            | 可能原因                              |
|------------------------------------------|---------------------------------------|
| `InitHsm` 返回 -1                        | HSM 驱动未加载 / 芯片未上电           |
| `ConfigSSLWithHsm` 返回非 0              | 对应证书 / 私钥在芯片中不存在或损坏   |
| TLS 握手失败 "certificate verify failed" | broker 证书不是芯片内 CA 签发，或时钟未同步 |
| paho 报 "MQTTCLIENT_NULL_PARAMETER"      | `opts.ssl` 未设置                     |
| paho 走了文件路径（未调回调）            | `privateKey` 不是精确字符串 `__EXTERNAL_CONFIG__` |

更多排错细节可看 syslog（`LOG_AUTH` 设施），SDK 在失败路径会写
`[Utils][tid] ...`。

### 5.6 不支持的场景

- 不支持作为 TLS 服务端使用（设备私钥用于客户端双向认证）。
- 不支持导出明文私钥。HSM engine 设计上禁止。
- 不支持在 `ConfigSSLWithHsm` 之后再用 `SSL_CTX_use_PrivateKey` 或 paho
  的 `keyStore`/`privateKey` 文件路径覆盖，会破坏 engine 绑定。
- 设备凭据不可通过本 SDK 替换，仅可读用；更新走生产 / OTA 流程。

---

以下是参考代码：
/*
 * paho_mqtts_demo.c — MQTTS 最小示例
 *
 * 流程：InitHsm → 注册外部 SSL 配置回调 → MQTTClient_connect
 * （paho 内部建 SSL_CTX → 调回调 → ConfigSSLWithHsm 注入芯片凭据 → TLS 握手）
 *
 * 编译：make
 * 运行：paho_mqtts_demo mqtts://broker.example.com:8883
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include <MQTTClient.h>
#include <paho/SSLSocket.h>

#include <tbox/UtlForHsm.h>

static int running = 1;
static void sig_handler(int s) { (void)s; running = 0; }

static int onMessageArrived(void* ctx, char* topic, int topicLen, MQTTClient_message* msg)
{
    (void)ctx;
    printf("[RX] %.*s: %.*s\n", topicLen, topic, msg->payloadlen, (char*)msg->payload);
    MQTTClient_freeMessage(&msg);
    MQTTClient_free(topic);
    return 1;
}

static int sslConfigCb(SSL_CTX* ctx)
{
    return ConfigSSLWithHsm(ctx);
}


int main(int argc, char* argv[])
{
    const char* serverURI = "mqtts://127.0.0.1:8883";
    const char* clientId  = "tbox_demo";
    const char* topic     = "demo/test";
    const char* payload   = "hello from t-box";

    if (argc > 1) serverURI = argv[1];
    if (argc > 2) topic     = argv[2];

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* 1. 初始化 HSM */
    if (InitHsm() != 0) {
        fprintf(stderr, "InitHsm failed\n");
        return 1;
    }

    /* 2. 注册外部 SSL 配置回调 */
    SSLSocket_setExternalConfigCallback(sslConfigCb);

    /* 3. 创建 client + 注册消息回调 */
    MQTTClient client;
    int rc = MQTTClient_create(&client, serverURI, clientId,
                               MQTTCLIENT_PERSISTENCE_NONE, NULL);
    if (rc != MQTTCLIENT_SUCCESS) {
        fprintf(stderr, "MQTTClient_create failed: %d\n", rc);
        return 1;
    }
    MQTTClient_setCallbacks(client, NULL, NULL, onMessageArrived, NULL);

    /* 4. connect：privateKey="__EXTERNAL_CONFIG__" 触发回调 */
    MQTTClient_SSLOptions     ssl_opts  = MQTTClient_SSLOptions_initializer;
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;

    ssl_opts.struct_version = 5;
    ssl_opts.privateKey     = "__EXTERNAL_CONFIG__";   /* 关键 */

    conn_opts.keepAliveInterval = 60;
    conn_opts.cleansession     = 1;
    conn_opts.ssl              = &ssl_opts;
    conn_opts.connectTimeout   = 10;

    rc = MQTTClient_connect(client, &conn_opts);
    if (rc != MQTTCLIENT_SUCCESS) {
        fprintf(stderr, "connect failed: %d (%s)\n", rc, MQTTClient_strerror(rc));
        MQTTClient_destroy(&client);
        return 1;
    }
    printf("connected to %s\n", serverURI);

    /* 5. 订阅 + 发布 */
    MQTTClient_subscribe(client, topic, 1);

    MQTTClient_message msg = MQTTClient_message_initializer;
    MQTTClient_deliveryToken token;
    msg.payload    = (void*)payload;
    msg.payloadlen = (int)strlen(payload);
    msg.qos        = 1;
    MQTTClient_publishMessage(client, topic, &msg, &token);

    /* 6. 等消息，Ctrl-C 退出 */
    while (running) {
        MQTTClient_yield();
        usleep(100000);
    }

    MQTTClient_disconnect(client, 3000);
    MQTTClient_destroy(&client);
    return 0;
}