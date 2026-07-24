# 五种方案对比与选型

## 总体技术链路图

```
[应用层] 调用 OpenSSL EVP API (EVP_EncryptInitEx, EVP_SealInit ...)
    │
    ├──────────────────────────────┬──────────────────────┬─────────────────┐
    ▼                              ▼                      ▼                 ▼
[libp11 ENGINE]              [Engine 直接]          [Provider]       [LD_PRELOAD]
    │                              │                      │
    ▼                              ▼                      ▼
[PKCS#11 Module]             [e_optee.so]          [optee_provider.so]
    │                              │                      │
    └──────────────┬───────────────┴──────────┬───────────┘
                   ▼                          ▼
             [libteec.so]          [Linux Kernel Crypto API]
                   │                     drivers/crypto/optee/
                   ▼
        SMC → OP-TEE Core → Crypto TA
```

---

## 方法一：OpenSSL Engine（传统方式）

**路线：** `OpenSSL ENGINE API → libteec → OP-TEE TA`

| 项目 | 说明 |
|------|------|
| 适用版本 | OpenSSL 1.x 全系；3.x 兼容模式但已标记废弃 |
| 工作原理 | 实现 `ENGINE` 结构体，注册算法回调。`EVP_EncryptInit_ex` 等标准 API 调用引擎的 `ciphers`/`digests` 方法，内部走 TEE Client API (`libteec`) 调用 OP-TEE TA |
| 代表实现 | [optee_engine](https://github.com/linaro-swg/optee_openssl_engine)（Linaro 官方维护，已归档） |
| 核心代码量 | ~800 行 C |

**优点：**
- OpenSSL 1.x 唯一官方方案，成熟稳定
- 应用无需改代码，`openssl.cnf` 配置引擎即可
- TA 可同时做密钥管理（密钥不出 TEE）

**缺点：**
- OpenSSL 3.x 已弃用 ENGINE，后续不再维护
- 不支持 OpenSSL 3.x 的 `OSSL_PROVIDER` 特性
- 每个上下文切换有开销

---

## 方法二：OpenSSL Provider（OpenSSL 3.x 推荐方式）

**路线：** `OSSL_PROVIDER → op-tee-provider → libteec → OP-TEE TA`

| 项目 | 说明 |
|------|------|
| 适用版本 | OpenSSL 3.0+ |
| 工作原理 | 实现一个 Provider，通过 `OSSL_ALGORITHM` 注册算法；内部使用 `EVP` 接口标准，底层通过 `libteec` 与 OP-TEE 通信 |
| 状态 | 社区有 prototype（optee_provider），但不如 Engine 成熟 |

**优点：**
- OpenSSL 3.x 唯一官方推荐的扩展方式
- 支持 Fetch + 懒加载，性能比 Engine 好
- 可叠加 Key Management Provider，密钥全生命周期在 TEE 内
- `openssl.cnf` 中 `default = optee_provider` 即可

**缺点：**
- 生态成熟度低于 Engine
- Provider 接口较 ENGINE 更复杂（`OSSL_DISPATCH`、`OSSL_CORE_HANDLE` 等）
- 部分算法在 FIPS 模式下不兼容

---

## 方法三：PKCS#11 Token + libp11

**路线：** `OpenSSL → p11-kit/libp11 → PKCS#11 module → OP-TEE PKCS#11 TA → Secure Storage`

| 项目 | 说明 |
|------|------|
| 适用版本 | OpenSSL 1.x / 3.x 均可 |
| 工作原理 | OP-TEE 官方提供了 [PKCS#11 TA](https://github.com/OP-TEE/optee_os/tree/master/ta/pkcs11)（GlobalPlatform TEE SAPI PKCS#11 兼容）。REE 侧写一个 PKCS#11 module 调用该 TA。OpenSSL 通过 `p11-kit` 或 `libp11 ENGINE` 接入 |
| 关键链路 | App → OpenSSL → libp11(pkcs11 ENGINE) → PKCS#11 module → libteec → PKCS#11 TA |

**优点：**
- 标准 PKCS#11 接口，第三方工具也能用（像 `pkcs11-tool`、`p11tool`）
- 密钥对象化管理（C_GenerateKeyPair / C_Sign / C_Encrypt 语义天然对齐）
- OP-TEE PKCS#11 TA 由官方维护，持续更新
- **密钥全生命周期在 TEE 内，满足"密钥不出安全域"合规要求**

**缺点：**
- 间接调用多，延迟比直接 Engine/Provider 高 1-2 倍
- libp11 仍是 ENGINE 机制（OpenSSL 3.x 降级使用）
- 需要 p11-kit 运行时环境

---

## 方法四：Linux Kernel Crypto API（af_alg / cryptodev）

**路线：** `OpenSSL → devcrypto ENGINE/Provider → /dev/crypto (AF_ALG) → OP-TEE crypto driver → Crypto TA`

| 项目 | 说明 |
|------|------|
| 适用版本 | OpenSSL 1.x / 3.x |
| 工作原理 | OP-TEE 在 Linux 内核侧注册 crypto 驱动（`drivers/crypto/optee/`）。应用层通过 Linux Crypto API (`AF_ALG` 套接字) 调用。OpenSSL 通过 `devcrypto ENGINE` 或自定义 Provider 桥接 |
| 内核驱动路径 | `drivers/crypto/optee/` — OP-TEE 上游已合入 |

**优点：**
- 完全在内核态完成，TA 调用路径最短（REE App → 内核 → OP-TEE）
- 不依赖用户态 libteec
- Linux Crypto API 标准统一，可同时被其他应用使用

**缺点：**
- OpenSSL 侧 `devcrypto engine` 已废弃且功能受限（仅对称加解密 + 哈希，无 RSA/ECC）
- 密钥管理能力弱（密钥在 REE 侧，无法做到密钥不出 TEE）
- 内核 → OP-TEE 的 SMC 调用上下文切换开销不可忽略
- `AF_ALG` 每操作需创建 socket，短操作性能差

---

## 方法五：LD_PRELOAD 符号劫持（不推荐）

**路线：** `LD_PRELOAD → 拦截 OpenSSL 符号 → libteec → OP-TEE TA`

| 项目 | 说明 |
|------|------|
| 适用版本 | 任何版本，不依赖 OpenSSL 扩展接口 |
| 工作原理 | 通过 `dlsym(RTLD_NEXT, ...)` 拦截 `EVP_EncryptInit_ex`、`EVP_DigestUpdate` 等符号，内部转发到 OP-TEE |

**优点：**
- 无需改 OpenSSL 配置、无需重编应用
- 原型验证极快（几小时可出 demo）

**缺点：**
- 维护成本极高（需跟踪每个 OpenSSL 版本内部符号行为）
- 部分静态链接的应用无法劫持
- 多线程/异步回调场景容易出 bug
- 仅适合原型验证，不可用于生产

---

## 横向对比总表

| 维度 | ① Engine | ② Provider | ③ PKCS#11 | ④ Kernel Crypto | ⑤ LD_PRELOAD |
|------|:--------:|:----------:|:----------:|:---------------:|:------------:|
| **OpenSSL 版本** | 1.x ✅ / 3.x ⚠️ | 3.0+ ✅ | 全系 ✅ | 全系 ✅ | 全系 ✅ |
| **未来兼容性** | ❌ 已废弃 | ✅ 官方方向 | ⚠️ 依赖 ENGINE | ⚠️ devcrypto 废弃 | ❌ 无保障 |
| **密钥不出 TEE** | ✅ | ✅ | ✅ | ❌ | ✅（看实现） |
| **延迟**（低→高） | ★★★ | ★★★ | ★★ | ★★★★ | ★★★ |
| **实现难度** | ★★★ | ★★★★ | ★★（TA 复用） | ★★★ | ★ |
| **维护方** | 社区（停滞） | 社区 | OP-TEE 官方 + 社区 | Linux 内核社区 | 自维护 |
| **生态兼容性** | 好 | 好 | 最好（非 OpenSSL 应用也能用） | 好（但弱） | 差 |
| **推荐场景** | OpenSSL 1.x 存量系统 | 新项目 OpenSSL 3.x | 需要密钥全生命周期管理 / 多工具共用 | 纯对称加解密兜底 | 仅原型验证 |

---

## 针对 tbox 平台的推荐

| 优先级 | 方案 | 原因 |
|--------|------|------|
| ⭐⭐⭐⭐⭐ | ③ PKCS#11 + OP-TEE PKCS#11 TA | OP-TEE 官方维护 PKCS#11 TA，车规级安全认证路径最短；GlobalPlatform 标准，过国密/CC 认证有现成路径；密钥全生命周期在 TEE 内 |
| ⭐⭐⭐ | ② Provider | OpenSSL 3.x 原生方案，更纯粹的 OpenSSL 生态，无需额外 PKCS#11 运行时 |
| ⭐⭐ | ① Engine | OpenSSL 1.x 存量系统兼容 |
| ⭐ | ④ Kernel Crypto | 对称加解密兜底，密钥管理弱 |
| ❌ | ⑤ LD_PRELOAD | 仅原型验证 |

### 推荐实现步骤

```
1. 确认内核开启了 OP-TEE 驱动 (CONFIG_TEE=y, CONFIG_OPTEE=y)
2. 确认 PKCS#11 TA 编译进 optee_os (CFG_PKCS11_TA=y)
3. 编译 optee_client 中的 optee_pkcs11 module → liboptee_pkcs11.so
4. 编译 libp11 (pkcs11 engine for OpenSSL)
5. 编写 openssl.cnf 加载 pkcs11 engine + optee_pkcs11 模块
6. 应用层无任何代码改动，直接调用 OpenSSL EVP API
```
