# 多业务密钥的访问控制与区分

## 核心澄清：PIN 不是用来选密钥的

PKCS#11 中有**两个完全独立的维度**：

```
C_Login(PIN)          ← 认证：证明你是谁（身份认证）
C_SignInit(obj)       ← 授权：选择用哪个密钥（权限控制）
C_FindObjects(attr)   ← 查找：按属性定位密钥
```

| 概念 | 类比 | 作用 |
|------|------|------|
| Token PIN | 门的锁密码 | 允许你进入 Token 区域 |
| CKA_ID / CKA_LABEL | 保险柜上的标签 | 告诉你哪个柜子里是什么 |
| CKA_PRIVATE / CKA_ENCRYPT | 柜子上的权限标签 | 规定谁能碰、能做什么 |

**结论：** 多个业务密钥**不需要**用 PIN 来区分。传入 NULL 只解决 PIN 认证问题，密钥选择通过对象属性（CKA_ID / CKA_LABEL）完成。

---

## 一、多密钥的典型场景

tbox 上常见的一组业务密钥：

```c
// Token 中的业务密钥清单（产线灌装时注入）

密钥 1: 设备身份密钥
  ├─ CKA_ID    = "device-key"
  ├─ CKA_LABEL = "TLS 客户端认证密钥"
  ├─ CKA_CLASS = CKO_PRIVATE_KEY
  ├─ CKA_KEY_TYPE = CKK_RSA
  ├─ CKA_SIGN  = CK_TRUE      // 允许签名（TLS 握手用）
  ├─ CKA_DECRYPT = CK_TRUE    // 允许解密（TLS key exchange）
  └─ CKA_EXTRACTABLE = CK_FALSE  // 不可导出

密钥 2: OTA 固件解密密钥
  ├─ CKA_ID    = "ota-key"
  ├─ CKA_LABEL = "OTA AES 解密密钥"
  ├─ CKA_CLASS = CKO_SECRET_KEY
  ├─ CKA_KEY_TYPE = CKK_AES
  ├─ CKA_DECRYPT = CK_TRUE     // 只允许解密
  ├─ CKA_ENCRYPT = CK_FALSE    // 不允许加密（防滥用）
  └─ CKA_EXTRACTABLE = CK_FALSE

密钥 3: 安全日志 HMAC 密钥
  ├─ CKA_ID    = "log-hmac-key"
  ├─ CKA_LABEL = "安全日志 HMAC-SHA256 密钥"
  ├─ CKA_CLASS = CKO_SECRET_KEY
  ├─ CKA_KEY_TYPE = CKK_SHA256_HMAC
  ├─ CKA_SIGN  = CK_TRUE      // 允许生成 HMAC
  ├─ CKA_VERIFY = CK_FALSE    // 不对外暴露验证能力
  └─ CKA_EXTRACTABLE = CK_FALSE

密钥 4: 远程诊断签名密钥
  ├─ CKA_ID    = "diag-key"
  ├─ CKA_LABEL = "远程诊断 ECDSA 签名密钥"
  ├─ CKA_CLASS = CKO_PRIVATE_KEY
  ├─ CKA_KEY_TYPE = CKK_EC
  ├─ CKA_SIGN  = CK_TRUE
  └─ CKA_EXTRACTABLE = CK_FALSE
```

---

## 二、HTTPS 场景下密钥怎么被选中的

### OpenSSL 引擎的选择路径（应用开发者视角）

```bash
# curl 使用设备证书和私钥:
curl --engine pkcs11 \
  --key "pkcs11:token=TBOX-ABCD1234;object=device-key" \    ← 选择 RSA 私钥
  --cert "pkcs11:token=TBOX-ABCD1234;object=device-cert" \  ← 选择 X.509 证书
  https://cloud.example.com
```

OpenSSL 引擎内部发生了什么：

```
curl --key "pkcs11:token=TBOX-...;object=device-key"
  │
  ▼
libp11 (pkcs11 engine) 解析 URI:
  ├─ token = "TBOX-ABCD1234"
  ├─ object = "device-key"
  │
  ▼
C_FindObjectsInit(session, template)
  template = { CKA_LABEL, "device-key", CKA_CLASS, CKO_PRIVATE_KEY }
  │
  ▼
C_FindObjects(session, &hKey, 1, &count)
  │
  ▼
C_SignInit(session, &mechanism, hKey)   ← 选定密钥
  │
  ▼
C_Sign(session, tls_handshake_hash, sig, &siglen)  ← 执行签名
```

**关键：密钥选择靠 CKA_LABEL / CKA_ID，不靠 PIN。**

### 代码中指定密钥的方式

```c
// 方式 1: PKCS#11 URI（最常用，OpenSSL / libp11）
// 格式: pkcs11:token=<TOKEN_LABEL>;object=<CKA_LABEL>
//       pkcs11:token=<TOKEN_LABEL>;id=<CKA_ID_HEX>
"pkcs11:token=TBOX-ABCD1234;object=device-key"
"pkcs11:token=TBOX-ABCD1234;object=ota-key"

// 方式 2: 显式 C_FindObjects（自研代码）
CK_OBJECT_HANDLE find_key(CK_SESSION_HANDLE session, const char *label) {
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &priv_key_class, sizeof(priv_key_class) },
        { CKA_LABEL, (void*)label, strlen(label) },
    };
    CK_OBJECT_HANDLE hKey;
    CK_ULONG count;

    C_FindObjectsInit(session, template, 2);
    C_FindObjects(session, &hKey, 1, &count);
    C_FindObjectsFinal(session);

    return count > 0 ? hKey : CK_INVALID_HANDLE;
}

// 使用:
CK_OBJECT_HANDLE dev_key = find_key(session, "device-key");
C_SignInit(session, &mechanism, dev_key);
```

---

## 三、多业务场景下的 PIN 管理（方案 B 的落实）

对于方案 B（TA 内自动 PIN），所有业务共享同一个 User PIN。访问控制的粒度靠**两个维度**实现：

### 维度 1：密钥属性控制（TEE 内强制执行）

```c
/* 产线灌装时设置每个密钥的权限属性 */

// OTA 密钥：只能解密，不能签名
uint8_t decrypt_true = CK_TRUE;
uint8_t encrypt_false = CK_FALSE;
uint8_t sign_false = CK_FALSE;

C_SetAttributeValue(session, hOtaKey, (CK_ATTRIBUTE[]){
    { CKA_DECRYPT, &decrypt_true, sizeof(CK_BBOOL) },
    { CKA_ENCRYPT, &encrypt_false, sizeof(CK_BBOOL) },
    { CKA_SIGN,    &sign_false, sizeof(CK_BBOOL) },
}, 3);

// 如果 OTA 升级模块试图用 ota-key 签名:
// C_SignInit(session, &mechanism, hOtaKey)
// → TA 内部检查: CKA_SIGN = CK_FALSE
// → 返回 CKR_KEY_FUNCTION_NOT_PERMITTED
// → 攻击被阻断
```

### 维度 2：密钥可以按进程隔离（Key Daemon + 方案 B 混用）

如果不同业务进程需要完全隔离（例如 OTA 模块不能使用设备签名密钥），可引入**轻量级 daemon**：

```
┌────────────────────────────────────────────────────────────┐
│  PKCS#11 TA (方案 B: 自动 PIN 登录)                         │
│  ├─ [设备签名密钥]  CKA_LABEL="device-key"                   │
│  ├─ [OTA 解密密钥]  CKA_LABEL="ota-key"                     │
│  └─ [日志 HMAC]    CKA_LABEL="log-hmac-key"                 │
└────────┬───────────────┬───────────────────┬───────────────┘
         │               │                   │
         ▼               ▼                   ▼
┌──────────────┐  ┌──────────────┐   ┌──────────────┐
│ TLS Daemon   │  │ OTA Agent    │   │ Log Service  │
│ (进程 A)     │  │ (进程 B)     │   │ (进程 C)     │
│             │  │              │   │              │
│ 只能调       │  │ 只能调       │   │ 只能调       │
│ C_Sign      │  │ C_Decrypt    │   │ C_Sign       │
│ device-key  │  │ ota-key      │   │ log-hmac-key │
└──────────────┘  └──────────────┘   └──────────────┘
```

**进程隔离的实现方式（不依赖 PIN）：**

```c
// 方式 A: Unix Domain Socket 转发（方案 C 简化版）
// 每个 daemon 只暴露特定的签名/解密端点，不暴露完整 PKCS#11

// 方式 B: seccomp + capabilities
// OTA Agent 进程使用 seccomp 过滤系统调用
// 即使 OTA Agent 中有漏洞，也无法调用 C_Sign
// 因为它根本打不开 PKCS#11 Module 的共享内存设备

// 方式 C: 不同 TA（最彻底）
// 为每个业务创建独立的 Trusted Application
// ┌─ Crypto TA for TLS ─┐   ┌─ OTA TA ────────────┐
// │  密钥: device-key    │   │  密钥: ota-key       │
// │  UUID: 1111-...     │   │  UUID: 2222-...     │
// │  通过 libteec 调用   │   │  通过 libteec 调用   │
// └─────────────────────┘   └─────────────────────┘
// → OTA 模块即使被攻破，也无法碰到 TLS 密钥
```

---

## 四、如果硬要用不同 PIN 区分密钥

如果业务需求要求"每个密钥有独立口令"（比如法规要求），PKCS#11 不支持"每个密钥独立 PIN"——但可以变通实现：

### 方案：多个 Token + 各自 PIN

```
┌────────────────────────────────────────────────┐
│  物理 Token 1  (SO PIN=ppp, User PIN=pin_A)    │
│  ├─ 密钥: device-key                            │
│  └─ 访问: TLS daemon (知道 pin_A)              │
│                                                │
│  物理 Token 2  (SO PIN=ppp, User PIN=pin_B)    │
│  ├─ 密钥: ota-key                              │
│  └─ 访问: OTA agent (知道 pin_B)              │
│                                                │
│  物理 Token 3  (SO PIN=ppp, User PIN=pin_C)    │
│  ├─ 密钥: log-hmac-key                         │
│  └─ 访问: Log service (知道 pin_C)            │
└────────────────────────────────────────────────┘
```

PKCS#11 TA 配置多个 Token：

```makefile
# optee_os 配置
CFG_PKCS11_TA_TOKEN_COUNT = 3   # 3 个 Token
```

每个 Token 有独立的：

| Token ID | Label | User PIN | 存储的密钥 | 用途 |
|----------|-------|----------|-----------|------|
| 0 | TBOX-xxx-TLS | pin_A | device-key | HTTPS TLS 客户端认证 |
| 1 | TBOX-xxx-OTA | pin_B | ota-key | OTA 固件解密 |
| 2 | TBOX-xxx-LOG | pin_C | log-hmac-key | 安全日志签名 |

每个业务进程只打开对应的 Token：

```c
// TLS daemon — 只访问 Token 0
C_GetSlotList(CK_TRUE, &slotId, &count);  // 找到 slot 0
C_OpenSession(slotId, ...);
C_Login(session, CKU_USER, pin_A, ...);   // 用 pin_A
// 只能操作 Token 0 中的密钥

// OTA agent — 只访问 Token 1
C_GetSlotList(CK_TRUE, &slotId, &count);  // 找到 slot 1
C_OpenSession(slotId, ...);
C_Login(session, CKU_USER, pin_B, ...);   // 用 pin_B
// 只能操作 Token 1 中的密钥
```

**但这种方式对方案 B（自动 PIN）来说，相当于每个 Token 需要一个自动 PIN 存储位置。**

### 更简洁的做法：在 TA 内用 CKA_ID 和 seccomp 做隔离

对 tbox 场景，更推荐**不拆分 Token，而是做进程权限隔离**：

```c
// 修改 PKCS#11 TA，在 TA 内部检验调用者的身份
//
// TA 记录每个 REE 进程的 UUID（OP-TEE 提供了这个能力）
// 然后建立白名单:
//   process TLS-daemon-UUID → 允许使用 device-key (CKR_OK)
//   process OTA-agent-UUID  → 允许使用 ota-key   (CKR_OK)
//   process OTA-agent-UUID  → 尝试使用 device-key → CKR_USER_NOT_LOGGED_IN
//
// 这样即使 OTA 进程被完全控制，也无法碰到 TLS 密钥

TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext,
                                      uint32_t cmdID,
                                      uint32_t paramTypes,
                                      TEE_Param params[4])
{
    /* 获取调用方的身份（OP-TEE 提供）*/
    TEE_Identity client_id;
    TEE_GetClientIdentity(&client_id);

    /* 如果是 C_SignInit，检查调用方是否有权使用该密钥 */
    if (cmdID == PKCS11_CMD_SIGN_INIT) {
        struct pkcs11_object *key = resolve_key_from_params(params);
        if (!is_process_allowed(client_id, key)) {
            return TEE_ERROR_ACCESS_DENIED;
        }
    }
    /* ... */
}
```

---

## 五、总结：NULL PIN 和密钥选择的关系

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  C_Login(NULL)  →  TA 自动注入 PIN → 认证通过                   │
│                    ╰── 这只是"开门"，不做密钥选择                 │
│                                                                 │
│  之后:                                                          │
│  C_FindObjects({ CKA_LABEL="device-key" }) → hKey=0x1001       │
│  C_SignInit(session, &mech, hKey=0x1001)                       │
│          ↑ 真正选密钥的是这里（对象句柄）                         │
│                                                                 │
│  再之后:                                                         │
│  C_Sign(session, data, sig, &len)                              │
│          ↑ 用句柄 0x1001 对应的密钥执行签名                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

| 你的疑问 | 答案 |
|----------|------|
| NULL PIN 用来区分密钥吗？ | **不是。** PIN 只做认证，密钥选择靠 CKA_ID / CKA_LABEL |
| 多个密钥共享同一个 PIN 安全吗？ | **安全。** 密钥本身的 CKA_SIGN/DECRYPT 属性限制了用途 |
| 需要在 TA 内区分业务吗？ | **可选。** 可用 TEE_GetClientIdentity 做进程级白名单 |
| 需要多个 Token 吗？ | **一般不需要。** 同一个 Token 放多个密钥，用属性控制 + 进程隔离 |
