# HTTPS 应用中 PIN 码管理与无感调用方案

## 核心矛盾

```
TEE 保护密钥 → 需要 PIN 认证才能访问 → PIN 每次写在应用层 → 新的攻击面
```

要解决的问题：HTTPS 应用（curl / nginx / 自研客户端）需要在**不暴露 PIN 码**的前提下，无缝使用 TEE 内的密钥进行 TLS 握手。

---

## 一、OpenSSL Engine 配置：不需要每个应用配

系统级一次性配置，所有依赖 OpenSSL 的应用自动共享：

```ini
# /etc/ssl/openssl.cnf — 全局配置
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/engines-3/libpkcs11.so
MODULE_PATH = /usr/lib/liboptee_pkcs11.so

# 关键：不在这里配 PIN —— 见下文分析
# PIN = 123456   ← ❌ 绝对不要这么做
```

配置后以下应用自动走 PKCS#11 引擎，**无需逐个应用配置**：

```
/usr/bin/curl
/usr/bin/wget
/usr/sbin/nginx
/usr/bin/git
/usr/bin/python3 （通过 ssl 模块调用的 OpenSSL）
自研 HTTPS 客户端（基于 OpenSSL BIO/SSL 接口）
```

---

## 二、PIN 码暴露的风险分析

### PIN 暴露路径全景

```
攻击面                             风险等级        攻击成本
─────────────────────────────────────────────────────────
openssl.cnf 明文写 PIN             ❌ 极高       cat 即可
环境变量 OPENSSL_PIN              ❌ 高         /proc/<pid>/environ
应用启动参数 --pin 1234           ❌ 高         ps aux
文件 /etc/pkcs11_pin 0644         ❌ 高         任何用户可读
文件 /etc/pkcs11_pin 0400 root    ⚠️ 中        需要 root
进程间传递句柄                     ✅ 低        需要 ptrace
TEE 内直接管理（应用完全不知PIN）   ✅ 极低        无法从 REE 侧接触
```

### 为什么不能写死在 openssl.cnf

```ini
[pkcs11_section]
PIN = 12345678          # ← 灾难！任何能读这个文件的进程都可以使用所有密钥
```

攻击场景：
1. 攻击者通过 Web 漏洞拿到 www-data 用户权限
2. `cat /etc/ssl/openssl.cnf` → 看到 PIN
3. 使用 PKCS#11 tool 或 OpenSSL 命令导出/使用所有密钥
4. 密钥完全失效

---

## 三、四种 PIN 管理方案

### 方案 A：PIN 文件 + 权限管控

```
           ┌──────────────────────────────────┐
           │  PIN 存储文件                      │
           │  /mnt/secure/pkcs11_pin           │
           │    → owner: root   group: root     │
           │    → permissions: 0400            │
           │    → 内容: 产线随机生成的 128 位 hex │
           │    → 产线灌装时写入，每台设备唯一     │
           └────────────────┬─────────────────┘
                            │
                            ▼
           ┌──────────────────────────────────┐
           │  PKCS#11 Module 自动读取 PIN      │
           │                                   │
           │  liboptee_pkcs11.so 中实现:        │
           │                                   │
           │  CK_RV C_Login(session, type,     │
           │            pin, len) {            │
           │      if (pin == NULL || len == 0) {│
           │          pin = read_file(          │
           │              "/mnt/secure/"        │
           │              "pkcs11_pin");        │
           │      }                            │
           │      return real_C_Login(pin);     │
           │  }                                 │
           └────────────────┬─────────────────┘
                            │
                            ▼
           ┌──────────────────────────────────┐
           │  应用层: 传 NULL 或空             │
           │                                   │
           │  curl --engine pkcs11 \           │
           │    --key "pkcs11:token=..."       │
           │    # 不需要 --pass 参数            │
           │                                   │
           │  /* 代码中 */                      │
           │  C_Login(session, CKU_USER,       │
           │    NULL_PTR, 0);  // 无感       │
           └──────────────────────────────────┘
```

**优点：**
- 应用不需要知道 PIN
- 文件权限 0400 + root:root，普通进程无法读取
- 产线灌装时写入，每台设备不同
- 实现简单，不需改 TA

**缺点：**
- 如果攻击者拿到 root，可以读取 PIN 文件
- 但 root 在嵌入式场景中已是边界——设备已被攻破

**产线灌装时的写入逻辑：**

```bash
# 产线脚本中
PIN=$(openssl rand -hex 16)  # 128 位随机数
echo "$PIN" > /mnt/secure/pkcs11_pin
chown root:root /mnt/secure/pkcs11_pin
chmod 0400 /mnt/secure/pkcs11_pin

# 同时也用这个 PIN 初始化 Token
optee_pkcs11_client --init-pin \
    --so-pin "$SO_PIN" \
    --user-pin "$PIN"
```

---

### 方案 B：TA 内部自动管理 PIN（最安全）

```
    应用层                          Secure World
  ┌────────┐   C_Sign()     ┌──────────────────────────┐
  │ curl   │───────────────▶│  PKCS#11 TA              │
  │ nginx  │  无需 PIN      │  ├─ 收到 C_Login(NULL)    │
  │ 自研   │                │  ├─ 从 RPMB 读取 PIN 密文 │
  └────────┘                │  ├─ 解密得到实际 PIN      │
       ▲                    │  ├─ 内部调用验证逻辑       │
       │   签名结果          │  └─ 返回 CKR_OK          │
       └────────────────────└──────────────────────────┘
```

**实现：修改 PKCS#11 TA 源码**

```c
/* 修改 pkcs11_ta.c — 自动处理 PIN 验证 */

static enum pkcs11_rc verify_user_pin(struct pkcs11_session *session,
                                       const uint8_t *pin, size_t pin_size)
{
    /* 如果应用层传了 PIN，就用它验证（兼容老用法） */
    if (pin && pin_size > 0) {
        return verify_pin(PKCS11_CKU_USER, pin, pin_size,
                          session->token->db_main->user_pin_salt,
                          session->token->db_main->user_pin_hash);
    }

    /* ⭐ 如果应用层没传 PIN（或传 NULL），TA 自动从 RPMB 读取 */
    uint8_t auto_pin[64];
    size_t auto_pin_size = sizeof(auto_pin);

    /* 打开 RPMB 中的 PIN 加密存储对象（产线灌装时写入） */
    TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE_RPMB,
                             &PIN_SECRET_UUID,
                             TEE_DATA_FLAG_ACCESS_READ,
                             &pin_secret_handle);
    TEE_ReadObjectData(pin_secret_handle, auto_pin, &auto_pin_size);
    TEE_CloseObject(pin_secret_handle);

    return verify_pin(PKCS11_CKU_USER, auto_pin, auto_pin_size,
                      session->token->db_main->user_pin_salt,
                      session->token->db_main->user_pin_hash);
}

/* 修改 entry_ck_login，当 pin 为 NULL 时走自动路径 */
enum pkcs11_rc entry_ck_login(struct pkcs11_client *client,
                              uint32_t ptypes, TEE_Param *params)
{
    /* ... 解析参数 ... */

    if (pin_size == 0 || pin == NULL) {
        /* 自动登录模式 — 从 RPMB 读取 */
        rc = verify_user_pin(session, NULL, 0);
    } else {
        /* 传统模式 — 用传入的 PIN */
        rc = verify_user_pin(session, pin, pin_size);
    }

    /* ... */
}
```

**产线灌装时额外步骤：**

```bash
# 产线脚本新增：将 PIN 写入 RPMB 加密区域
PIN=$(openssl rand -hex 16)

# 调用自定义 TA 命令，将 PIN 安全存入 RPMB
# PIN 在 TEE 内部以 AES-GCM 加密后存储在 RPMB 中
optee_custom_client --store-pin \
    --pin "$PIN" \
    --store-id "user-pin"

# 同时初始化 Token 的 PIN
optee_pkcs11_client --init-pin \
    --so-pin "$SO_PIN" \
    --user-pin "$PIN"
```

**优点：**
- PIN 在 Secure RAM 中处理，REE 完全不可见
- 应用层传 NULL 指针即可
- 无法从 REE 侧任何路径获取 PIN
- 即使拿到 root 也无法读取 TA 内部存储

**缺点：**
- 需要修改 PKCS#11 TA 源码（optee_os/ta/pkcs11/）
- 需要维护自己的 optee_os 分支
- TA 的"自动登录"行为编译后固定，无法运行时切换

---

### 方案 C：Key Daemon + Unix Socket（适合多进程隔离）

```
┌─────────────────────┐
│  pkcs11-daemon      │  ← 系统服务，开机自启
│                     │
│  1. 读取 PIN 文件    │
│  2. C_OpenSession() │
│  3. C_Login(PIN)    │
│  4. 保留 Session    │
│  5. 对外提供 Unix    │
│     Socket 接口      │
│     (签名/解密请求)  │
└────────┬────────────┘
         │ Unix Domain Socket
         │ (权限 0700, sock 文件)
         ▼
┌─────────────────────┐
│  libp11-passthrough │  ← 替代 libp11 的引擎插件
│                     │
│  不是直接调 C_Sign  │
│  而是通过 socket    │
│  转发到 daemon      │
└─────────────────────┘
```

**进程隔离效果：**

```
PID   USER     COMMAND
1     root     /sbin/init
234   root     /usr/bin/pkcs11-daemon    ← 唯一持有 PIN 的进程
312   tls-svc  /usr/sbin/nginx            ← 通过 socket 请求签名
345   tls-svc  /usr/bin/tbox-cloud-client ← 同上
```

**daemon 接口定义（protobuf）：**

```protobuf
service PKCS11Daemon {
    // 签名
    rpc Sign(SignRequest) returns (SignResponse);
    // 解密
    rpc Decrypt(DecryptRequest) returns (DecryptResponse);
    // 获取公钥
    rpc GetPublicKey(GetKeyRequest) returns (GetKeyResponse);
}

message SignRequest {
    bytes data = 1;       // 待签名数据
    string key_id = 2;    // 密钥标识，如 "device-key"
    uint32 mechanism = 3; // CKM_RSA_PKCS, CKM_ECDSA...
}

message SignResponse {
    bytes signature = 1;
    uint32 rv = 2;        // PKCS#11 返回码
}
```

**优点：**
- 只有 daemon 进程知道 PIN
- 普通应用进程即使被攻破，也拿不到 PIN（只能请求签名）
- 可以加审计日志：记录每次签名请求的来源 + 数据 hash
- 粒度访问控制：可限制每个调用方只能使用指定密钥

**缺点：**
- 多一层进程间通信，延迟增加 ~1-2ms
- daemon 崩溃 → 所有 TLS 连接中断
- 实现工作量大（daemon + protobuf + 客户端 SDK + 重启恢复）
- 需要处理并发访问和连接池

---

### 方案 D：Session 缓存 + 一次登录（最简单）

PKCS#11 标准中，每个密钥对象有 `CKA_ALWAYS_AUTHENTICATE` 属性：

```c
/* 产线灌装时设置密钥属性 */
uint8_t always_auth = CK_FALSE;   // 不需要每次都输入 PIN
set_attribute(obj, CKA_ALWAYS_AUTHENTICATE, &always_auth, sizeof(bool));
```

**含义对比：**

| 属性值 | 行为 |
|--------|------|
| `CKA_ALWAYS_AUTHENTICATE = CK_FALSE` | 在 Session 中 C_Login 一次后，后续所有操作不再需要 PIN |
| `CKA_ALWAYS_AUTHENTICATE = CK_TRUE` | 每次 C_Sign/C_Encrypt 前都必须重新 C_Login |

**配合 Session 缓存的用法：**

```c
/* 应用层：只需要在连接开始时登录一次 */
static CK_SESSION_HANDLE g_session;
static int g_logged_in = 0;

void ensure_session(void) {
    if (!g_logged_in) {
        C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL, NULL, &g_session);
        C_Login(g_session, CKU_USER, PIN, PIN_LEN);
        g_logged_in = 1;
        /* 此后所有 C_Sign / C_Encrypt 无需再输入 PIN */
    }
}

void tls_sign(const uint8_t *data, size_t len,
              uint8_t *sig, size_t *siglen) {
    ensure_session();
    /* 直接在已登录的 Session 上操作 */
    C_SignInit(g_session, &mechanism, hPrivateKey);
    C_Sign(g_session, data, len, sig, siglen);
}

void tls_decrypt(const uint8_t *cipher, size_t len,
                 uint8_t *plain, size_t *plainlen) {
    ensure_session();
    C_DecryptInit(g_session, &mechanism, hSecretKey);
    C_Decrypt(g_session, cipher, len, plain, plainlen);
}
```

**OpenSSL 侧配合 — libp11 的 PIN 回调：**

```c
/* 应用代码：注册 PIN 回调，从安全文件读取 */
static int get_pin_cb(char *buf, int len, int flags, void *userdata)
{
    int fd = open("/mnt/secure/pkcs11_pin", O_RDONLY);
    if (fd < 0) return -1;
    int n = read(fd, buf, len - 1);
    close(fd);
    buf[n] = '\0';
    return n;
}

int main()
{
    PKCS11_CTX *ctx = PKCS11_CTX_new();
    PKCS11_CTX_load(ctx, "/usr/lib/liboptee_pkcs11.so");

    /* 注册 PIN 回调，而非硬编码 */
    PKCS11_set_pin_callback(ctx, get_pin_cb, NULL);

    /* 后续 OpenSSL EVP 操作自动通过回调获取 PIN */
}
```

**优点：**
- 实现最简单，只需注册回调
- Session 缓存后，后续 TLS 握手零额外交互

**缺点：**
- PIN 仍短暂出现在应用进程内存中
- 如果攻击者能 dump 进程内存（ptrace），可获取 PIN

---

## 四、四种方案对比

| 维度 | A. PIN 文件 + Module 内读 | B. TA 内自动读 PIN | C. Key Daemon | D. Session 缓存 |
|------|:------------------------:|:-----------------:|:-------------:|:--------------:|
| **应用修改量** | 不改（传 NULL） | 不改（传 NULL） | 需接 socket | 注册回调 |
| **PIN 暴露面** | ⚠️ root 可读 /mnt/secure/ 文件 | ✅ TEE 内，REE 不可见 | ✅ 仅 daemon | ⚠️ 应用进程内存中 |
| **实现复杂度** | ★★（改 Module） | ★★★（改 TA） | ★★★★（daemon + 协议） | ★（回调即可） |
| **延迟开销** | 无 | 无 | ~1-2ms IPC | 无 |
| **单点故障** | 无 | 无 | Daemon 崩溃 → 全断 | 无 |
| **审计能力** | ❌ | ❌ | ✅ | ❌ |
| **运维友好** | ★★★ | ★★★ | ★★ | ★★★★★ |
| **tbox 推荐度** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐（原型用） |

---

## 五、tbox 推荐组合方案

```
┌──────────────────────────────────────────────────────────────┐
│  tbox HTTPS 一机一密 — 推荐架构                               │
│                                                              │
│  核心策略: 方案 B 为主 + 方案 A 为回退                         │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ openssl.cnf 全局配置 pkcs11 engine                      │  │
│  │ → 所有 HTTPS 应用（curl/nginx/自研）自动走 TEE           │  │
│  │ → 无需逐个应用配置                                      │  │
│  └────────────────────────────────────────────────────────┘  │
│                            │                                  │
│                            ▼                                  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ PIN 管理策略                                             │  │
│  │                                                         │  │
│  │  主路径（方案 B — 修改 TA）:                              │  │
│  │  1. 产线随机生成 128 位 PIN                               │  │
│  │  2. 存入 RPMB 加密区域（TEE 内加密）                      │  │
│  │  3. 应用层 C_Login 传 NULL → TA 内部自动读取              │  │
│  │  4. PIN 完全在 Secure World 内，REE 不可见               │  │
│  │                                                         │  │
│  │  回退路径（方案 A — Module 读取）:                         │  │
│  │  1. 如果 TA 不支持自动读取（未修改）                       │  │
│  │  2. liboptee_pkcs11.so 在 C_Login(NULL) 时自动            │  │
│  │     从 /mnt/secure/pkcs11_pin 读取                       │  │
│  │  3. 文件权限 root:root 0400                              │  │
│  │  4. 依然比 openssl.cnf 写死 PIN 安全得多                  │  │
│  └────────────────────────────────────────────────────────┘  │
│                            │                                  │
│                            ▼                                  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ HTTPS 应用使用方法（示例）                                │  │
│  │                                                         │  │
│  │  # curl — 无 PKCS#11 参数，engine 已在 openssl.cnf 全局  │  │
│  │  curl https://cloud.example.com/api/v1/data             │  │
│  │                                                         │  │
│  │  # 指定客户端证书（PKCS#11 URI 方式）                     │  │
│  │  curl --engine pkcs11 \                                 │  │
│  │    --key "pkcs11:token=TBOX-ABCD1234;object=device-key"\ │  │
│  │    --cert "pkcs11:token=TBOX-ABCD1234;object=device-cert"\│  │
│  │    https://cloud.example.com                            │  │
│  │                                                         │  │
│  │  # 注意: 不需要 --pass / -E 指定 PIN                    │  │
│  │  # PIN 由 TA (或 Module) 内部处理，应用完全无感           │  │
│  │                                                         │  │
│  │  # 自研 C 代码                                           │  │
│  │  SSL_CTX_use_PrivateKey_file(ctx,                        │  │
│  │    "pkcs11:token=TBOX-ABCD1234;object=device-key",       │  │
│  │    SSL_FILETYPE_ASN1);                                   │  │
│  │  # OpenSSL 框架自动通过 engine 调用 C_Sign               │  │
│  │  # C_Login(NULL) → TA 自动完成认证                       │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### 产线灌装的 PIN 相关步骤

```bash
#!/bin/bash
# 产线脚本中与 PIN 相关的部分

# 1. 生成随机 PIN
PIN=$(openssl rand -hex 16)   # 128 位，如 "a1b2c3d4e5f6..."
echo "Generated PIN: $PIN"

# 2. 写入 RPMB 加密区域（方案 B — 修改 TA 后）
optee_custom_client --store-pin \
    --pin "$PIN" \
    --store-id "user-pin"

# 3. 同时写入 REE 侧回退文件（方案 A）
mkdir -p /mnt/secure
echo "$PIN" > /mnt/secure/pkcs11_pin
chown root:root /mnt/secure/pkcs11_pin
chmod 0400 /mnt/secure/pkcs11_pin

# 4. 初始化 Token User PIN
optee_pkcs11_client --init-pin \
    --so-pin "$SO_PIN" \
    --user-pin "$PIN"

# 5. 验证: 传 NULL 是否能正常登录
optee_pkcs11_client --login --pin ""  # 传空 → 走自动路径
# → 应返回 CKR_OK
```

---

## 六、最终结论

| 场景 | 推荐方案 |
|------|----------|
| **tbox 量产 — 有 TA 修改能力** | 方案 B（TA 内自动 PIN）→ 应用传 NULL，PIN 完全不暴露 |
| **tbox 量产 — 不改 TA** | 方案 A + 方案 D（Module 读文件 + Session 缓存） |
| **多进程隔离需求高** | 方案 C（Key Daemon） |
| **原型验证 / 开发阶段** | 方案 D（回调 + Session 缓存） |
| **❌ 绝对不能做的事** | openssl.cnf 写死 PIN / 环境变量传 PIN |

**核心原则：PIN 应该像密钥本身一样被保护——产线生成、TEE 管理、应用无感。**
