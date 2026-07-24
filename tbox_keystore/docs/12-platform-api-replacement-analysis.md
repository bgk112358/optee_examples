# 平台黑盒 API 替换可行性与重构方案

> **背景**：`three_part/api.txt` 中列出的 28 个接口（`ql_km_*` 密钥管理 + `ql_ss_*` 安全存储）来自平台厂商提供的黑盒库，无法定制和修改，需要在 OP-TEE 环境下重写功能等价的实现。

---

## 一、接口全景与分类

### 1.1 密钥管理与加解密操作（ql_km_* / ql_*_args，16 个）

```
初始化/去初始化:
  ql_km_initialize()         → 初始化加解密服务
  ql_km_deinitialize()       → 去初始化加解密服务

密钥生命周期:
  ql_km_gen_key()            → 生成密钥（通过 key_args 指定算法/参数）
  ql_km_import_key()         → 导入外部密钥
  ql_km_destroy_key()        → 销毁密钥，释放内存
  ql_km_export_key()         → 导出非对称算法的公钥
  ql_km_get_key_algo()       → 从 BLOB 读取密钥的算法类别

数据清理:
  ql_km_destroy_blob()       → 销毁 BLOB 数据，释放内存

算法操作（流式：begin → update* → finish）:
  ql_km_operation_begin()    → 开始算法操作（加密/解密/签名/验签/摘要）
  ql_km_operation_update()   → 进行算法操作
  ql_km_operation_finish()   → 进行最后一轮算法操作

算法参数构造器:
  ql_aes_genkey_args()       → 构造 AES 密钥生成参数
  ql_aes_operation_args()    → 构造 AES 操作参数
  ql_rsa_genkey_args()       → 构造 RSA 密钥生成参数
  ql_rsa_operation_args()    → 构造 RSA 操作参数
  ql_ec_genkey_args()        → 构造 EC 密钥生成参数
```

### 1.2 安全存储（ql_ss_*，12 个）

```
生命周期:
  ql_ss_initialize()         → 初始化安全存储功能
  ql_ss_deinitialize()       → 去初始化安全存储功能

对象操作（类 POSIX 文件接口）:
  ql_ss_open()               → 打开安全存储对象
  ql_ss_create()             → 创建并打开安全存储对象
  ql_ss_close()              → 关闭安全存储对象
  ql_ss_read()               → 从安全存储读取数据
  ql_ss_write()              → 向安全存储写入数据
  ql_ss_seek()               → 移动文件指针
  ql_ss_unlink()             → 删除安全存储文件
  ql_ss_trunc()              → 截短文件到指定长度
  ql_ss_rename()             → 重命名安全存储对象
  ql_ss_get_info()           → 获取安全存储对象信息
```

---

## 二、OP-TEE 能力映射分析

### 2.1 基础通信模型

平台的 `ql_*` 库本质上是对 TEE 调用的封装层，内部必然走以下路径：

```
REE 应用 → libql_km.so / libql_ss.so → libteec.so → SMC → OP-TEE Core → 自定义 TA
```

替换方案同样采用此模型：

```
REE 应用 → libql_compat.so (新) → libteec.so → SMC → OP-TEE Core → 替换 TA (新)
```

### 2.2 密钥管理接口的 OP-TEE 等价映射

| 平台接口 | OP-TEE GP TEE 等价 API | 映射难度 | 备注 |
|----------|----------------------|:--------:|------|
| `ql_km_initialize()` | `TEEC_InitializeContext()` + `TEEC_OpenSession()` | ★ | 建立 TEE 上下文和 TA 会话 |
| `ql_km_deinitialize()` | `TEEC_CloseSession()` + `TEEC_FinalizeContext()` | ★ | 关闭会话和上下文 |
| `ql_km_gen_key()` | `TEE_AllocateTransientObject()` + `TEE_GenerateKey()` + 序列化 → `TEE_CreatePersistentObject()` | ★★★ | 密钥存储格式需自定 |
| `ql_km_import_key()` | `TEE_AllocateTransientObject()` + `TEE_PopulateTransientObject()` + `TEE_CreatePersistentObject()` | ★★★ | 需解析外部密钥格式 |
| `ql_km_destroy_key()` | `TEE_OpenPersistentObject()` + `TEE_CloseAndDeletePersistentObject1()` | ★★ | UUID→文件映射 |
| `ql_km_export_key()` | `TEE_GetObjectBufferAttribute()` 读取公钥属性 | ★★ | RSA→(n,e), EC→(x,y) |
| `ql_km_get_key_algo()` | 从自定序列化头中读取算法类型字段 | ★ | 解析自定 BLOB 头 |
| `ql_km_destroy_blob()` | `TEE_Free()` 或 `free()` | ★ | 根据 BLOB 所在位置决定 |
| `ql_km_operation_begin()` | `TEE_AllocateOperation()` + `TEE_SetOperationKey()` + `TEE_CipherInit()` | ★★★ | 需还原算法/模式/Key 的映射 |
| `ql_km_operation_update()` | `TEE_CipherUpdate()` / `TEE_AsymmetricSignDigest()` 等 | ★★ | 流式更新语义一致 |
| `ql_km_operation_finish()` | `TEE_CipherDoFinal()` + `TEE_FreeOperation()` | ★★ | 处理 padding/认证标签 |
| `ql_aes_genkey_args()` | AES 参数结构体构造（纯 REE 侧逻辑） | ★ | 无 TEE 调用 |
| `ql_aes_operation_args()` | AES 操作参数结构体构造（纯 REE 侧逻辑） | ★ | 无 TEE 调用 |
| `ql_rsa_genkey_args()` | RSA 参数结构体构造（纯 REE 侧逻辑） | ★ | 无 TEE 调用 |
| `ql_rsa_operation_args()` | RSA 操作参数结构体构造（纯 REE 侧逻辑） | ★ | 无 TEE 调用 |
| `ql_ec_genkey_args()` | EC 参数结构体构造（纯 REE 侧逻辑） | ★ | 无 TEE 调用 |

### 2.3 安全存储接口的 OP-TEE 等价映射

| 平台接口 | OP-TEE GP TEE 等价 API | 映射难度 | 备注 |
|----------|----------------------|:--------:|------|
| `ql_ss_initialize()` | `TEEC_InitializeContext()` + `TEEC_OpenSession()` | ★ | 同密钥管理类 |
| `ql_ss_deinitialize()` | `TEEC_CloseSession()` + `TEEC_FinalizeContext()` | ★ | 同密钥管理类 |
| `ql_ss_open()` | `TEE_OpenPersistentObject()` | ★ | 1:1 语义映射 |
| `ql_ss_create()` | `TEE_CreatePersistentObject()` | ★ | 1:1 语义映射 |
| `ql_ss_close()` | `TEE_CloseObject()` | ★ | 1:1 语义映射 |
| `ql_ss_read()` | `TEE_ReadObjectData()` | ★ | 1:1 语义映射 |
| `ql_ss_write()` | `TEE_WriteObjectData()` | ★ | 1:1 语义映射 |
| `ql_ss_seek()` | `TEE_SeekObjectData()` | ★ | 1:1 语义映射 |
| `ql_ss_unlink()` | `TEE_OpenPersistentObject()` + `TEE_CloseAndDeletePersistentObject1()` | ★ | 两步合成一步 |
| `ql_ss_trunc()` | GP API 无直接等价；需读→新对象→替换 | ★★★ | 需额外实现 |
| `ql_ss_rename()` | GP API 无直接等价；需创建新对象 + 删除旧 | ★★★ | 需额外实现 |
| `ql_ss_get_info()` | `TEE_GetObjectInfo1()` | ★ | 1:1 语义映射 |

### 2.4 映射难度总评

```
28 个接口中：
  1:1 直接映射    : 16 个 (57%)  — 安全存储的大部分 + 参数构造器
  需适配层封装    :  8 个 (29%)  — 密钥管理核心操作
  需创新实现      :  2 个 ( 7%)  — ql_ss_trunc() / ql_ss_rename()
  纯 REE 侧逻辑   :  5 个 (18%)  — 所有 *args 构造器（含在直接映射中）

总评：技术可行 ✅
```

---

## 三、关键风险点与挑战

### 3.1 密钥 BLOB 格式不透明（最高风险）

**问题描述**：`ql_km_gen_key()` 和 `ql_km_import_key()` 返回的"密钥 BLOB"是平台私有格式。`ql_km_operation_begin()` 通过解析 BLOB 来获取算法类型和密钥材料。

**影响范围**：
- `ql_km_gen_key()`, `ql_km_import_key()`, `ql_km_destroy_key()`
- `ql_km_export_key()`, `ql_km_get_key_algo()`
- `ql_km_operation_begin()` — 需要从 BLOB 中提取密钥

**应对方案**：
- 定义自有的序列化格式（参考 [tbox_keystore TA](../ta/keystore.c) 的 `struct serialized_key` 设计）
- BLOB = 固定头 + 变长属性数据
- 提供 `ql_blob_to_internal()` / `ql_internal_to_blob()` 转换层

### 3.2 操作句柄生命周期

**问题描述**：`ql_km_operation_begin()` 初始化操作后，中间可以多次调用 `ql_km_operation_update()`，最后 `ql_km_operation_finish()` 收尾。需要正确管理 TEE Operation Handle 的生命周期。

**应对方案**：
- 在每个 TEE Session 内维护一个 `operation_context` 数据结构
- begin 时 `TEE_AllocateOperation()`
- update 时 `TEE_CipherUpdate()` / `TEE_DigestUpdate()`
- finish 时 `TEE_CipherDoFinal()` + `TEE_FreeOperation()`
- 异常路径（用户未调 finish 而调 destroy_key）需要清理

### 3.3 Secure Storage trunc & rename 无直接等价

**问题描述**：GP TEE Internal Core API 没有 `truncate` 和 `rename` 的概念。

**应对方案**：

**trunc 实现**：
```
1. TEE_OpenPersistentObject() 打开旧对象
2. TEE_ReadObjectData() 读取前 new_size 字节
3. TEE_CloseAndDeletePersistentObject1() 删除旧对象
4. TEE_CreatePersistentObject() 以相同 UUID 创建新对象，写入截断后数据
```

**rename 实现**：
```
1. TEE_OpenPersistentObject() 打开旧对象
2. TEE_ReadObjectData() 读取全部数据
3. TEE_CloseAndDeletePersistentObject1() 删除旧对象
4. 用新名称派生新 UUID
5. TEE_CreatePersistentObject() 以新 UUID 创建对象，写入数据
```

> **注意**：以上两步非原子操作，掉电可能导致数据丢失。如果平台有原子性要求，需考虑 WAL（Write-Ahead Log）方案。

### 3.4 算法覆盖范围未知

**问题描述**：接口声明支持 AES / RSA / EC，但具体算法细节（CBC/CTR/GCM/CCM，RSA-PKCS#1/RSA-PSS，ECDSA/ECDH，SHA-256/SHA-384/SHA-512/SM3）未知。

**应对方案**：
- 第一版实现最常用子集：AES-CBC（含 NOPAD/PKCS7），AES-CTR，AES-GCM，RSA-2048-PKCS#1_v1.5_SHA256，ECDSA-P256-SHA256
- 预留算法枚举扩展点
- 通过 `ql_km_operation_begin` 的 `mechanism` 参数进行算法分派

---

## 四、推荐实现架构

### 4.1 总体架构图

```
┌───────────────────────────────────────────────────────────┐
│  现有应用代码 (不改动)                                       │
│  ql_km_initialize() / ql_km_gen_key() / ...                │
│  ql_ss_open() / ql_ss_read() / ...                         │
└──────────────────────────┬────────────────────────────────┘
                           │ ABI 兼容
                           ▼
┌───────────────────────────────────────────────────────────┐
│  libql_compat.so (替换库，REE 侧)                            │
│                                                             │
│  ┌─────────────────────┐  ┌─────────────────────────────┐  │
│  │ ql_km_* 兼容层       │  │ ql_ss_* 兼容层               │  │
│  │ ├─ BLOB 序列化/反序  │  │ ├─ 对象名→UUID 映射          │  │
│  │ ├─ 操作上下文管理    │  │ ├─ trunc/rename 模拟实现     │  │
│  │ ├─ 参数构造器        │  │ └─ 文件指针管理              │  │
│  │ └─ 错误码转换        │  │                              │  │
│  └─────────┬───────────┘  └──────────────┬──────────────┘  │
│            │                              │                 │
│            └──────────────┬───────────────┘                 │
│                           ▼                                 │
│                   libteec.so (TEE Client API)               │
└───────────────────────────┬───────────────────────────────┘
                            │ SMC (#0)
                            ▼
┌───────────────────────────────────────────────────────────┐
│  OP-TEE Core + 替换 TA (Secure World)                       │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  ql_compat_ta (替换 TA)                              │   │
│  │  UUID: 待分配                                         │   │
│  │                                                       │   │
│  │  ┌─────────────────┐  ┌───────────────────────────┐  │   │
│  │  │ 密钥生命周期     │  │ 安全存储                   │  │   │
│  │  │ ├─ CMD_GEN_KEY  │  │ ├─ CMD_SS_OPEN            │  │   │
│  │  │ ├─ CMD_IMP_KEY  │  │ ├─ CMD_SS_CREATE          │  │   │
│  │  │ ├─ CMD_DEL_KEY  │  │ ├─ CMD_SS_CLOSE           │  │   │
│  │  │ ├─ CMD_EXP_PUB  │  │ ├─ CMD_SS_READ            │  │   │
│  │  │ ├─ CMD_OP_BEGIN │  │ ├─ CMD_SS_WRITE           │  │   │
│  │  │ ├─ CMD_OP_UPDATE│  │ ├─ CMD_SS_SEEK            │  │   │
│  │  │ ├─ CMD_OP_FINISH│  │ ├─ CMD_SS_UNLINK          │  │   │
│  │  │ └─ CMD_BLOB_ALGO│  │ ├─ CMD_SS_TRUNC           │  │   │
│  │  └────────┬────────┘  │ ├─ CMD_SS_RENAME           │  │   │
│  │           │            │ └─ CMD_SS_INFO             │  │   │
│  │           ▼            └──────────────┬─────────────┘  │   │
│  │  ┌────────────────────────────────────┐                │   │
│  │  │  TEE Internal Core API             │                │   │
│  │  │  ├─ TEE_AllocateTransientObject    │                │   │
│  │  │  ├─ TEE_GenerateKey / Populate     │                │   │
│  │  │  ├─ TEE_AllocateOperation          │                │   │
│  │  │  ├─ TEE_CipherUpdate / DoFinal     │                │   │
│  │  │  ├─ TEE_CreatePersistentObject     │                │   │
│  │  │  ├─ TEE_OpenPersistentObject       │                │   │
│  │  │  ├─ TEE_ReadObjectData / Write     │                │   │
│  │  │  └─ TEE_SeekObjectData / Close     │                │   │
│  │  └────────────────────────────────────┘                │   │
│  └─────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────┘
                            │
                            ▼
┌───────────────────────────────────────────────────────────┐
│  Secure Storage 后端 (REE FS 或 RPMB)                       │
│  HUK → SSK → TSK → FEK 加密链                              │
└───────────────────────────────────────────────────────────┘
```

### 4.2 关键设计决策

#### 4.2.1 一个 TA 还是两个 TA？

| 方案 | 结构 | 优点 | 缺点 |
|------|------|------|------|
| **方案 A（推荐）** | 单一 TA 包含两个功能子模块（密钥管理 + 安全存储） | 一个会话，`ql_km_initialize` 和 `ql_ss_initialize` 共享同一个 `TEEC_Session`；实现简单 | TA 体积稍大 |
| 方案 B | 两个独立 TA（km TA + ss TA） | 模块边界清晰；可独立升级 | 两个会话管理复杂；调用方需要两次 initialize |

**推荐方案 A**，理由：
- `ql_km_initialize()` 和 `ql_ss_initialize()` 大概率共享同一个底层 TEE context——分离 TA 会引入不必要的复杂度
- tbox_keystore 示例也是单一 TA 承载多种功能，模式成熟

#### 4.2.2 密钥 BLOB 的自定义格式

参考 [keystore.c:22-32](../ta/keystore.c) 的设计，扩展为更通用的格式：

```c
#define BLOB_MAGIC        0x514C424B  /* "QLBK" */
#define BLOB_VERSION      1

struct ql_key_blob_hdr {
    uint32_t magic;             /* BLOB_MAGIC — 校验标识 */
    uint32_t version;           /* 格式版本号 */
    uint32_t key_type;          /* KEY_TYPE_AES / KEY_TYPE_RSA / KEY_TYPE_EC */
    uint32_t key_size_bits;     /* 密钥长度（位） */
    uint32_t flags;             /* PERM_ENCRYPT | PERM_DECRYPT | PERM_SIGN... */
    uint32_t attr_count;        /* 属性数量 */
    uint32_t attr_sizes[];      /* 每个属性的长度数组（变长） */
    /* 后面紧跟 attr_sizes[0] + attr_sizes[1] + ... 字节的属性数据 */
};

/* key_type 枚举 */
enum ql_key_type {
    KEY_TYPE_AES        = 1,
    KEY_TYPE_DES        = 2,
    KEY_TYPE_RSA_KEYPAIR= 3,
    KEY_TYPE_RSA_PUBKEY = 4,
    KEY_TYPE_EC_KEYPAIR = 5,
    KEY_TYPE_EC_PUBKEY  = 6,
    KEY_TYPE_HMAC       = 7,
};
```

#### 4.2.3 操作上下文管理

```c
/* REE 侧：ql_km_operation_begin 返回的不透明句柄 */
typedef void* QL_OPERATION_HANDLE;

/* TA 侧：每个 session 维护活跃操作 */
struct ql_operation_ctx {
    uint32_t            op_id;          /* 操作 ID（句柄 = &ctx） */
    uint32_t            state;          /* OP_STATE_IDLE / ACTIVE / FINALIZED */
    uint32_t            algorithm;      /* GP TEE 算法 ID */
    uint32_t            mode;           /* ENCRYPT / DECRYPT / SIGN / VERIFY / DIGEST */
    TEE_OperationHandle tee_op;         /* GP TEE 操作句柄 */
    TEE_ObjectHandle    key;            /* 已加载的密钥句柄 */
    uint32_t            key_type;       /* 密钥类型（用于 sign/verify 分派） */
};

/* state 状态机：
   IDLE ──[begin]──▶ ACTIVE ──[update]*──▶ ACTIVE ──[finish]──▶ FINALIZED
         ▲                                      │
         └──────────[begin 重用 op_id]───────────┘
*/
```

#### 4.2.4 安全存储的对象名映射

平台接口使用字符串名操作安全存储对象，而 GP TEE API 使用 `TEE_UUID`（16字节）。需要一个确定性的映射：

```c
/* 方案：与 tbox_keystore 一致，SHA-256(label) → UUID */
static void name_to_uuid(const char *name, TEE_UUID *uuid)
{
    uint8_t hash[32];
    size_t hash_len = sizeof(hash);

    TEE_OperationHandle op;
    TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    TEE_DigestDoFinal(op, name, strlen(name), hash, &hash_len);
    TEE_FreeOperation(op);

    memcpy(uuid, hash, sizeof(TEE_UUID));
}
```

---

## 五、具体接口实现方案

### 5.1 密钥管理类接口

#### ql_km_initialize()

```
REE: TEEC_InitializeContext(NULL, &ctx)
     TEEC_OpenSession(&ctx, &sess, &QL_COMPAT_TA_UUID, TEEC_LOGIN_PUBLIC, ...)
     将会话指针保存到全局 TLS 或传入的句柄中
```

#### ql_km_gen_key(params, &blob, &blob_len)

```
REE: 将 key_args（含算法、大小、权限）打包 → TEEC_InvokeCommand(CMD_GEN_KEY)

TA:  1. TEE_AllocateTransientObject(type, bits, &key)
     2. TEE_GenerateKey(key, bits, NULL, 0)
     3. serialize_to_blob(key, type, bits, flags) → blob_data
     4. TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &uuid, ..., blob_data, blob_len, &obj)
     5. TEE_CloseObject(obj)
     6. 返回 blob_data → REE 侧副本供调用方持有
```

#### ql_km_import_key(key_material, material_len, params, &blob)

```
TA:  1. TEE_AllocateTransientObject(type, bits, &key)
     2. 解析外部密钥格式（如 PKCS#8 DER 私钥 / 裸 AES key bytes）
     3. TEE_InitRefAttribute() + TEE_PopulateTransientObject()
     4. serialize_to_blob(key, ...) → 同 gen_key 的落盘逻辑
```

#### ql_km_operation_begin(blob, mechanism, &op_handle)

```
REE: 将 BLOB 和机制参数打包 → TEEC_InvokeCommand(CMD_OP_BEGIN)

TA:  1. 解析 BLOB 头 → 获取 key_type, key_size_bits
     2. 从 BLOB UUID 打开持久化对象 → 恢复 TEE_ObjectHandle
        或：直接用 BLOB 中的属性数据 populate transient object
     3. mechanism → GP TEE algorithm ID + mode 映射:
         "AES-CBC"    → TEE_ALG_AES_CBC_PKCS7
         "AES-GCM"    → TEE_ALG_AES_GCM
         "RSA-SIGN"   → TEE_ALG_RSASSA_PKCS1_V1_5_SHA256
         "ECDSA"      → TEE_ALG_ECDSA_SHA256
     4. TEE_AllocateOperation(&op, algo, mode, key_size)
     5. TEE_SetOperationKey(op, key)
     6. 如果是 cipher mode: TEE_CipherInit(op, iv, iv_len)
     7. 分配 op_ctx_id → 返回给 REE 侧
```

#### ql_km_operation_update(op_handle, in, in_len, out, &out_len)

```
TA:  1. 根据 op_handle 找到 operation_ctx
     2. 按算法类型分派:
        - cipher: TEE_CipherUpdate(tee_op, in, in_len, out, &out_len)
        - digest: TEE_DigestUpdate(tee_op, in, in_len)
        - sign (单次): TEE_AsymmetricSignDigest(tee_op, ...)
        - verify (单次): TEE_AsymmetricVerifyDigest(tee_op, ...)
     3. 返回 updated out_len
```

#### ql_km_operation_finish(op_handle, out, &out_len)

```
TA:  1. 根据 op_handle 找到 operation_ctx
     2. TEE_CipherDoFinal() / TEE_DigestDoFinal()
     3. TEE_FreeOperation(tee_op)
     4. 释放 ctx
```

### 5.2 安全存储类接口

这些接口绝大部分是 GP TEE Persistent Object API 的 1:1 封装：

```
ql_ss_open(name, flags)     → TEE_OpenPersistentObject(..., name_to_uuid(name), flags_convert(flags), &obj)
                               用 obj 指针的低 32bit 作为 fd 返回，或用哈希表映射 fd→obj

ql_ss_create(name, flags)   → TEE_CreatePersistentObject(..., name_to_uuid(name), flags, ...)

ql_ss_read(fd, buf, len)    → TEE_ReadObjectData(lookup_obj(fd), buf, len, &read_bytes)

ql_ss_write(fd, buf, len)   → TEE_WriteObjectData(lookup_obj(fd), buf, len)

ql_ss_seek(fd, offset, whence) → TEE_SeekObjectData(lookup_obj(fd), offset, gp_whence)

ql_ss_close(fd)             → TEE_CloseObject(lookup_obj(fd)) + 释放 fd 槽位

ql_ss_unlink(name)          → 打开 + TEE_CloseAndDeletePersistentObject1()

ql_ss_get_info(name, info)  → TEE_OpenPersistentObject() + TEE_GetObjectInfo1()
```

---

## 六、实现工作量估算

### 6.1 模块分解与代码量估算

| 模块 | 内容 | 预估代码量 | 难度 |
|------|------|:----------:|:----:|
| **TA 核心框架** | entry.c, TA 入口点, 命令分发 | ~250 行 | ★★ |
| **密钥管理子模块** | key_lifecycle.c — 生成/导入/销毁/导出/查询 | ~500 行 | ★★★ |
| **加密操作子模块** | crypto_ops.c — begin/update/finish, 算法分派 | ~400 行 | ★★★ |
| **安全存储子模块** | ss_ops.c — open/create/close/read/write/seek/unlink/trunc/rename/info | ~350 行 | ★★ |
| **BLOB 序列化** | blob.c — 序列化/反序列化/BLOB 头解析 | ~250 行 | ★★ |
| **REE 侧兼容库** | libql_compat.c — 所有 ql_* 函数的 REE 侧实现 | ~600 行 | ★★ |
| **参数构造器** | args_builder.c — ql_*_genkey_args / ql_*_operation_args | ~200 行 | ★ |
| **头文件** | ql_compat.h, ql_compat_ta.h | ~150 行 | ★ |
| **构建系统** | CMakeLists.txt × 2 (TA + library) | ~100 行 | ★ |
| **单元测试** | test_ql_compat.c | ~300 行 | ★★ |
| **总计** | | **~3100 行 C** | |

### 6.2 开发阶段

```
Phase 1: 核心框架搭建（2-3天）
  ├── TA skeleton (entry point, command dispatch)
  ├── REE library skeleton (TEEC boilerplate)
  ├── BLOB 序列化格式定义
  └── CMake 构建系统

Phase 2: 安全存储模块（2天）
  ├── 1:1 映射接口实现（open/create/close/read/write/seek/unlink/info）
  ├── trunc/rename 模拟实现
  └── 对象名→UUID 映射

Phase 3: 密钥管理模块（3天）
  ├── gen_key / import_key / destroy_key / export_key / get_key_algo
  ├── AES/RSA/EC 的 serialize/deserialize
  └── BLOB 落盘与读取

Phase 4: 加密操作模块（3天）
  ├── begin/update/finish 状态机
  ├── AES-CBC/CTR/GCM 对称加密
  ├── RSA sign/verify
  └── ECDSA sign/verify

Phase 5: 参数构造器 + 集成测试（2天）
  ├── ql_*_genkey_args / ql_*_operation_args
  ├── 端到端测试
  └── 文档

总计：约 12-15 人天
```

---

## 七、推荐重构策略

### 7.1 推荐方案：单一兼容 TA + REE 适配库

**架构**：一个 TA (`ql_compat_ta`) + 一个 REE 共享库 (`libql_compat.so`)，应用层直接 LD_PRELOAD 或替换原 `libql_km.so` / `libql_ss.so`。

### 7.2 渐进式替换路径

```
Step 1: qemu 环境（optee400）验证
  ├── 编译替换 TA，用 xtest 风格的 CA 测试
  ├── 验证所有 28 个接口的基本功能
  └── 运行 <2 秒延迟的性能基准

Step 2: 开发板验证（AG519M）
  ├── 交叉编译 TA + libql_compat.so
  ├── 在真实设备上替换原平台库
  ├── 确认 RPMB 安全存储后端正常工作
  └── 长稳测试（24h+ 连续加解密）

Step 3: 产线适配
  ├── 对接灌装流程（一机一密 + PIN 初始化和锁定）
  ├── 更新 openssl.cnf 配置
  └── 性能调优（密钥缓存、共享内存优化）

Step 4: 生产切换
  ├── A/B 灰度 — 部分设备使用新 TA
  ├── MES 上报对比（良率、耗时）
  └── 全量切换
```

### 7.3 备选方案（若平台 API 有隐藏行为）

如果替换过程中发现平台 API 存在无法逆向的行为（如自定义密钥派生、硬件绑定逻辑等），可考虑：

- **方案 B**：仅替换安全存储模块（ql_ss_*），因为其与 GP TEE API 高度一致；密钥管理保留原平台库
- **方案 C**：在 OP-TEE PKCS#11 TA 之上封装 ql_* 接口（更重但标准化程度更高）

---

## 八、风险缓解清单

| 风险 | 概率 | 影响 | 缓解措施 |
|------|:----:|:----:|----------|
| BLOB 格式逆向不完全 | 中 | 高 | 第一版只实现必要字段；预留 BLOB 版本号 |
| 平台库有隐藏全局状态 | 高 | 中 | TA 内使用全局变量隔离 session |
| 算法参数与平台行为不一致 | 中 | 高 | 单元测试覆盖已知输入/输出对 |
| trunc/rename 非原子导致数据损坏 | 低 | 高 | 实现 WAL 日志；文档标注限制 |
| 性能劣化（SMC 调用开销） | 中 | 中 | REE 侧缓存 key alias→blob 映射；减少 TA 往返 |
| 平台库的内部错误码映射 | 中 | 低 | 建立 GP TEE Result → ql_error_code 映射表 |
| 并发/多线程安全 | 低 | 中 | TA 内 session 级操作隔离；REE 侧加 pthread mutex |

---

## 九、关键参考实现

| 参考 | 路径 | 关联点 |
|------|------|--------|
| tbox_keystore TA | [optee_examples_AG519M/tbox_keystore/ta/](../ta/) | 密钥序列化/反序列化、持久化存储、PIN 管理、命令分发模式 |
| tbox_keystore CA | [optee_examples_AG519M/tbox_keystore/host/keystore_client.c](../host/keystore_client.c) | REE 侧 TEEC 调用模式、错误处理 |
| AES TA | [optee_examples_AG519M/aes/ta/aes_ta.c](../../optee_examples_AG519M/aes/ta/aes_ta.c) | 流式加密操作 (prepare→set_key→set_iv→cipher) |
| Secure Storage TA | [optee_examples_AG519M/secure_storage/ta/](../../optee_examples_AG519M/secure_storage/ta/) | Persistent Object 的 CRUD 模式 |
| PKCS#11 TA（官方） | [optee400/optee_os/ta/pkcs11/](../../../optee400/optee_os/) | 密钥全生命周期管理、多算法支持 |
| 架构分析 | [01-architecture-overview.md](01-architecture-overview.md) | 五种方案对比、推荐选型 |
| 密钥存储 | [05-key-storage.md](05-key-storage.md) | HUK→SSK→TSK→FEK 加密链、存储架构 |

---

## 十、结论

### 可行性判断：✅ 技术可行

- 28 个接口中，**22 个（79%）有直接或接近直接的 OP-TEE GP TEE API 映射**
- 2 个接口（trunc/rename）需要模拟实现，技术上可接受
- 5 个接口（*args 构造器）是纯 REE 侧逻辑，可完全复制

### 推荐路径

1. **使用单一兼容 TA** 承载密钥管理和安全存储两种功能
2. **自定义密钥 BLOB 格式** 替换平台私有格式
3. **先在 qemu 环境验证** → 开发板验证 → 产线灰度 → 全量切换
4. **首期实现 AES-CBC/CTR/GCM + RSA-2048 + ECDSA-P256**，后续按需扩展算法

### 可复用资产

- `tbox_keystore` 示例已完整实现：密钥序列化、持久化存储、ACL、PIN 管理、AES/RSA 操作
- `secure_storage` 示例已实现：创建/读取/写入/删除 Persistent Object
- `aes` 示例已实现：AES-CBC/CTR/ECB 的流式操作

这些示例代码可以作为替换 TA 的直接参考，大幅降低开发风险。
