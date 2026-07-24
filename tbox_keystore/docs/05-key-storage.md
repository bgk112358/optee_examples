# 密钥在 TEE 内的存储机制

## 总体架构：三层存储模型

```
┌─────────────────────────────────────────────────────────┐
│  PKCS#11 应用层视角                                        │
│  CKA_TOKEN = TRUE → 持久化对象 (Token Object)                │
│  CKA_TOKEN = FALSE → 会话级对象 (Session Object，TA 退出即销毁) │
└─────────────────────────────────┬───────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────┐
│  ① PKCS#11 TA 内部对象管理层                                │
│  ┌──────────────────┐   ┌──────────────────────────┐     │
│  │ struct pkcs11_object │──▶ struct obj_attrs      │     │
│  │  .uuid  = TEE_UUID   │   ├── CKA_CLASS         │     │
│  │  .attributes=attrs   │   ├── CKA_KEY_TYPE      │     │
│  │  .key_handle         │   ├── CKA_VALUE (密钥明文) │     │
│  │  .attribs_hdl (文件) │   ├── CKA_MODULUS        │     │
│  └──────────────────┘   │   ├── CKA_PRIVATE_EXP    │     │
│                          │   └── ...                │     │
│                          └──────────────────────────┘     │
└─────────────────────────────────┬───────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────┐
│  ② GP TEE 内部持久化对象 API (TEE Internal Core API)      │
│  TEE_CreatePersistentObject()                             │
│  TEE_OpenPersistentObject()                               │
│  TEE_ReadObjectData() / TEE_WriteObjectData()             │
│  TEE_CloseAndDeletePersistentObject1()                    │
│                                                           │
│  存储ID: TEE_STORAGE_PRIVATE (按配置选择后端)               │
│  文件名: UUID 二进制 (sizeof(TEE_UUID) = 16 字节)          │
└─────────────────────────────────┬───────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────┐
│  ③ Secure Storage 后端（可配置，二选一或同时）              │
│                                                           │
│  选项 A: REE FS (CFG_REE_FS=y) ← 默认                    │
│    /data/tee/<file_number>                                 │
│  选项 B: RPMB (CFG_RPMB_FS=y)                             │
│    eMMC RPMB Partition (物理防回滚)                        │
│                                                           │
│  两者都运行时：                                            │
│    TEE_STORAGE_PRIVATE → REE FS                           │
│    TEE_STORAGE_PRIVATE_RPMB → RPMB                        │
│  且 REE FS 在 RPMB 中存 dirfile.db.hash 做完整性校验       │
└─────────────────────────────────────────────────────────┘
```

---

## 密钥写盘全流程

以 `C_CreateObject` 导入 AES-256 密钥为例，跟踪密钥从 REE 到安全存储的完整路径：

### 步骤 1：REE 侧调用链

```c
/* PKCS#11 Module (optee_pkcs11.so) → libteec */
C_CreateObject(session, template, &hKey);
  → TEEC_InvokeCommand(sess, PKCS11_CMD_CREATE_OBJECT, &op, NULL)
    → SMC → OP-TEE Core → PKCS#11 TA
```

### 步骤 2：TA 创建持久化对象

```c
/* object.c - create_object() 中 CKA_TOKEN = true 的分支 */

if (get_bool(obj->attributes, PKCS11_CKA_TOKEN)) {
    /* (A) 分配一个 TEE_UUID 作为此密钥文件的文件名 */
    create_object_uuid(get_session_token(session), obj);
    /* obj->uuid = {0xa1b2c3d4, ...} 唯一 UUID */

    /* (B) 将全部 PKCS#11 属性序列化并写入持久化存储 */
    size_t size = sizeof(struct obj_attrs) + obj->attributes->attrs_size;
    /* ↑ 属性结构体 + 密钥明文（CKA_VALUE）就在 attrs 中 */

    TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE,        /* 后端：REE FS 或 RPMB */
        obj->uuid, sizeof(TEE_UUID),/* 文件名 = 16 字节 UUID */
        TEE_DATA_FLAG_ACCESS_READ |
        TEE_DATA_FLAG_ACCESS_WRITE |
        TEE_DATA_FLAG_ACCESS_WRITE_META,
        TEE_HANDLE_NULL,            /* 无初始数据句柄 */
        obj->attributes,            /* ← 密钥数据在这里被序列化写入 */
        size,
        &obj->attribs_hdl);         /* 得到的文件句柄 */

    /* (C) 在 token 持久化数据库中注册该 UUID */
    register_persistent_object(session->token, obj->uuid);
    /* → 追加到 token_persistent_objs.uuids[] */

    /* (D) 关闭文件句柄 */
    TEE_CloseObject(obj->attribs_hdl);
}
```

### 步骤 3：Secure Storage 层 — 加密落盘

写入链条：
```
TEE_CreatePersistentObject()
  → tee_svc_storage.c → tee_ree_fs.c (或 tee_rpmb_fs.c)
     → tee_fs_key_manager.c → fs_htree.c
```

---

## 密钥派生链（加密层级）

```
┌──────────────────────────────────────────────────────┐
│  硬件 OTP (eFuse)：每个 SoC 独一无二的 HUK             │
│  Hardware Unique Key (128-bit)                        │
│  存储在 SoC eFuse 中，REE 无法读取                      │
└──────────────────────┬───────────────────────────────┘
                       ▼
SSK = HMAC-SHA256(HUK, ChipID || "OP-TEE Secure Storage")
  ↑ Secure Storage Key (每设备唯一，永不出 TEE 内存)
  ↑ 在 OP-TEE 启动时生成，只存在于 Secure RAM
                       ▼
TSK = HMAC-SHA256(SSK, TA_UUID)
  ↑ TA Storage Key (PKCS#11 TA 独享)
  ↑ PKCS#11 TA_UUID = {0xbd11e341, 0x7b31, 0x4e8a,
                        {0xa2, 0x2e, 0x49, 0xfb, 0x50, 0x8b, 0xb2, 0x33}}
                       ▼
FEK = PRNG()  ← 每个文件随机生成
  ↑ File Encryption Key (加密具体密钥文件)
  ↑ 用 TSK 加密后存于文件的 header 中
                       ▼
最终存储块:
  meta:  AES-GCM-Encrypt(TSK, FEK || meta_data)
  data:  AES-GCM-Encrypt(FEK, 密钥明文)
```

**数据结构（来自 `fs_htree.h`）：**

```c
/* 每个安全存储文件的磁盘结构 */
struct tee_fs_htree_image {
    uint8_t iv[TEE_FS_HTREE_IV_SIZE];          /* AES-GCM IV */
    uint8_t tag[TEE_FS_HTREE_TAG_SIZE];        /* GCM 认证标签 */
    uint8_t enc_fek[TEE_FS_HTREE_FEK_SIZE];    /* 用 TSK 加密的 FEK */
    uint8_t imeta[sizeof(struct tee_fs_htree_imeta)];  /* 文件元数据 */
    uint32_t counter;                          /* 防回滚计数器 */
};

struct tee_fs_htree_node_image {
    uint8_t hash[TEE_FS_HTREE_HASH_SIZE];      /* 子节点哈希 */
    uint8_t iv[TEE_FS_HTREE_IV_SIZE];          /* 数据块 IV */
    uint8_t tag[TEE_FS_HTREE_TAG_SIZE];        /* 数据块认证标签 */
    uint16_t flags;
};
```

---

## 物理路径 — REE FS 后端时磁盘上的样子

当 `CFG_REE_FS=y`（默认）时，在 REE 的 Linux 文件系统中可以看到：

```bash
# 在 Linux REE 侧查看（需要 root）
$ ls -la /data/tee/
-rw------- 1 root root  4096  ...  dirf.db         # 目录索引文件
-rw------- 1 root root  4096  ...  0               # PKCS#11 TA 主数据库
-rw------- 1 root root  4096  ...  1               # 密钥文件 1
-rw------- 1 root root  8192  ...  2               # 密钥文件 2
...
```

**文件名规则：** `dirf.db` 是目录索引，每个文件是一个线性递增的数字（`0`, `1`, `2`, ...）。文件是**加密后的二进制块**，REE 侧完全无法解读。

```bash
$ hexdump -C /data/tee/0
00000000  00 00 00 00 01 00 00 00  00 00 00 00 00 00 00 00  |................|
00000010  00 00 00 00 00 00 00 00  ... 加密的 Hash Tree Header ...
00000020  ... AES-GCM 加密数据 ...                            |..................|
```

**REE 侧看到的全部是 AES-GCM 加密的密文，没有密钥明文暴露。**

---

## PKCS#11 Token 持久化数据库结构

### 主数据库（token 元数据）

```c
/* pkcs11_token.h — 一个 token 一份，存储在 TEE 安全存储中 */

struct token_persistent_main {
    uint32_t version;                                    // 版本号
    uint8_t  label[PKCS11_TOKEN_LABEL_SIZE];            // Token 标签
    uint32_t flags;                                      // Token 标志
    uint32_t so_pin_count;                               // SO PIN 重试计数
    uint32_t so_pin_salt;                                // SO PIN 哈希盐值
    uint8_t  so_pin_hash[TEE_MAX_HASH_SIZE];            // SO PIN 哈希
    uint32_t user_pin_count;                             // User PIN 重试计数
    uint32_t user_pin_salt;                              // User PIN 哈希盐值
    uint8_t  user_pin_hash[TEE_MAX_HASH_SIZE];          // User PIN 哈希
};

/* 文件名 UUID = PKCS11_TA_DB_UUID（固定已知 UUID）*/
```

### 对象注册表（token 持有哪些密钥文件）

```c
struct token_persistent_objs {
    uint32_t count;             // 密钥数量
    TEE_UUID uuids[];           // 每个密钥对象对应一个 UUID
};

/* 注册表中的 UUID 就是每个密钥文件的文件名 */
```

### 每个密钥文件的内部结构

```c
/* 密钥文件 = UUID 命名的 GP 持久化对象 */
/* 内容 = 序列化的 PKCS#11 属性（obj_attrs + attrs[]）*/

struct obj_attrs {             // 序列化属性头
    uint32_t attrs_size;       // 属性数据总长度
    uint32_t attrs_count;      // 属性数量
    uint8_t  data[];           // 变长属性数组 [{id, size, value}, ...]
};

/* 例如一个 AES-256 密钥序列化后 ≈ 128 字节：*/
// CKA_CLASS        = CKO_SECRET_KEY      (4B)
// CKA_KEY_TYPE     = CKK_AES             (4B)
// CKA_VALUE        = 0xA1B2...32字节密钥  (32B)
// CKA_TOKEN        = true                (1B)
// CKA_PRIVATE      = true                (1B)
// CKA_ENCRYPT      = true                (1B)
// CKA_DECRYPT      = true                (1B)
// CKA_ID           = "my-aes-key\0"      (10B)
// CKA_LABEL        = "my-aes-key\0"      (10B)
// ...更多可选属性
```

---

## 不同配置下的存储后端对比

| 后端 | 配置宏 | 物理介质 | 路径形式 | 防回滚 | 性能 | 适用场景 |
|------|--------|----------|----------|--------|------|----------|
| **REE FS** | `CFG_REE_FS=y`（默认） | REE 文件系统（ext4/f2fs） | `/data/tee/<数字ID>` | ❌ | ★★★★ | 开发板/原型 |
| **RPMB** | `CFG_RPMB_FS=y` | eMMC RPMB 分区 | eMMC 内部（块地址） | ✅（硬件） | ★★ | 量产车规 |
| **REE FS + RPMB** | 两者都 y | 混合 | REE FS 数据 + RPMB 存 hash | ✅（软件） | ★★★ | 生产推荐 |

### REE FS 模式下的安全属性

| 安全机制 | 说明 |
|----------|------|
| 机密性 | 所有数据用 AES-GCM 加密，密钥链 HUK → SSK → TSK → FEK |
| 完整性 | GCM 认证标签验证，篡改可检测 |
| 原子性 | Hash Tree 双版本更新，写中断不会损坏数据 |
| 防回滚（REE FS） | 无硬件保护，依赖 RPMB 可选 |
| 防回滚（RPMB） | eMMC 硬件写计数器，一次写入不可重放 |

---

## 密钥在 TEE 内存在线期间的形式

密钥除了在磁盘上加密存储外，在 TEE 运行时还有**两种内存呈现形式**：

### 1. 序列化属性（`struct obj_attrs`）

```c
/* 从磁盘加载到内存后 */
struct pkcs11_object {
    TEE_UUID            *uuid;           // 文件 UUID
    struct obj_attrs    *attributes;     // ← 密钥明文在此内存中
    struct ck_token     *token;          // 所属 Token
    TEE_OperationHandle  key_handle;    // TEE 操作句柄（已导入的密钥）
    TEE_ObjectHandle     attribs_hdl;   // GP 持久化对象句柄
};

/* attributes 中直接包含 CKA_VALUE 明文（对称密钥）*/
/* 或 CKA_MODULUS + CKA_PRIVATE_EXPONENT（RSA 私钥）*/
/* 但此内存仅在 TEE Secure RAM 中，REE 无法访问 */
```

### 2. TEE Operation Handle（加密操作态）

```c
/* 当执行加解密时，密钥被导入 TEE 内部操作 */
/* object.c 中处理 processing 时调用：*/

TEE_AllocateOperation(&op, TEE_ALG_AES_CBC_PKCS7, TEE_MODE_ENCRYPT, 256);
TEE_SetOperationKey(op, key_from_attributes);
/* ↑ 此时密钥进入 TEE Core 的 crypto_*() 层 */
/*   在 LibTomCrypt 或硬件 Crypto Cell 内部 */
```

---

## 密钥存储完整生命周期图

```
应用创建密钥 (C_CreateObject / C_GenerateKey)
  │
  ├─ CKA_TOKEN = true?
  │   │
  │   ├── NO ──→ 仅存于 TA 内存 obj->attributes
  │   │           TA 关闭 → 密钥随 TA 销毁而消失
  │   │
  │   └── YES ─→ 分配 UUID
  │                │
  │                ▼
  │           序列化全部 PKCS#11 属性到 obj_attrs
  │                │
  │                ▼
  │           TEE_CreatePersistentObject(UUID)
  │                │
  │                ▼
  │           Secure Storage 层
  │           (tee_svc_storage.c)
  │                │
  │                ▼
  │           GP TEE File System
  │           (tee_ree_fs.c / tee_rpmb_fs.c)
  │                │
  │                ▼
  │           密钥管理器 (tee_fs_key_manager.c)
  │                │
  │                ├─ 生成 FEK (File Encryption Key)
  │                ├─ 用 TSK 加密 FEK → enc_fek
  │                │   (TSK = HMAC-SHA256(SSK, TA_UUID))
  │                ├─ 用 FEK + GCM 加密密钥明文数据
  │                └─ 写入 Hash Tree (fs_htree.c)
  │                     │
  │                     ▼
  │                 物理存储:
  │                 ├─ REE FS: /data/tee/<N>
  │                 │   全部数据 AES-GCM 加密 + 完整性保护
  │                 └─ RPMB: eMMC 安全分区
  │                     额外防回滚 + 认证写
  │
  ▼
Token 重启后读取流程:
  pkcs11_init() → init_persistent_db(token_id)
    → TEE_OpenPersistentObject(DB_UUID)
    → 读取解密 token_persistent_main（PIN 等信息）
    → 读取 token_persistent_objs → 得到 UUID 列表
    → 按需懒加载: load_persistent_object_attributes(obj)
       → TEE_OpenPersistentObject(obj->uuid)
       → 解密 → 填入 obj->attributes
       → 密钥在 TEE 内存中可用
```

---

## 安全边界总结

| 攻击面 | 保护措施 | 安全等级 |
|--------|----------|----------|
| REE 侧直接读 /data/tee/ | AES-GCM 加密，密钥在 TEE 内 | ✅ 机密性 |
| REE 侧篡改加密文件 | GCM 认证标签校验失败 | ✅ 完整性 |
| 回滚旧版本的密钥文件 | RPMB 写计数器 / Hash Tree | ✅ 防回滚（RPMB） |
| REE 侧 SMC 攻击 | OP-TEE 验证调用来源和参数 | ✅ 隔离 |
| 物理拆解 eMMC 读 RPMB | eMMC 认证写，密钥在 SoC OTP | ✅ 硬件绑定 |
| TA 内内存泄露 | Secure RAM 对 REE 不可见 | ✅ 内存隔离 |
| 重放 PKCS#11 命令 | 每次操作需经会话认证 | ✅ 会话安全 |
| SoC 级 HUK 泄露 | 存储在 eFuse 中，一次性编程 | ⚠️ 取决于芯片实现 |
