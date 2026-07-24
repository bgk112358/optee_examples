# PKCS#11 + OP-TEE PKCS#11 TA 路线（推荐）

## 技术调用链（REE → TEE 完整路径）

```
[应用层] 调用 OpenSSL EVP API (EVP_EncryptInitEx, EVP_SealInit ...)
    │
    ▼
[libp11 ENGINE] — pkcs11 ENGINE for OpenSSL
    将 EVP 操作映射为 PKCS#11 C_* 调用
    │ 配置: openssl.cnf 中 engine_id = pkcs11
    ▼
[PKCS#11 Module — optee_pkcs11.so]
    实现 PKCS#11 v2.40 标准接口 (C_EncryptInit / C_Decrypt / C_Sign ...)
    内部调用 TEE Client API
    │
    ▼
[libteec.so] — TEE Client API
    TEEC_InitializeContext()
    TEEC_OpenSession(&sess, &UUID_PKCS11_TA, ...)
    TEEC_InvokeCommand(&sess, PKCS11_CMD_ENCRYPT_INIT, ...)
    TEEC_InvokeCommand(&sess, PKCS11_CMD_ENCRYPT, ...)
    TEEC_CloseSession(&sess)
    TEEC_FinalizeContext()
    │
    ▼
[Linux TEE Driver — drivers/tee/optee/]
    optee_smc.c → smc_call() → SMC #0 → 切换到 Secure World
    │
    ▼
[OP-TEE OS — Secure Monitor]
    tee_entry.c → 根据 UUID 路由到 PKCS#11 TA
    │
    ▼
[PKCS#11 TA — ta/pkcs11/src/pkcs11_ta.c]
    TA_InvokeCommandEntryPoint()
      ├─ PKCS11_CMD_ENCRYPT_INIT → 解析机制+密钥 → TEE_AllocateOperation()
      ├─ PKCS11_CMD_ENCRYPT      → TEE_CipherUpdate()
      └─ PKCS11_CMD_ENCRYPT_FINAL → TEE_CipherDoFinal()
    │
    ▼
[TEE Internal Crypto API]
    tee_svc_cryp.c → crypto_*() 接口
    │
    ▼
[LibTomCrypt / Mbed TLS / HW Crypto Cell]
    实际执行加解密
```

---

## 各层关键代码

### 1. PKCS#11 Module (REE 侧) — 桥接 PKCS#11 C_* → libteec

OP-TEE 上游在 `optee_client` 仓库中提供了 `optee_pkcs11` 模块源码。

#### 头文件 — pkcs11_ta.h（TA UUID 和命令 ID）

```c
/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2019, Linaro Limited */
/* 来自 optee_os/ta/pkcs11/include/pkcs11_ta.h */

#define TA_PKCS11_UUID \
    { 0xbd11e341, 0x7b31, 0x4e8a, \
        { 0xa2, 0x2e, 0x49, 0xfb, 0x50, 0x8b, 0xb2, 0x33 } }

/* PKCS#11 命令 ID 定义 */
#define PKCS11_CMD_SLOT_LIST              0
#define PKCS11_CMD_SLOT_INFO              1
#define PKCS11_CMD_TOKEN_INFO             2
#define PKCS11_CMD_OPEN_SESSION           3
#define PKCS11_CMD_CLOSE_SESSION          4
#define PKCS11_CMD_FIND_OBJECTS_INIT      5
#define PKCS11_CMD_FIND_OBJECTS           6
#define PKCS11_CMD_FIND_OBJECTS_FINAL     7
#define PKCS11_CMD_ENCRYPT_INIT           8
#define PKCS11_CMD_ENCRYPT                9
#define PKCS11_CMD_ENCRYPT_UPDATE         10
#define PKCS11_CMD_ENCRYPT_FINAL          11
#define PKCS11_CMD_DECRYPT_INIT           12
#define PKCS11_CMD_DECRYPT                13
#define PKCS11_CMD_DECRYPT_UPDATE         14
#define PKCS11_CMD_DECRYPT_FINAL          15
/* ... 更多命令: SIGN, VERIFY, GENERATE_KEY, GENERATE_KEY_PAIR ... */
```

#### PKCS#11 Module 核心 — encrypt/decrypt 路径骨架

```c
/* 文件: optee_client/libpkcs11/src/session_encrypt.c（示意结构）*/

/* 1. 建立与 PKCS#11 TA 的 TEE 会话 */
static CK_RV tee_session_init(void)
{
    TEEC_Result res;
    TEEC_Context *ctx = get_global_ctx();

    res = TEEC_InitializeContext(NULL, ctx);
    if (res != TEEC_SUCCESS)
        return CKR_TOKEN_NOT_PRESENT;

    TEEC_UUID uuid = TA_PKCS11_UUID;
    res = TEEC_OpenSession(ctx, &session, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, NULL);
    if (res != TEEC_SUCCESS)
        return CKR_SESSION_HANDLE_INVALID;

    return CKR_OK;
}

/* 2. C_EncryptInit — 设置加密操作 */
CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hKey)
{
    TEEC_Operation op = { 0 };
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,  /* 机制参数 */
        TEEC_VALUE_INPUT,        /* 密钥句柄 */
        TEEC_NONE, TEEC_NONE);

    /* 打包 CK_MECHANISM 到 param[0] */
    pack_mechanism(&op.params[0], pMechanism);
    op.params[1].value.a = hKey;

    TEEC_Result res = TEEC_InvokeCommand(&session,
                        PKCS11_CMD_ENCRYPT_INIT, &op, NULL);
    return tee_err_to_pkcs11(res);
}

/* 3. C_Encrypt — 执行加密（单次完成） */
CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,
                CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                CK_BYTE_PTR pEncryptedData,
                CK_ULONG_PTR pulEncryptedDataLen)
{
    TEEC_Operation op = { 0 };
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,   /* 明文入 */
        TEEC_MEMREF_TEMP_OUTPUT,  /* 密文出 */
        TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = pData;
    op.params[0].tmpref.size   = ulDataLen;
    op.params[1].tmpref.buffer = pEncryptedData;
    op.params[1].tmpref.size   = *pulEncryptedDataLen;

    TEEC_Result res = TEEC_InvokeCommand(&session,
                        PKCS11_CMD_ENCRYPT, &op, NULL);
    if (res == TEEC_SUCCESS)
        *pulEncryptedDataLen = op.params[1].tmpref.size;

    return tee_err_to_pkcs11(res);
}

/* 4. 分块加密 Update / Final */
CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                      CK_BYTE_PTR pEncryptedPart,
                      CK_ULONG_PTR pulEncryptedPartLen)
{
    /* 同 C_Encrypt，命令改为 PKCS11_CMD_ENCRYPT_UPDATE */
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession,
                     CK_BYTE_PTR pLastEncryptedPart,
                     CK_ULONG_PTR pulLastEncryptedPartLen)
{
    /* 命令改为 PKCS11_CMD_ENCRYPT_FINAL */
}
```

---

### 2. PKCS#11 TA (Secure World) — 接收 PKCS#11 命令并调用内部加密 API

```c
/* 文件: optee_os/ta/pkcs11/src/pkcs11_ta.c（示意骨架）*/

TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext,
                                      uint32_t cmdID,
                                      uint32_t paramTypes,
                                      TEE_Param params[4])
{
    struct pkcs11_session *session = sessionContext;

    switch (cmdID) {
    case PKCS11_CMD_ENCRYPT_INIT: {
        /* 1. 解析算法机制（如 CKM_AES_CBC_PAD）*/
        struct pkcs11_attribute *mech = parse_mechanism(&params[0]);

        /* 2. 查找密钥对象 */
        struct pkcs11_object *key = session_find_object(session,
                                        params[1].value.a);

        /* 3. 分配 TEE 操作 */
        TEE_OperationHandle op;
        TEE_AllocateOperation(&op, TEE_ALG_AES_CBC_PKCS7,
                              TEE_MODE_ENCRYPT, key->key_size * 8);

        /* 4. 设置密钥 */
        TEE_SetOperationKey(op, key->tee_key);

        /* 5. 设置 IV */
        TEE_CBCInit(op, mech->iv, mech->iv_len);

        session->current_op = op;
        return TEE_SUCCESS;
    }

    case PKCS11_CMD_ENCRYPT: {
        size_t out_len = params[1].tmpref.size;
        TEE_CipherUpdate(session->current_op,
                         params[0].tmpref.buffer, params[0].tmpref.size,
                         params[1].tmpref.buffer, &out_len);
        params[1].tmpref.size = out_len;
        return TEE_SUCCESS;
    }

    case PKCS11_CMD_ENCRYPT_FINAL:
        TEE_CipherDoFinal(session->current_op,
                          NULL, 0,
                          params[0].tmpref.buffer, &out_len);
        params[0].tmpref.size = out_len;
        TEE_FreeOperation(session->current_op);
        session->current_op = NULL;
        return TEE_SUCCESS;

    /* DECRYPT, SIGN, VERIFY, GENERATE_KEY ... 结构类似 */
    }
}
```

---

### 3. libp11 配置（REE 侧 OpenSSL 集成）

#### openssl.cnf

```ini
# /etc/ssl/openssl.cnf 或应用层覆盖
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-3/libpkcs11.so
MODULE_PATH = /usr/lib/liboptee_pkcs11.so
PIN = 123456
init = 0

# 默认算法路由到 pkcs11 engine（可选强制）
[default_section]
pkcs11_default_algorithms = ALL
```

#### 应用代码 — 无感调用

```c
/* 应用层完全透明，用标准的 OpenSSL API 即可 */
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, ptlen);
EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
/* ↑ 这些调用被 libp11 引擎拦截路由到 PKCS#11 → libteec → TA */
```

#### Makefile 构建

```makefile
# optee_pkcs11 module 构建
CC = aarch64-linux-gnu-gcc
CFLAGS = -fPIC -I$(TEEC_EXPORT)/include
LDFLAGS = -shared -L$(TEEC_EXPORT)/lib -lteec

liboptee_pkcs11.so: module.o session_encrypt.o session_decrypt.o \
                    session_digest.o session_sign_verify.o
    $(CC) $(LDFLAGS) -o $@ $^
```

---

## 关键数据结构

### 核心对象

```c
/* object.h — PKCS#11 对象定义 */
struct pkcs11_object {
    TEE_UUID            *uuid;           /* 持久化对象的 UUID 文件名 */
    struct obj_attrs    *attributes;     /* 序列化的 PKCS#11 属性集 */
    struct ck_token     *token;          /* 所属 Token */
    TEE_OperationHandle  key_handle;     /* TEE 操作句柄 */
    TEE_ObjectHandle     attribs_hdl;    /* GP 持久化对象句柄 */
    LIST_ENTRY(pkcs11_object) link;      /* 链表 */
};

/* pkcs11_token.h — Token 运行时状态 */
struct ck_token {
    enum pkcs11_token_state state;
    uint32_t session_count;
    uint32_t rw_session_count;
    struct object_list object_list;
    struct token_persistent_main *db_main;   /* 持久化主数据库（内存副本） */
    struct token_persistent_objs *db_objs;   /* 持久化对象列表（内存副本） */
};
```

### PKCS#11 命令协议

| 命令 | ID | 功能 |
|------|----|------|
| PKCS11_CMD_ENCRYPT_INIT | 8 | 初始化加密操作（选择算法+密钥） |
| PKCS11_CMD_ENCRYPT | 9 | 单次完成加密 |
| PKCS11_CMD_ENCRYPT_UPDATE | 10 | 分块加密 |
| PKCS11_CMD_ENCRYPT_FINAL | 11 | 收尾（处理 padding） |
| PKCS11_CMD_DECRYPT_INIT | 12 | 初始化解密 |
| PKCS11_CMD_DECRYPT | 13 | 单次完成解密 |
| PKCS11_CMD_DECRYPT_UPDATE | 14 | 分块解密 |
| PKCS11_CMD_DECRYPT_FINAL | 15 | 解密收尾 |

---

## 实现步骤（tbox 生产环境）

```
1. 内核配置
   ├─ CONFIG_TEE=y
   ├─ CONFIG_OPTEE=y
   └─ CONFIG_OPTEE_SHM_NUM_PRIV_PAGES=...

2. optee_os 配置
   ├─ CFG_PKCS11_TA=y
   ├─ CFG_RPMB_FS=y (量产推荐防回滚)
   └─ CFG_REE_FS=y (开发阶段)

3. optee_client 编译
   ├─ libteec.so → /usr/lib
   ├─ tee-supplicant → /usr/bin
   └─ optee_pkcs11 module → /usr/lib/liboptee_pkcs11.so

4. libp11 编译安装
   ├─ libpkcs11.so → /usr/lib/engines-3/
   └─ p11-kit 可选

5. 配置 openssl.cnf
   └─ 加载 pkcs11 engine + optee_pkcs11 模块

6. 应用层
   └─ 直接调用 OpenSSL EVP API，零改动
```
