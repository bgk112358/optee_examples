# OpenSSL Provider 路线（OpenSSL 3.x 原生）

## 技术调用链

```
应用 (EVP_EncryptInitEx(libctx, EVP_aes_256_cbc, NULL, key, iv))
    │
    ▼
[EVP 框架] 按算法名查找 Provider
    ├─ OSSL_PROVIDER_load(NULL, "optee")
    │   → provider_init() 被调用
    │   → provider_register_ciphers()
    │   → OSSL_ALGORITHM[] = { { "AES-256-CBC", dispatch, ... }, ...}
    │
    ├─ OSSL_DISPATCH table
    │   ├─ OSSL_FUNC_CIPHER_NEWCTX       → optee_cipher_newctx
    │   ├─ OSSL_FUNC_CIPHER_ENCRYPT_INIT → optee_cipher_encrypt_init
    │   ├─ OSSL_FUNC_CIPHER_UPDATE       → optee_cipher_update
    │   ├─ OSSL_FUNC_CIPHER_FINAL        → optee_cipher_final
    │   └─ OSSL_FUNC_CIPHER_FREECTX      → optee_cipher_freectx
    │
    ▼
[optee_provider.so] 内部 → libteec → SMC → OP-TEE OS → Crypto TA
```

---

## 关键骨架代码

### provider_optee.c — 完整的 Provider 实现

```c
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/evp.h>
#include <tee_client_api.h>

/* ========= Provider 入口 ========= */

/* 算法描述 */
#define OP_TEE_AES_256_CBC_PROPERTIES \
    "provider=optee,iv=any,fips=no"

/* Provider 全局状态 */
typedef struct {
    OSSL_LIB_CTX *libctx;
    TEEC_Context tee_ctx;
    int tee_initialized;
} OPTEE_PROV_CTX;

/* ========= Cipher 实现 ========= */

/* Per-operation 上下文 */
typedef struct {
    OPTEE_PROV_CTX *prov;
    TEEC_Session *session;
    int encrypt;       /* 1=enc, 0=dec */
    size_t keylen;
    unsigned char key[32];
    unsigned char iv[16];
    int init_done;
} OPTEE_CIPHER_CTX;

/* newctx — 分配操作上下文 */
static void *optee_cipher_newctx(void *provctx, const char *alg)
{
    OPTEE_CIPHER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    ctx->prov = (OPTEE_PROV_CTX *)provctx;
    return ctx;
}

/* encrypt_init — 初始化加密操作 */
static int optee_cipher_encrypt_init(void *vctx,
                                     const unsigned char *key,
                                     size_t keylen,
                                     const unsigned char *iv,
                                     size_t ivlen,
                                     const OSSL_PARAM params[])
{
    OPTEE_CIPHER_CTX *ctx = (OPTEE_CIPHER_CTX *)vctx;

    /* 1. 初始化 TEE 连接（懒加载）*/
    if (!ctx->prov->tee_initialized) {
        TEEC_InitializeContext(NULL, &ctx->prov->tee_ctx);
        ctx->prov->tee_initialized = 1;
    }

    /* 2. 打开会话到 Crypto TA */
    ctx->session = OPENSSL_zalloc(sizeof(TEEC_Session));
    TEEC_UUID uuid = TA_CRYPTO_UUID;
    TEEC_OpenSession(&ctx->prov->tee_ctx, ctx->session,
                     &uuid, TEEC_LOGIN_PUBLIC,
                     NULL, NULL, NULL);

    /* 3. 注入密钥到 TA */
    ctx->encrypt = 1;
    memcpy(ctx->key, key, keylen);
    memcpy(ctx->iv,  iv,  ivlen);
    ctx->keylen = keylen;

    TEEC_Operation op = { 0 };
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,  /* key */
        TEEC_MEMREF_TEMP_INPUT,  /* iv  */
        TEEC_VALUE_INPUT,        /* enc flag */
        TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)key;
    op.params[0].tmpref.size   = keylen;
    op.params[1].tmpref.buffer = (void *)iv;
    op.params[1].tmpref.size   = ivlen;
    op.params[2].value.a       = 1;  /* encrypt */

    TEEC_InvokeCommand(ctx->session, CMD_INIT_CIPHER, &op, NULL);
    ctx->init_done = 1;
    return 1;
}

/* decrypt_init — 同上，encrypt=0 */
static int optee_cipher_decrypt_init(void *vctx,
                                     const unsigned char *key,
                                     size_t keylen,
                                     const unsigned char *iv,
                                     size_t ivlen,
                                     const OSSL_PARAM params[])
{
    /* 结构同上，params[2].value.a = 0 */
}

/* update — 分块加解密 */
static int optee_cipher_update(void *vctx,
                               unsigned char *out, size_t *outl,
                               size_t outsize,
                               const unsigned char *in, size_t inl)
{
    OPTEE_CIPHER_CTX *ctx = (OPTEE_CIPHER_CTX *)vctx;
    TEEC_Operation op = { 0 };

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,   /* 明文入 */
        TEEC_MEMREF_TEMP_OUTPUT,  /* 密文出 */
        TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)in;
    op.params[0].tmpref.size   = inl;
    op.params[1].tmpref.buffer = out;
    op.params[1].tmpref.size   = outsize;

    TEEC_Result res = TEEC_InvokeCommand(ctx->session,
                          CMD_CIPHER_UPDATE, &op, NULL);
    if (res != TEEC_SUCCESS) return 0;

    *outl = op.params[1].tmpref.size;
    return 1;
}

/* final — 收尾（处理 padding） */
static int optee_cipher_final(void *vctx,
                              unsigned char *out, size_t *outl,
                              size_t outsize)
{
    OPTEE_CIPHER_CTX *ctx = (OPTEE_CIPHER_CTX *)vctx;
    TEEC_Operation op = { 0 };

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_OUTPUT,  /* 末块密文 */
        TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = out;
    op.params[0].tmpref.size   = outsize;

    TEEC_Result res = TEEC_InvokeCommand(ctx->session,
                          CMD_CIPHER_FINAL, &op, NULL);
    if (res != TEEC_SUCCESS) return 0;

    *outl = op.params[0].tmpref.size;
    return 1;
}

/* freectx — 清理 */
static void optee_cipher_freectx(void *vctx)
{
    OPTEE_CIPHER_CTX *ctx = (OPTEE_CIPHER_CTX *)vctx;
    if (ctx->session) {
        TEEC_CloseSession(ctx->session);
        OPENSSL_free(ctx->session);
    }
    OPENSSL_free(ctx);
}

/* ========= OSSL_DISPATCH 表 ========= */

static const OSSL_DISPATCH optee_aes256cbc_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX,         (void *)optee_cipher_newctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,   (void *)optee_cipher_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,   (void *)optee_cipher_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE,         (void *)optee_cipher_update },
    { OSSL_FUNC_CIPHER_FINAL,          (void *)optee_cipher_final },
    { OSSL_FUNC_CIPHER_FREECTX,        (void *)optee_cipher_freectx },
    { OSSL_FUNC_CIPHER_GET_PARAMS,     (void *)optee_cipher_get_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void *)optee_cipher_get_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void *)optee_cipher_set_ctx_params },
    { 0, NULL }
};

/* 算法注册表 */
static const OSSL_ALGORITHM optee_ciphers[] = {
    { "AES-256-CBC",   OP_TEE_AES_256_CBC_PROPERTIES,
      optee_aes256cbc_functions, "OP-TEE AES-256-CBC" },
    { "AES-128-CBC",   OP_TEE_AES_128_CBC_PROPERTIES,
      optee_aes128cbc_functions, "OP-TEE AES-128-CBC" },
    { "AES-256-GCM",   ... },
    { NULL, NULL, NULL, NULL }
};

/* ========= Provider 生命周期 ========= */

int OSSL_PROVIDER_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    OPTEE_PROV_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    ctx->libctx = (OSSL_LIB_CTX *)handle;
    *provctx = ctx;

    static const OSSL_DISPATCH optee_dispatch[] = {
        { OSSL_FUNC_PROVIDER_TEARDOWN,
          (void *)optee_provider_teardown },
        { OSSL_FUNC_PROVIDER_QUERY_OPERATION,
          (void *)optee_provider_query_operation },
        { 0, NULL }
    };
    *out = optee_dispatch;
    return 1;
}

/* Provider 查询 — 告诉 OpenSSL 我们支持什么 */
static const OSSL_ALGORITHM *optee_provider_query_operation(
        void *provctx, int operation_id, int *no_store)
{
    *no_store = 0;
    switch (operation_id) {
    case OSSL_OP_CIPHER:  return optee_ciphers;
    case OSSL_OP_DIGEST:  return optee_digests;   /* SHA-256... */
    case OSSL_OP_KEYMGMT: return optee_keymgmt;   /* RSA/ECC keys */
    }
    return NULL;
}

static void optee_provider_teardown(void *provctx)
{
    OPTEE_PROV_CTX *ctx = (OPTEE_PROV_CTX *)provctx;
    if (ctx->tee_initialized)
        TEEC_FinalizeContext(&ctx->tee_ctx);
    OPENSSL_free(ctx);
}
```

---

## Provider 加载方式

### 方式 A：openssl.cnf 全局加载

```ini
# /etc/ssl/openssl.cnf
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
optee = optee_sect
default = default_sect

[optee_sect]
module = /usr/lib/ossl-modules/optee_provider.so
activate = 1

[default_sect]
activate = 1
```

### 方式 B：代码加载

```c
OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "optee");
/* 此后所有 EVP 调用自动路由到 OP-TEE */
```

### 方式 C：按算法选择（不全局覆盖）

```c
EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC",
                                       "provider=optee");
```

---

## Makefile 构建

```makefile
CC = aarch64-linux-gnu-gcc
CFLAGS = -fPIC $(shell pkg-config --cflags openssl3) -I$(TEEC_EXPORT)/include
LDFLAGS = -shared $(shell pkg-config --libs openssl3) -L$(TEEC_EXPORT)/lib -lteec

optee_provider.so: provider_optee.o
    $(CC) $(LDFLAGS) -o $@ $^

install:
    cp optee_provider.so /usr/lib/ossl-modules/
```

---

## Provider 与 ENGINE 差异速查

| 维度 | ENGINE | Provider |
|------|--------|----------|
| 入口函数 | `bind_engine()` / `ENGINE_load_*()` | `OSSL_PROVIDER_init()` |
| 算法注册 | `ENGINE_set_ciphers(e, cb)` | `OSSL_ALGORITHM[]` 数组 |
| 操作上下文 | `EVP_CIPHER_CTX` + app_data | Provider 自定义 ctx 结构体 |
| 参数传递 | 直接函数参数 | `OSSL_PARAM` 数组（key/value） |
| 内存管理 | 手动 | Provider 可重载 OPENSSL_zalloc |
| 适用范围 | **已废弃**（3.x 兼容） | **官方推荐** |

---

## 适用范围

| 场景 | 是否推荐 | 说明 |
|------|----------|------|
| OpenSSL 3.x 新项目 | ✅ | 官方推荐，未来主流 |
| OpenSSL 1.x 系统 | ❌ | 不兼容 |
| 需要 FIPS | ⚠️ | 需额外验证 |
| 快速原型验证 | ⚠️ | 实现量稍大（~1000行） |
