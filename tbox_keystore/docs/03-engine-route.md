# OpenSSL ENGINE 路线

## 技术调用链

```
应用 (EVP_EncryptInitEx(...))
    │
    ▼
[e_optee ENGINE .so] — EVP 框架按 NID 查找算法
    └── engine_table_select(EVP_PKEY_AES256_CBC) → ENGINE_finish()
    │
    ├─ ENGINE_set_ciphers() 注册的回调 → 返回 EVP_CIPHER 结构
    │     内部 fields: EVP_CIPHER_nid, EVP_CIPHER_block_size
    │                  init_key = optee_aes256_init_key
    │                  do_cipher = optee_aes_do_cipher
    │
    ├─ optee_aes256_init_key() → TEEC_OpenSession(...)
    │
    └─ optee_aes_do_cipher() → TEEC_InvokeCommand(sess, CMD_AES_CBC, ...)
        → libteec → SMC → OP-TEE → Crypto TA → TEE_CipherUpdate()
```

---

## 关键骨架代码

### e_optee.c — ENGINE 注册部分

```c
/* Engine 入口 — bind_engine 是 OpenSSL 加载 engine 的入口点 */
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <tee_client_api.h>

static TEEC_Context optee_ctx;
static int engine_refcount = 0;

/* ---- 对称加解密实现 ---- */

static int optee_aes256_init_key(EVP_CIPHER_CTX *ctx,
                                  const unsigned char *key,
                                  const unsigned char *iv, int enc)
{
    /* 懒初始化 TEE 上下文 */
    if (engine_refcount++ == 0)
        TEEC_InitializeContext(NULL, &optee_ctx);

    /* 打开 Crypto TA 会话 */
    TEEC_Session *sess = EVP_CIPHER_CTX_get_app_data(ctx);
    if (!sess) {
        sess = calloc(1, sizeof(TEEC_Session));
        TEEC_UUID uuid = TA_CRYPTO_UUID;  /* 自定义 Crypto TA */
        TEEC_OpenSession(&optee_ctx, sess, &uuid,
                         TEEC_LOGIN_PUBLIC, NULL, NULL, NULL);
        EVP_CIPHER_CTX_set_app_data(ctx, sess);
    }

    /* 通过 TEEC_InvokeCommand 将密钥注入 TA */
    TEEC_Operation op = { 0 };
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,  /* 密钥材料 */
        TEEC_VALUE_INPUT,        /* enc 标志 */
        TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)key;
    op.params[0].tmpref.size   = 32;       /* AES-256 */
    op.params[1].value.a       = enc;      /* 1=encrypt, 0=decrypt */

    return TEEC_SUCCESS == TEEC_InvokeCommand(sess,
               CMD_SET_KEY, &op, NULL) ? 1 : 0;
}

static int optee_aes_do_cipher(EVP_CIPHER_CTX *ctx,
                                unsigned char *out,
                                const unsigned char *in, size_t inl)
{
    TEEC_Session *sess = EVP_CIPHER_CTX_get_app_data(ctx);
    TEEC_Operation op = { 0 };

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,   /* 明文入 */
        TEEC_MEMREF_TEMP_OUTPUT,  /* 密文出 */
        TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)in;
    op.params[0].tmpref.size   = inl;
    op.params[1].tmpref.buffer = out;
    op.params[1].tmpref.size   = inl + 32;  /* 预留 padding */

    TEEC_Result res = TEEC_InvokeCommand(sess,
                          CMD_AES_CBC_UPDATE, &op, NULL);

    /* 更新输出长度 */
    if (res == TEEC_SUCCESS)
        EVP_CIPHER_CTX_set_buf_len(ctx, op.params[1].tmpref.size);
    return res == TEEC_SUCCESS ? 1 : 0;
}

/* ---- EVP_CIPHER 结构体定义 ---- */

static const EVP_CIPHER optee_aes_256_cbc = {
    .nid      = NID_aes_256_cbc,
    .block_size = 16,
    .key_len  = 32,
    .iv_len   = 16,
    .flags    = EVP_CIPH_CBC_MODE,
    .init     = optee_aes256_init_key,
    .do_cipher = optee_aes_do_cipher,
    .ctx_size = sizeof(TEEC_Session *),  /* 存放 session 指针 */
};

/* ---- ENGINE 注册 ---- */

static int optee_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                          const int **nids, int nid)
{
    if (!cipher) {
        /* 第一次调用：返回支持的 NID 列表 */
        static int cipher_nids[] = { NID_aes_256_cbc, NID_aes_128_cbc, ... };
        *nids = cipher_nids;
        return ARRAY_SIZE(cipher_nids);
    }

    /* 按 nid 返回对应的 EVP_CIPHER */
    switch (nid) {
    case NID_aes_256_cbc: *cipher = &optee_aes_256_cbc; break;
    /* ... */
    default: *cipher = NULL; return 0;
    }
    return 1;
}

void ENGINE_load_optee(void)
{
    ENGINE *e = ENGINE_new();
    ENGINE_set_id(e, "optee");
    ENGINE_set_name(e, "OP-TEE Cryptographic Engine");
    ENGINE_set_ciphers(e, optee_ciphers);
    ENGINE_set_digests(e, optee_digests);   /* SHA-256 等同理 */
    ENGINE_set_pkey_meths(e, optee_pkey);   /* RSA/ECC 同理 */
    ENGINE_add(e);
    ENGINE_free(e);
}
```

---

### 自定义 Crypto TA（Secure World 端）

```c
/* 文件: ta/crypto_ta/src/crypto_ta.c — 定制的加解密 TA */

#define TA_CRYPTO_UUID \
    { 0xa1234567, 0x... }

TEE_Result TA_InvokeCommandEntryPoint(void *sessCtx,
                                      uint32_t cmd,
                                      uint32_t pt, TEE_Param params[4])
{
    static TEE_OperationHandle op;

    switch (cmd) {
    case CMD_SET_KEY: {
        /* 从 params[0] 获取密钥材料 */
        TEE_Attribute attr;
        TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
                             params[0].tmpref.buffer,
                             params[0].tmpref.size);

        int enc = params[1].value.a;
        TEE_AllocateOperation(&op, TEE_ALG_AES_CBC_PKCS7,
                              enc ? TEE_MODE_ENCRYPT : TEE_MODE_DECRYPT,
                              256);
        TEE_SetOperationKey(op, &attr);  /* 密钥永远在 TEE 内 */
        return TEE_SUCCESS;
    }

    case CMD_AES_CBC_UPDATE: {
        size_t out_len = params[1].tmpref.size;
        TEE_CipherUpdate(op,
                         params[0].tmpref.buffer, params[0].tmpref.size,
                         params[1].tmpref.buffer, &out_len);
        params[1].tmpref.size = out_len;
        return TEE_SUCCESS;
    }
    /* CMD_AES_CBC_FINAL → TEE_CipherDoFinal */
    }
}
```

---

## 加载方式

### 方式 A：环境变量（零配置）

```bash
export OPENSSL_ENGINES=/usr/lib/engines-1.1
OPENSSL_CONF=/dev/null openssl engine -t -c optee
```

### 方式 B：代码中显式加载

```c
ENGINE_load_optee();
ENGINE *e = ENGINE_by_id("optee");
ENGINE_set_default(e, ENGINE_METHOD_ALL);
```

### 方式 C：openssl.cnf 全局

```ini
openssl_conf = openssl_init
[openssl_init]
engines = engine_section
[engine_section]
optee = optee_section
[optee_section]
engine_id = optee
dynamic_path = /usr/lib/engines-1.1/e_optee.so
default_algorithms = ALL
```

---

## Makefile 构建

```makefile
CC = aarch64-linux-gnu-gcc
CFLAGS = -fPIC $(shell pkg-config --cflags openssl) -I$(TEEC_EXPORT)/include
LDFLAGS = -shared $(shell pkg-config --libs openssl) -L$(TEEC_EXPORT)/lib -lteec

e_optee.so: e_optee.o
    $(CC) $(LDFLAGS) -o $@ $^

install:
    cp e_optee.so /usr/lib/engines-1.1/
```

---

## 适用范围

| 场景 | 是否推荐 | 说明 |
|------|----------|------|
| OpenSSL 1.x 存量系统 | ✅ | 唯一成熟方案 |
| OpenSSL 3.x 新项目 | ❌ | Provider 是官方方向 |
| 需要长期维护 | ❌ | ENGINE API 已废弃 |
| 快速原型验证 | ✅ | 实现量最小（~800行） |
