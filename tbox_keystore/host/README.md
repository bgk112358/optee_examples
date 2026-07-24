# host — TBox Keystore Client Application (CA)

## 概述

`keystore_client.c` 是 tbox_keystore TA 的 REE 侧命令行管理工具。通过 TEE Client API（libteec）与 OP-TEE 中的 TA 通信，提供密钥全生命周期管理和密码学操作。

**单一源文件，约 650 行 C。**

## 命令

```bash
tbox_keystore <command> [options]
```

| 命令 | 说明 | 示例 |
|------|------|------|
| `--init-pin <hex>` | 写入灌装 PIN（一次性） | `--init-pin a1b2c3d4` |
| `--lock` | 锁定 TA（禁用写入） | `--lock` |
| `--gen-rsa <label>` | 生成 RSA 密钥对 | `--gen-rsa device-key --size 2048 --sign` |
| `--gen-aes <label>` | 生成 AES 密钥 | `--gen-aes ota-key --size 256 --decrypt` |
| `--export-pub <label>` | 导出 RSA 公钥 | `--export-pub device-key --out key.pub` |
| `--sign <label>` | RSA SHA-256 签名 | `--sign device-key --data <hex>` |
| `--verify <label>` | RSA SHA-256 验签 | `--verify device-key --data <hex> --sig <hex>` |
| `--encrypt <label>` | AES-CBC 加密 | `--encrypt ota-key --data <hex>` |
| `--decrypt <label>` | AES-CBC 解密 | `--decrypt ota-key --data <hex>` |
| `--info <label>` | 查看密钥信息 | `--info device-key` |
| `--delete <label>` | 删除密钥 | `--delete old-key` |

## 外部接口

### 对外依赖

```c
#include <tee_client_api.h>       // TEE Client API (libteec)
#include "tbox_keystore_ta.h"     // TA UUID + CMD_* 枚举
```

### 内部全局状态

| 变量 | 类型 | 说明 |
|------|------|------|
| `g_ctx` | `TEEC_Context` | TEE 上下文，每进程一个 |
| `g_sess` | `TEEC_Session` | 与 TA 的会话 |
| `g_initialized` | `int` | 会话是否已建立 |

### 内部函数

| 函数 | 说明 |
|------|------|
| `init_tee()` | `TEEC_InitializeContext` + `TEEC_OpenSession` |
| `fini_tee()` | `TEEC_CloseSession` + `TEEC_FinalizeContext` |
| `invoke_cmd(cmd, op)` | 封装 `TEEC_InvokeCommand` |
| `do_init_pin(hex)` | 解析 hex PIN，发送 `CMD_PIN_INIT` |
| `do_gen_rsa(label, size, perms)` | 发送 `CMD_KEY_GEN_RSA`，permissions 组合 `PERM_SIGN/VERIFY/DECRYPT` |
| `do_gen_aes(label, size, perms)` | 发送 `CMD_KEY_GEN_AES`，permissions 组合 `PERM_ENCRYPT/DECRYPT` |
| `do_export_pub(label, outfile)` | 发送 `CMD_KEY_EXPORT_PUB`，输出 hex 或文件 |
| `do_sign(label, data, outfile)` | 发送 `CMD_SIGN`，输出签名 |
| `do_verify(label, data, sig)` | 发送 `CMD_VERIFY`，输出 Valid/Invalid |
| `do_encrypt(label, data, outfile)` | 发送 `CMD_ENCRYPT_AES` |
| `do_decrypt(label, data, outfile)` | 发送 `CMD_DECRYPT_AES` |
| `do_get_info(label)` | 发送 `CMD_GET_INFO`，打印 key_type/size/permissions |
| `do_delete_key(label)` | 发送 `CMD_KEY_DELETE` |
| `do_lock()` | 发送 `CMD_PROVISION_LOCK` |
| `hex_decode(hex, &buf, &len)` | hex 字符串 → 二进制 |
| `hex_print(fp, data, len)` | 二进制 → hex 字符串打印 |
| `read_file(path, &buf, &len)` | 读文件到 buffer |
| `write_file(path, data, len)` | 写 buffer 到文件 |

### 权限位

```c
#define PERM_SIGN       0x01      // 可签名
#define PERM_VERIFY     0x02      // 可验签
#define PERM_ENCRYPT    0x04      // 可加密
#define PERM_DECRYPT    0x08      // 可解密
#define PERM_EXPORT_PUB 0x10      // 可导出公钥
```

`--gen-rsa` 默认开启 `PERM_EXPORT_PUB | PERM_VERIFY`，`--sign` 加 `PERM_SIGN`，`--decrypt` 加 `PERM_DECRYPT`。

## TA 命令映射

| 命令 ID | 宏 | 数据方向 | 说明 |
|:---:|------|------|------|
| 0 | `CMD_PIN_INIT` | REE → TA | 写入 PIN |
| 1 | `CMD_KEY_GEN_RSA` | REE → TA | 生成 RSA 密钥 |
| 2 | `CMD_KEY_GEN_AES` | REE → TA | 生成 AES 密钥 |
| 3 | `CMD_KEY_EXPORT_PUB` | REE → TA → REE | 导出 RSA 公钥 |
| 4 | `CMD_KEY_DELETE` | REE → TA | 删除密钥 |
| 5 | `CMD_SIGN` | REE → TA → REE | RSA 签名 |
| 6 | `CMD_VERIFY` | REE → TA → REE | RSA 验签 |
| 7 | `CMD_ENCRYPT_AES` | REE → TA → REE | AES 加密 |
| 8 | `CMD_DECRYPT_AES` | REE → TA → REE | AES 解密 |
| 9 | `CMD_GET_INFO` | REE → TA → REE | 查询密钥信息 |
| 10 | `CMD_PROVISION_LOCK` | REE → TA | 锁定 TA |

## TEEC 参数类型约定

每个命令使用固定的 `TEEC_PARAM_TYPES` 组合，TA 侧验证不匹配则返回 `TEE_ERROR_BAD_PARAMETERS`。

| 命令 | param[0] | param[1] | param[2] | param[3] |
|------|------|------|------|------|
| `CMD_PIN_INIT` | MEMREF_INPUT (PIN) | — | — | — |
| `CMD_KEY_GEN_RSA` | MEMREF_INPUT (label) | VALUE_INPUT (size\|perms) | — | — |
| `CMD_SIGN` | MEMREF_INPUT (label) | MEMREF_INPUT (data) | MEMREF_OUTPUT (sig) | — |
| `CMD_VERIFY` | MEMREF_INPUT (label) | MEMREF_INPUT (data) | MEMREF_INPUT (sig) | VALUE_OUTPUT (result) |
| `CMD_KEY_EXPORT_PUB` | MEMREF_INPUT (label) | MEMREF_OUTPUT (pubkey) | — | — |

## 构建

```bash
cd host && mkdir -p build && cd build
cmake .. && make
# 产物: tbox_keystore
```

**注意**：此 CMake 构建只编译 CA 命令行工具。TA 需用 Makefile 单独构建（参见 [ta/README.md](../ta/README.md)）。

## 部署

```bash
cp tbox_keystore /usr/bin/
```

## 相关文档

- [ta/README.md](../ta/README.md) — TA 实现
- [engine/README.md](../engine/README.md) — ENGINE 实现
- [ta/include/tbox_keystore_ta.h](../ta/include/tbox_keystore_ta.h) — UUID + 命令 ID 定义
