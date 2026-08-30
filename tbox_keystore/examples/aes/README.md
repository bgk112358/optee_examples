# aes_crypt — TEE 文件 AES 加解密示例

## 概述

通过 TBox Keystore TA 对**任意大小的二进制文件**做 AES-CBC 加解密。支持：

| 能力 | 说明 |
|------|------|
| PKCS#7 填充 | TA 内完成（加密末块补 1..16 字节；解密末块校验并去除） |
| IV 选择 | `--iv zero`（全零 IV）或 `--iv random`（TA 生成随机 IV） |
| 任意文件大小 | ≤ 1 MB 单次 TA 调用；更大文件 64 KB 分块，CBC 链式续块 |
| 权限控制 | 复用 TA 的 ACL：密钥需 `--encrypt` / `--decrypt` 权限 |

调用链：

```
aes_crypt → libteec (CA) → CMD_FILE_ENCRYPT(21) / CMD_FILE_DECRYPT(22) → TA
```

## 命令

```
./aes_crypt encrypt --key <label> --in <input> --out <output> [--iv zero|random] [--verbose]
./aes_crypt decrypt --key <label> --in <input> --out <output> [--iv zero|random] [--verbose]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `encrypt` / `decrypt` | — | 操作模式 |
| `--key <label>` | — | TA 中的 AES 密钥标签（256 位） |
| `--in <file>` | — | 输入文件 |
| `--out <file>` | — | 输出文件 |
| `--iv zero` | ✓ 默认 | 全零 IV，输出文件 = 纯密文 |
| `--iv random` | — | TA 生成随机 IV，输出文件 = `[16B IV][密文]` |
| `--verbose` | 关 | 打印每分块耗时明细 |

> 加解密两端的 `--iv` 必须一致。`--iv random` 时解密端自动从文件头读 IV。

### 时间统计

程序末尾打印一行汇总（`CLOCK_MONOTONIC` 纳秒计时，毫秒级精度）：

```
aes_crypt: encrypt timing: total=12.345 ms  TA-calls=2  TA-time=11.111 ms  file=131072 B  rate=10.62 MB/s
```

| 字段 | 含义 |
|------|------|
| `total` | 整个加解密耗时（含读文件 + TA 调用 + 写文件） |
| `TA-calls` | TA 调用次数（≤1MB 为 1，分块为 N） |
| `TA-time` | 所有 TA 调用累计耗时（不含读写文件） |
| `rate` | 吞吐量 = 文件字节数 / 总耗时（MB/s） |

加 `--verbose` 时，每个分块额外打印一行：

```
aes_crypt:   chunk 0: 5.234 ms
aes_crypt:   chunk 1: 4.876 ms
```

## 输出文件格式

| 模式 | 输出文件布局 |
|------|------|
| `--iv zero` | `[密文]` |
| `--iv random` | `[16 字节随机 IV][密文]` |

## 外部接口

引用 TA 共享头文件 `ta/include/tbox_keystore_ta.h` 中的：

```c
#define CMD_FILE_ENCRYPT  21
#define CMD_FILE_DECRYPT  22

struct aes_file_meta {
    uint32_t key_size;   /* AES 密钥位数 (256)        */
    uint32_t iv_mode;    /* 0=零 IV, 1=随机 IV        */
    uint32_t is_first;   /* 1=首块（初始化 IV）        */
    uint32_t is_last;    /* 1=末块（PKCS#7 填充/去除） */
    uint8_t  iv[16];     /* 双向：加密随机IV回传 / 解密IV传入 / 续块IV */
};
```

直接调用 `TEEC_InvokeCommand()`，不依赖 ENGINE / OpenSSL。

## 内部逻辑

### 加密（do_encrypt）

```
读取文件 → 计算文件大小
若 size ≤ 1MB: 单次调用 (is_first=1, is_last=1)
否则:          CHUNK=64KB 循环调用, 每块 is_last 标识, CBC 续块

每块:
  meta.iv = 首块? (TA 按 iv_mode 生成/置零) : 上一块密文尾16字节
  TEEC_InvokeCommand(CMD_FILE_ENCRYPT)
  首块且 iv_mode=random → 先写 16B IV 头, 再写密文
  记录本块密文尾16字节作为下一块 IV
```

### 解密（do_decrypt）

```
读取文件 → 若 iv_mode=random 先读 16B IV 头作为首块 IV
校验密文总长是 16 的倍数
同样单次/分块, 每块 is_last 标识, 续块 IV = 上一块密文尾16字节
TA 内去除末块 PKCS#7 填充
```

## 前置依赖

| 依赖 | 来源 | 部署路径 |
|------|------|----------|
| `libteec` | `optee400/optee_client/export-ca_arm64/lib/libteec.a` | 静态链接 |
| TA 头文件 | `ta/include/tbox_keystore_ta.h` | 编译期 |
| `optee_example_tbox_keystore` | `../../host/` 构建 | `/usr/bin/` |
| TA (`f8e9209a-….ta`) | `../../ta/` 构建 | `/lib/optee_armtz/` |

## 构建

```bash
cd examples/aes && mkdir -p build && cd build
cmake .. -DCMAKE_C_COMPILER=/home/test0923/workspace/OP-TEE/optee400/toolchains/aarch64/bin/aarch64-none-linux-gnu-gcc

// cmake .. -DOPENSSL_ROOT_DIR=/home/test0923/workspace/OP-TEE/three_part/openssl/out -DCMAKE_C_COMPILER=/home/test0923/workspace/optee400/toolchains/aarch64/bin/aarch64-linux-gnu-gcc

make
```

产物：`aes_crypt`（单可执行文件，静态链接 libteec.a）。

> 需与 TA 版本配套：TA 需已包含 `CMD_FILE_ENCRYPT/DECRYPT`（本示例新增），否则 TA 返回 `TEE_ERROR_NOT_SUPPORTED`。

## 设备端运行

```bash
# 1. 部署 TA + 灌装密钥
cd ta && make && cp f8e9209a-….ta /lib/optee_armtz/
cd examples/aes
./scrypt/setup_aes_key.sh file-key

# 2. 加密（随机 IV）
./aes_crypt encrypt --key file-key --iv random --in plain.txt --out data.enc

# 3. 解密（必须与加密使用相同 --iv 模式）
./aes_crypt decrypt --key file-key --iv random --in data.enc --out restored.txt

# 4. 校验
cmp plain.txt restored.txt && echo "ROUNDTRIP OK"
```

## 预期输出

```
=== Step 1: Init PIN ===
PIN provisioned

=== Step 2: Generate AES key ... ===
AES-256 key generated: 'file-key' (perms=0xc)

=== Step 3: Verify ===
Key:       file-key
Type:      AES
Size:      256 bits
Perms:     SIGN=N VERIFY=N ENCRYPT=Y DECRYPT=Y

aes_crypt: encrypt: plain.txt -> data.enc (random IV)
aes_crypt: encrypt timing: total=2.358 ms  TA-calls=1  TA-time=1.102 ms  file=16384 B  rate=6.94 MB/s
aes_crypt: decrypt: data.enc -> restored.txt (random IV)
aes_crypt: decrypt timing: total=2.091 ms  TA-calls=1  TA-time=0.998 ms  file=16384 B  rate=7.84 MB/s
ROUNDTRIP OK
```

## 限制

- **CBC + 零 IV 的安全提示**：`--iv zero` 时相同明文+相同密钥产生相同密文（无随机化），仅适合内部演示；生产建议用 `--iv random`。
- **单次调用上限**：≤ 1 MB 走单次调用；更大文件自动分块，无大小上限。
- **密钥类型**：必须为 AES 密钥（示例启动时通过 `CMD_GET_INFO` 校验，非 AES 报错退出）。
- **PKCS#7 填充不占用 TA 堆**：加密末块填充采用 `TEE_CipherUpdate`（主体流式）+ 16 字节尾块 `TEE_CipherDoFinal` 实现，TA 内不复制整块明文，任意大小文件不受 TA 堆（`TA_DATA_SIZE`）限制。

## 相关文档

- [../../README.md](../../README.md) — TBox Keystore 项目说明
- [../../ta/README.md](../../ta/README.md) — TA 说明
- [../../docs/05-key-storage.md](../../docs/05-key-storage.md) — TEE 内密钥存储机制
