# rsa_crypt — TEE 文件 RSA-2048 签名/验签 + 基准测试

## 概述

对任意文件做 RSA-2048 签名/验签，签名在 TEE 内完成。支持吞吐基准测试。

调用链：

```
rsa_crypt → 读文件 → SHA-256(OpenSSL, CA) → libteec (CA) → CMD_SIGN(5)/CMD_VERIFY(6) → TA
```

> hash 在 CA 侧用 OpenSSL 计算（SHA-256，32 字节），TA 内对摘要做
> `RSASSA-PKCS1-v1_5-SHA256` 签名/验签。

## 命令

```
./rsa_crypt sign   --key <label> --in <file> --out <sig> [--bench-sec N] [--verbose]
./rsa_crypt verify --key <label> --in <file> --sig <sig>  [--bench-sec N] [--verbose]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `sign` / `verify` | — | 操作模式 |
| `--key <label>` | — | TA 中的 RSA-2048 密钥标签（需 `--sign` 权限；`--verify` 是 gen-rsa 默认权限） |
| `--in <file>` | — | 输入文件（任意大小，读入内存算 SHA-256） |
| `--out <file>` | — | 签名输出文件（RSA-2048 = 256 字节原始二进制） |
| `--sig <file>` | — | 验签时读取的签名文件 |
| `--bench-sec N` | 关 | 循环 TA 调用约 N 秒，输出吞吐/平均耗时 |
| `--verbose` | 关 | 打印计算出的 SHA-256 摘要前 4 + 后 2 字节 |

## 计算 hash 的参数

每次运行都会打印：

```
rsa_crypt: hash=SHA-256  digest=32B  padding=RSASSA-PKCS1-v1_5  key=RSA-2048  sig=256B  key-label=rsa-key
```

| 参数 | 值 |
|------|-----|
| hash 算法 | SHA-256 |
| digest 长度 | 32 字节 |
| 填充方式 | RSASSA-PKCS1-v1_5（对应 TA 的 `TEE_ALG_RSASSA_PKCS1_V1_5_SHA256`） |
| 密钥 | RSA-2048 |
| 签名长度 | 256 字节 |

## 基准测试（--bench-sec）

`--bench-sec N` 循环调用 TA 的 `CMD_SIGN`（或 `CMD_VERIFY`）约 N 秒，计时用
`CLOCK_MONOTONIC`（毫秒级精度）。测的是**纯 TA 调用耗时**（不含文件读/算 hash），
循环复用同一份 32 字节摘要。

输出示例（`--bench-sec 1`）：

```
rsa_crypt: sign bench:   time=1.004 s  ops=384  avg=2.615 ms/op  rate=382.5 ops/s
rsa_crypt: verify bench: time=1.002 s  ops=1276  avg=0.785 ms/op  rate=1273.5 ops/s
```

| 字段 | 含义 |
|------|------|
| `time` | 实际基准时长（≈N 秒） |
| `ops` | 完成的操作次数 |
| `avg` | 平均每次耗时（ms/op） |
| `rate` | 吞吐（ops/s，即每秒能签/验多少次） |

> 签名（私钥运算）通常比验签（公钥运算）慢——RSA-2048 私钥操作为模幂运算，
> 公钥操作用小指数，快很多。这正对应上面的数字差异。

## 外部接口

引用 TA 共享头文件 `ta/include/tbox_keystore_ta.h`：

```c
#define CMD_SIGN    5
#define CMD_VERIFY  6
```

直接调用 `TEEC_InvokeCommand()`，不依赖 ENGINE。

## 内部逻辑

```
sign:
  读文件 → SHA-256(OpenSSL) → CMD_SIGN(摘要) → sig(256B) → 写文件
  → 自校验 CMD_VERIFY → [--bench-sec] 循环签名测吞吐

verify:
  读文件 → SHA-256(OpenSSL) → 读 sig → CMD_VERIFY(摘要+sig) → VALID/INVALID
  → [--bench-sec] 循环验签测吞吐
```

## 前置依赖

| 依赖 | 来源 | 部署路径 |
|------|------|----------|
| `libteec` | `optee400/optee_client/export-ca_arm64/lib/libteec.a` | 静态链接 |
| OpenSSL 1.1.1 | `three_part/openssl/out` | 静态链接 libcrypto.a |
| TA 头文件 | `ta/include/tbox_keystore_ta.h` | 编译期 |
| `optee_example_tbox_keystore` | `../../host/` 构建 | `/usr/bin/` |
| TA (`f8e9209a-….ta`) | `../../ta/` 构建 | `/lib/optee_armtz/` |

## 构建

```bash
cd examples/rsa && mkdir -p build && cd build
cmake .. -DCMAKE_C_COMPILER=/home/test0923/workspace/OP-TEE/optee400/toolchains/aarch64/bin/aarch64-none-linux-gnu-gcc
make
```

产物：`rsa_crypt`（单可执行文件，静态链接 libteec.a + libcrypto.a）。

## 设备端运行

```bash
# 1. 灌装 PIN + RSA-2048 密钥
./scrypt/setup_rsa_key.sh rsa-key

# 2. 签名 + 自校验 + 基准
./rsa_crypt sign --key rsa-key --in plain.txt --out sig.bin --bench-sec 1

# 3. 单独验签
./rsa_crypt verify --key rsa-key --in plain.txt --sig sig.bin

# 4. 篡改测试（改一个字节，验签应 INVALID）
cp sig.bin sig_tamper.bin
printf '\x00' | dd of=sig_tamper.bin bs=1 seek=100 conv=notrunc
./rsa_crypt verify --key rsa-key --in plain.txt --sig sig_tamper.bin
```

## 预期输出

```
=== Step 1: Init PIN ===
PIN provisioned

=== Step 2: Generate RSA-2048 key (sign perm; verify perm is default) ===
RSA-2048 key generated: 'rsa-key' (perms=0x13)   # VERIFY(0x02)+EXPORT_PUB(0x10)+SIGN(0x01)

=== Step 3: Verify ===
Key:       rsa-key
Type:      RSA
Size:      2048 bits
Perms:     SIGN=Y VERIFY=Y ENCRYPT=N DECRYPT=N

rsa_crypt: hash=SHA-256  digest=32B  padding=RSASSA-PKCS1-v1_5  key=RSA-2048  sig=256B  key-label=rsa-key
rsa_crypt: sign: plain.txt -> sig.bin (256 B sig)
rsa_crypt: verify: VALID (self-check)
rsa_crypt: sign bench:   time=1.004 s  ops=384  avg=2.615 ms/op  rate=382.5 ops/s
rsa_crypt: verify: VALID
rsa_crypt: verify bench: time=1.002 s  ops=1276  avg=0.785 ms/op  rate=1273.5 ops/s
```

## 限制

- **密钥**：必须为 RSA-2048 且带 `--sign` 权限（`--verify` 是 gen-rsa 默认权限，无需额外指定；示例启动时经 `CMD_GET_INFO` 校验，非 RSA / 非 2048 报错退出）。
- **hash 在 CA 计算**：文件内容在 REE 侧算 SHA-256，仅 32 字节摘要进入安全世界；若要求文件全程不出安全世界，需扩展 TA 新增"TA 内算 hash + 签名"命令（本示例未实现）。
- **签名一次性读入内存**：文件整体读入内存算 hash，超大文件需注意 REE 内存。

## 相关文档

- [../../README.md](../../README.md) — TBox Keystore 项目说明
- [../../ta/README.md](../../ta/README.md) — TA 说明
- [../../docs/13-openssl-engine-integration.md](../../docs/13-openssl-engine-integration.md) — ENGINE 集成（同链路签名）
