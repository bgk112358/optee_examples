# engine_test — ENGINE 冒烟测试

## 概述

最小化测试程序，验证 tbox_keystore ENGINE 的完整回调链路：

1. 注册 ENGINE → 2. 获取句柄 → 3. 初始化 TEEC 会话 → 4. 从 TA 加载密钥 → 5. EVP 签名（走 ENGINE → TA） → 6. EVP 验签

## 命令

```bash
engine_test [key-label]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `key-label` | `server-key` | TA 中的密钥 label |

## 外部接口

引用单个外部符号：

```c
extern int ENGINE_load_tbox_keystore(void);
```

链接 `libe_tbox_keystore.so` 后可用。不直接调用任何 TEEC 或 TA 接口。

## 内部逻辑（6 步骤）

```
[1] ENGINE_load_tbox_keystore()           ← 全局注册 ENGINE
[2] ENGINE_by_id("tbox_keystore")         ← 获取 ENGINE 句柄
[3] ENGINE_init(e)                         ← → tee_start() → TEEC_OpenSession
[4] ENGINE_load_private_key(e, label, …)   ← → CMD_KEY_EXPORT_PUB → 构造 RSA
[5] EVP_DigestSign(EVP_sha256(), …)        ← → rsa_sign → CMD_SIGN
[6] EVP_DigestVerify(…)                    ← → rsa_verify → CMD_VERIFY
```

每步成功打印 `OK`，全部通过打印 `ALL TESTS PASSED`。

## 前置依赖

| 依赖 | 来源 | 部署路径 |
|------|------|----------|
| `libe_tbox_keystore.so` | `../../engine/build/` | `/usr/lib/` |
| `libteec.a` | `optee400/optee_client/` | 静态链接到 .so |
| OpenSSL 1.1.x | `three_part/openssl/out/` | 交叉编译 |
| TA 已灌装 PIN + 密钥 | `tbox_keystore --init-pin …` | `/lib/optee_armtz/` |

## 构建

```bash
cd examples/engine_test && mkdir -p build && cd build
cmake .. -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
    -DOPENSSL_ROOT_DIR=/home/test0923/workspace/three_part/openssl/out \
    -DOPENSSL_INCLUDE_DIR=/home/test0923/workspace/three_part/openssl/out/include \
    -DOPENSSL_SSL_LIBRARY=/home/test0923/workspace/three_part/openssl/out/lib/libssl.so \
    -DOPENSSL_CRYPTO_LIBRARY=/home/test0923/workspace/three_part/openssl/out/lib/libcrypto.so
make -j
```

产物：`engine_test`（单可执行文件，静态链接了 engine .so）。

## 设备端运行

```bash
# 1. 确保 TA + ENGINE 已部署
# 2. 确保密钥已灌装
./scrypt/setup_keys.sh
./tbox_keystore --info server-key

# 3. 运行
./engine_test server-key
```

## 预期输出

```
=== ENGINE smoke test  (label: server-key) ===

[1] Registering tbox_keystore ENGINE ...    OK
[2] ENGINE_by_id('tbox_keystore') ...       OK
[3] ENGINE_init  (TEEC -> TA) ...           OK
[4] ENGINE_load_private_key('server-key') ... OK
[5] EVP_DigestSign (goes through TA) ...    OK  (signature: 256 bytes)
[6] EVP_DigestVerify via ENGINE key ...     OK

=== ALL TESTS PASSED ===
```

## 相关文档

- [engine/README.md](../../engine/README.md) — ENGINE 实现说明
- [15-engine-debug-issues.md](../../docs/15-engine-debug-issues.md) — ENGINE 调试记录
