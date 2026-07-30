# dongle_test — Dongle & SO-PIN Test Suite

## 概述

两个测试，覆盖 dongle 抽象层 + SO-PIN 全生命周期。

| 测试 | 类型 | 运行环境 | 内容 |
|------|:--:|------|------|
| `dongle_test` | C 单元测试 | 开发机 (host gcc) | `dongle_ops` 接口：factory/probe/open/sign/verify/pubkey/serial/attr |
| `test_so_lifecycle.sh` | Shell 集成测试 | 目标机 (QEMU/真机) | CA CLI 全生命周期：灌装→锁定→SO 解锁→重锁→错误路径 |

## dongle_test (C 单元测试)

### 构建

```bash
cd examples/dongle_test && mkdir -p build && cd build
cmake .. && make
```

### 运行

```bash
./dongle_test
```

### 测试用例

| 用例 | 内容 |
|------|------|
| factory | `dongle_get("dummy")` 返回非 NULL，`dongle_get("nonexistent")` 返回 NULL |
| probe_no_key | 无密钥文件时 `probe()` 返回 0 |
| open_close | `probe()`=1, `open()` 成功, `close()` 不崩溃 |
| sign | `sign(digest, 32)` 返回 DER 签名，错误长度 digest 被拒绝 |
| sign_verify | 签名后 OpenSSL 验签成功，篡改 digest 验签失败 |
| get_pubkey | `get_pubkey()` 返回有效 DER，可被 `d2i_PUBKEY` 解析为 EC key |
| serial_attr | `get_serial()` → `0xDEAD0001`, `get_attr("name")` → `"dummy"`, 不存在的属性返回 -1 |
| double_open | 两次 `open()` 获得不同 ctx, `close(NULL)` 安全 |
| detect | `dongle_detect()` 在有 dummy key 时自动检测到 dummy 后端 |

## test_so_lifecycle.sh (集成测试)

### 前提

- TEE + TA 已部署（QEMU 或真机）
- `tbox_keystore` 在 PATH
- 已执行 `make gen-dummy-key`（生成 `~/.tbox/dummy-dongle-key.pem`）

### 运行

```bash
cd examples/dongle_test
chmod +x test_so_lifecycle.sh
./test_so_lifecycle.sh
```

### 测试流程

```
Phase A: SO 灌装
  init-so-pin → provision-dongle ×2 → so-info (验证 PROVISIONED + 2 dongles)

Phase B: 锁定 + 解锁
  lock → gen-rsa(失败) → so-unlock → gen-rsa(成功) → delete

Phase C: 重新锁定
  so-lock → so-info(验证 LOCKED) → gen-rsa(失败)

Phase D: 错误路径
  连续 3 次错误 SO-PIN → 冷却生效 → 错误 dongle index → 拒绝
```

## 依赖

| 依赖 | `dongle_test` | `test_so_lifecycle.sh` |
|------|:--:|:--:|
| OpenSSL dev | ✓ | — |
| Dongle source files | ✓ (`../../host/dongle/`) | — |
| TEE + TA | — | ✓ |
| tbox_keystore | — | ✓ |
| Dummy key file | — | ✓ |

## 相关文档

- [host/dongle/dongle_ops.h](../../host/dongle/dongle_ops.h) — dongle 统一接口
- [docs/24-so-pin-yubikey-unlock.md](../../docs/24-so-pin-yubikey-unlock.md) — SO-PIN 设计文档
- [docs/09-pin-management.md](../../docs/09-pin-management.md) — Provisioning PIN 管理
