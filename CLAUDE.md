# CLAUDE.md — TBox Keystore 项目上下文

本文件记录项目当前状态，供 Claude Code 下次打开本目录时快速恢复上下文。

## 项目概述

TBox 安全服务系统：用 ARM TrustZone + OP-TEE 替代离散 HSM 安全芯片，为 HTTPS / MQTTS 提供密钥管理和密码学运算。核心链路：OpenSSL ENGINE → CA (REE) → TA (TEE 安全世界)。

- **TA UUID**: `f8e9209a-3c7d-4d6b-a15e-7f328b11c049`
- **OP-TEE 版本**: 3.2（注意：不支持 ECDSA transient object，会 TA panic）
- **工作空间根**: `/home/test0923/workspace/OP-TEE/`
- **交叉编译工具链**: `OP-TEE/optee400/toolchains/aarch64/`
- **OpenSSL 交叉编译产物**: `OP-TEE/three_part/openssl/out`（1.1.1b）

> 旧路径 `/home/test0923/workspace/OP-TEE/optee400` 和 `/home/test0923/workspace/OP-TEE/three_part` 已通过软链接指向 `OP-TEE/` 下的新位置，旧的硬编码路径仍可用。

## 目录结构

```
optee_examples_AG519M/tbox_keystore/
├── ta/                    # 可信应用（安全世界）
│   ├── entry.c            # 命令分发 + Gate 逻辑
│   ├── pin_mgr.c          # Provisioning PIN 管理
│   ├── so_pin_mgr.c       # SO-PIN 管理 + 解锁协议 + 白名单
│   ├── keystore.c         # 密钥生命周期
│   ├── crypto_ops.c       # RSA/AES 密码学封装
│   ├── acl.c              # 权限校验
│   └── sub.mk             # 源文件清单（新增 .c 要加这里）
├── host/                  # CA 客户端（REE）
│   ├── keystore_client.c  # CLI 工具（含 SO 命令）
│   ├── dongle/            # dongle 抽象层
│   │   ├── dongle_ops.h   # 统一接口
│   │   ├── dongle_factory.c
│   │   ├── dongle_dummy.c # 模拟 dongle（本地 P-256 密钥文件）
│   │   └── dongle_yubikey.c # YubiKey 后端（ykman CLI fallback）
│   └── Makefile           # DONGLE_BACKENDS 条件编译
├── engine/                # OpenSSL ENGINE (e_tbox_keystore.c)
├── examples/              # 各示例（见下方「examples 目录」）
├── scripts/               # 产线灌装脚本
└── docs/                  # 设计文档（25-30 是 YubiKey/SGX/调试记录 相关）
```

## 当前实现状态

### 已完成并调试通过

1. **SO-PIN + dongle 双因子解锁**（命令 12-18）
   - 状态机：UNSET → PROVISIONED → LOCKED ↔ UNLOCKED → BRICKED
   - 失败计数器：连续 3 次错 PIN → 60s 冷却；累计 1000 次 → 永久 BRICKED
   - `test_so_lifecycle.sh` 全流程通过（灌装→锁定→SO解锁→重锁→错误路径）

2. **dongle 抽象层**（`host/dongle/`）
   - `dongle_ops` 统一接口 + factory 自动检测（YubiKey → Dummy）
   - `dongle_test` 单元测试 9 项全通过

3. **关键架构决策**：OP-TEE 3.2 不支持 ECDSA transient object（`TEE_AllocateTransientObject(TEE_TYPE_ECDSA_*)` 直接 TA panic），因此：
   - ECDSA 验签移到 CA 侧（OpenSSL `ECDSA_do_verify`）
   - `CMD_SO_UNLOCK_CONFIRM`(18) 当前无参数，TA 只检查 `g_so_challenge_valid`，**不验白名单不验签名**（已知安全缺口）
   - 见 docs/28-yubikey-full-lifecycle.md 的坦诚分析

### 关键命令映射（TA 侧）

| 命令 | ID | 功能 |
|------|:--:|------|
| CMD_PIN_INIT | 0 | 灌装 PIN |
| CMD_KEY_GEN_RSA/AES | 1/2 | 密钥生成 |
| CMD_KEY_EXPORT_PUB | 3 | 导出公钥 |
| CMD_KEY_DELETE | 4 | 删除密钥 |
| CMD_SIGN/VERIFY | 5/6 | RSA 签名/验签 |
| CMD_ENCRYPT_AES/DECRYPT_AES | 7/8 | AES 加解密 |
| CMD_GET_INFO | 9 | 密钥信息 |
| CMD_PROVISION_LOCK | 10 | 锁定 TA |
| CMD_RSA_DECRYPT | 11 | RSA 解密（TLS） |
| CMD_SO_PIN_INIT | 12 | 写 SO-PIN |
| CMD_PROVISION_DONGLE | 13 | 注册单个 dongle 公钥 |
| CMD_SO_UNLOCK_REQ | 14 | 解锁请求（Phase 1，返回 challenge） |
| CMD_SO_UNLOCK_CONFIRM | 18 | 解锁确认（当前无参数，**待改 RSA 版**） |
| CMD_SO_LOCK | 16 | 重新锁定 |
| CMD_SO_GET_INFO | 17 | SO 状态查询 |
| **CMD_FILE_ENCRYPT/DECRYPT** | **21/22** | **AES 分块文件加解密（IV 可选零/随机，PKCS#7 在 TA 内）** |

## 最新工作（最近几轮）

**YubiKey 方案演进**（docs/25-29）：
- 25-yubikey-guide.md — YubiKey 4/5 对比、PIV 功能详解、操作指南
- 26-sgx-provisioning-attestation.md — SGX 远程证明四层次方案（A本地/B离线签名/C云端SGX）
- 27-yubikey-provisioning-trusted-server.md — 可信服务器替代 SGX（工控机+安全官员都不可信）
- 28-yubikey-full-lifecycle.md — SO 解锁闭环 + 安全缺口分析
- **29-rsa-yubikey-provisioning.md — 最终方案（RSA-2048 替代 ECDSA）**

**核心结论（重要）**：
- OP-TEE 3.2 不能做 ECDSA 验签 → 改 YubiKey 用 RSA-2048（PIV Slot 9a 手动生成）
- RSA-2048 验签 OP-TEE 原生支持（`crypto_rsa_verify` 已实现）
- 这样 TA 可以在 `so_unlock_confirm()` 内**原子完成** RSA 验签 + 白名单匹配，闭合安全缺口
- doc 29 是完整从零开始的方案文档，还未实施到代码

## examples 目录

| 示例 | 位置 | 功能 | 状态 |
|------|------|------|:--:|
| engine_test | `examples/engine_test/` | ENGINE 回调链冒烟测试（RSA 签名） | ✅ 通过 |
| tls_mutual_auth | `examples/tls_mutual_auth/` | TLS 双向认证 | ✅ 通过 |
| https_client | `examples/https_client/` | HTTPS 客户端 | ✅ 通过 |
| mqtts | `examples/mqtts/` | MQTTS 发布/订阅 | ✅ 通过 |
| dongle_test | `examples/dongle_test/` | dongle 抽象层 + SO-PIN 生命周期测试 | ✅ 9 项通过 |
| **aes** | `examples/aes/aes_crypt.c` | **文件 AES 加解密（CMD 21/22）** | ✅ 编译通过，待设备实测 |
| **rsa** | `examples/rsa/rsa_crypt.c` | **文件 RSA-2048 签名/验签 + 吞吐基准** | ✅ 编译通过，待设备实测 |

### aes_crypt（文件 AES 加解密）

- 命令：`encrypt` / `decrypt`，参数 `--key/--in/--out/--iv zero|random/--verbose`
- 复用 TA 新命令 `CMD_FILE_ENCRYPT`(21) / `CMD_FILE_DECRYPT`(22)
- IV：`zero`（全零）/ `random`（TA 生成随机 IV，输出文件带 16B IV 头）
- 填充：**PKCS#7 在 TA 内**（`crypto_aes_encrypt_ex`），**流式实现不占 TA 堆**——主体 `TEE_CipherUpdate` + 16B 尾块 `TEE_CipherDoFinal`，任意大小文件不受 `TA_DATA_SIZE`(32KB) 限制（方案 B，修复 0xFFFF000C）
- 分块：≤1MB 单次调用，更大文件 64KB 分块，CBC 链式续块（IV=上一块密文尾16B）
- 依赖：libteec + `ta/include`；无需 OpenSSL

### rsa_crypt（文件 RSA-2048 签名/验签 + 基准）

- 命令：`sign` / `verify`，参数 `--key/--in/--out/--sig/--bench-sec N/--verbose`
- 复用 TA `CMD_SIGN`(5) / `CMD_VERIFY`(6)，**未改 TA**
- 密钥权限：`--gen-rsa` 需 `--sign`（`--verify`/`--export-pub` 是 gen-rsa 默认权限，**不支持 `--verify` 选项**）
- hash 在 CA 用 OpenSSL `SHA256()` 计算（32B 摘要进 TA，`RSASSA-PKCS1-v1_5-SHA256`）
- 每次运行打印 hash 参数：`hash=SHA-256 digest=32B padding=RSASSA-PKCS1-v1_5 key=RSA-2048 sig=256B`
- 基准：`--bench-sec N` 循环 TA 调用约 N 秒，输出 `time/ops/avg(ms/op)/rate(ops/s)`
- 依赖：libteec + OpenSSL（`three_part/openssl/out`）

> 两个新示例均需先跑 `scrypt/setup_aes_key.sh` / `setup_rsa_key.sh` 灌装 PIN+密钥。
> 构建：`cd examples/<name>/build && cmake .. -DCMAKE_C_COMPILER=<aarch64 gcc> && make`

## 未完成事项

0. **examples/aes 与 examples/rsa 待设备实测**：
   - aes：重新部署 `.ta`（含 CMD 21/22）后跑 `aes_crypt encrypt/decrypt` + `cmp` 往返校验；用大文件（如 5MB）验证方案 B 不再报 0xFFFF000C
   - rsa：跑 `rsa_crypt sign/verify` + `--bench-sec 1` 得真实吞吐

1. **doc 29 方案的代码实施**（RSA-2048 版）：
   - TA 新增 `CMD_PROVISION_DONGLE_MANIFEST`(19)：可信服务器 RSA 签名 manifest → 验签 → 原子替换白名单
   - TA 修改 `CMD_SO_UNLOCK_CONFIRM`(18)：加 pubkey_der + sig_der 参数，RSA 验签 + 白名单匹配原子操作
   - TA 新增 `rsa_import_pubkey_from_der()` 函数（DER → TEE_ObjectHandle）
   - CA 新增 `--provision-dongle-manifest` 命令
   - 可信服务器脚本 gen-manifest.sh + sign-manifest.sh（doc 29 附录已写好）

2. **VMware 环境 YubiKey 直通问题**（正在排查）：
   - `lsusb` 显示 `0e0f:0004 VMware Virtual CCID`（虚拟智能卡读卡器，非 YubiKey 真身）
   - `pcsc_scan` 能识别 YubiKey 4（ATR 正确）
   - `ykman piv info` 报 "No YubiKey Detected"
   - 排查方向：`ykman piv info -r "VMware Virtual USB CCID 00 00"` 或 `yubico-piv-tool -a status`

## 关键约束/坑

- **OP-TEE 3.2 无 ECDSA**：`TEE_ALG_ECDSA_P256` 会导致 TA panic（已在 crypto_ops.c 中留了死代码 crypto_ecdsa_verify，等 OP-TEE 升级后启用）
- **REE FS 并发**：OP-TEE 3.2 REE FS 同 session reopen 会 ACCESS_CONFLICT，需 session 级缓存
- **`sed` 改 C 代码易破坏**：本项目多次因 sed 插行破坏 if/else 块、多行函数调用。**改 C 代码用 Read + Edit/Write，不要用 sed**
- **TA 源文件清单**：新增 .c 必须加到 `ta/sub.mk`
- **CMakeLists 两个**：顶层 `optee_examples_AG519M/CMakeLists.txt`（含 teec include/lib 路径）和 `tbox_keystore/CMakeLists.txt`
- **公钥/私钥格式**：RSA-2048 公钥 DER 约 294 字节；P-256 约 91 字节

## 文档索引

| 文档 | 主题 |
|------|------|
| docs/01-08 | 架构/密钥存储/灌装流程/PIN 管理 |
| docs/13-openssl-engine-integration.md | ENGINE 集成 |
| docs/15-engine-debug-issues.md | ENGINE 调试记录 |
| docs/24-so-pin-yubikey-unlock.md | SO-PIN 双因子解锁设计（ECDSA 版历史） |
| docs/25-yubikey-guide.md | YubiKey 选型与操作 |
| docs/26-sgx-provisioning-attestation.md | SGX 四层次方案 |
| docs/27-yubikey-provisioning-trusted-server.md | 可信服务器灌装 |
| docs/28-yubikey-full-lifecycle.md | SO 解锁闭环 + 缺口 |
| docs/29-rsa-yubikey-provisioning.md | **最终方案：RSA-2048 完整设计** |
| docs/30-ecc-p256-ta-unsupported-debug-log.md | ECDSA P-256 验签不支持调试记录（3.2 ECDSA transient panic → RSA） |
