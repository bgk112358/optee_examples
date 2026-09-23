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
│   └── Makefile           # CMake 薄包装（make / make plugins / gen-dummy-key）
├── dongle/                # dongle 子系统（独立于 CA，自带 CMakeLists）
│   ├── CMakeLists.txt     # 插件构建：dummy.so / remote.so / dummy_genkey
│   ├── dongle_ops.h       # 插件 ABI 契约（CA 与插件共享）
│   ├── dongle_factory.c   # 插件加载器（**链进 CA**，本身不是插件）
│   ├── dongle_dummy.c     # 本地软狗插件（RSA-2048）
│   ├── dongle_remote.c    # 远程签名狗插件（SSH）
│   ├── dongle_yubikey.c   # **未构建**（源码保留，文件头注明原因与回归方式）
│   └── remote.conf.example
├── engine/                # OpenSSL ENGINE (e_tbox_keystore.c)
├── examples/              # 各示例（见下方「examples 目录」）
├── remote-signer/         # 远端签名服务（Python，跑在上位机/云端）— docs/32 P1
├── scripts/               # 产线灌装脚本
└── docs/                  # 设计文档（24-33：YubiKey/SGX/dongle/调试记录/部署手册）
```

## 当前实现状态

### 已完成并调试通过

1. **SO-PIN + dongle 双因子解锁**（命令 12-18）
   - 状态机：UNSET → PROVISIONED → LOCKED ↔ UNLOCKED → BRICKED
   - 失败计数器：连续 3 次错 PIN → 60s 冷却；累计 1000 次 → 永久 BRICKED
   - `test_so_lifecycle.sh` 全流程通过（灌装→锁定→SO解锁→重锁→错误路径）

2. **dongle 可插拔子系统**（`dongle/`，`docs/32` P1–P10 已完成）
   - 插件式后端：`dummy.so`（本地软狗）/ `remote.so`（远程签名狗，私钥在远端）
   - `dongle_ops` 统一 ABI 契约 + `dongle_factory.c` **运行时 dlopen 加载器**（链进 CA）
   - 密钥路径规则、插入/拔出语义、**静默覆盖告警**（见 docs/32 §6.3）
   - `dongle_test` 单元测试 9 项全通过；`remote-signer/` 自测 22 项全通过

3. **关键架构决策**：OP-TEE 3.2 不支持 ECDSA transient object
   （`TEE_AllocateTransientObject(TEE_TYPE_ECDSA_*)` 直接 TA panic，见 docs/30），因此：
   - 密钥类型统一改 **RSA-2048**（TA 原生支持）
   - ✅ **`CMD_SO_UNLOCK_CONFIRM`(18) 已改带 `pubkey+sig`**，TA 在 `so_unlock_confirm()` 内
     **原子完成** RSA 验签 ∧ 白名单匹配 —— **docs/28 描述的安全缺口已闭合**
   - 白名单公钥上限 `SO_DONGLE_PUBKEY_MAX` 已放宽 256→512（RSA 公钥 294B 才装得下）

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
| CMD_SO_UNLOCK_CONFIRM | 18 | 解锁确认（**已改为带 pubkey+sig，TA 内原子验签+白名单**） |
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
- doc 29 的**核心已实施**（RSA-2048 / TA 内原子验签 / `rsa_import_pubkey_from_der`）；
  仅"批量 manifest 灌装"部分未做（见「未完成事项」）

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

1. **doc 29 方案剩余部分**（核心已实施，见上方"已完成"第 3 条）：
   - ✅ 已完成：`CMD_SO_UNLOCK_CONFIRM`(18) 带参、`rsa_import_pubkey_from_der()`、
     RSA 验签+白名单原子操作、公钥上限放宽
   - ❌ 仍未实施：`CMD_PROVISION_DONGLE_MANIFEST`(19) 批量 manifest 灌装
     （目前是逐台 `--provision-dongle-from-file`）+ `--provision-dongle-manifest` 命令
     + 可信服务器脚本 gen-manifest.sh / sign-manifest.sh

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
- **CMakeLists 三个**：顶层 `optee_examples_AG519M/CMakeLists.txt`（含 teec include/lib 路径）、`tbox_keystore/CMakeLists.txt`（CA，`add_subdirectory(dongle)`）、`dongle/CMakeLists.txt`（插件，可独立配置）
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
| docs/31-key-management-and-secure-services.md | 口语化说明：密钥管理（含 dongle）+ HTTPS/MQTTS 安全能力来源 |
| docs/33-deployment-guide.md | **部署手册（交付部署工程师）** |
| docs/34-cloud-device-provisioning-lifecycle.md | **云端 ↔ 车端逻辑关系**（灌装 / 售后两条线的时序与状态机） |
| docs/32-dongle-plugin-architecture.md | **Dongle 可插拔设计（本地软狗 + 远程 SSH 签名狗，RSA-2048，TA 内验签）— 未实施** |
