# dongle_test — Dongle & SO-PIN Test Suite

## 概述

两个测试，覆盖 dongle 抽象层 + SO-PIN 全生命周期。

| 测试 | 类型 | 运行环境 | 内容 |
|------|:--:|------|------|
| `dongle_test` | C 单元测试 | 开发机 (host gcc) | `dongle_ops` 接口：factory/probe/open/sign/verify/pubkey/serial/attr |
| `test_so_lifecycle.sh` | Shell 集成测试 | 目标机 (QEMU/真机) | CA CLI 全生命周期：灌装→锁定→SO 解锁→重锁→错误路径 |

## dongle_test (C 单元测试)

### 测试目标

`dongle_test` 是 **REE 侧 dongle 抽象层的独立单元测试**，不依赖 TEE/TA/OP-TEE，可在开发机上直接编译运行。

测试链路仅覆盖最底层：

```
┌────────────────────────────────────┐
│  test_so_lifecycle.sh (集成测试)    │  ← 需 TEE/TA, 在 QEMU/真机跑
│  CA CLI → TA (CMD_SO_UNLOCK_REQ)   │
├────────────────────────────────────┤
│  CA CLI (keystore_client.c)        │  ← 本测试不覆盖
│  do_so_unlock() / dongle_open()    │
├────────────────────────────────────┤
│  dongle 抽象层  ← dongle_test 测这层 │  ← 本测试覆盖
│  dongle_ops.h → dongle_dummy.c     │
└────────────────────────────────────┘
```

### 覆盖的源文件

| 文件 | 覆盖内容 | 程度 |
|------|---------|:--:|
| `host/dongle/dongle_ops.h` | 接口定义：caps 宏、函数指针表、工厂函数声明 | 全部 |
| `host/dongle/dongle_factory.c` | `dongle_get()` 按名查找、`dongle_detect()` 自动检测、注册表遍历 | 全部 |
| `host/dongle/dongle_dummy.c` | `probe()` / `open()` / `close()` / `sign()` / `get_pubkey()` / `get_serial()` / `get_attr()` | 全部 |
| `host/dongle/dongle_yubikey.c` | `dongle_yubikey_get_ops()` weak symbol 注册，内部 `yk_*` 函数**未执行**（无硬件） | 仅链接 |

### 构建

```bash
cd examples/dongle_test && mkdir -p build && cd build
cmake .. && make
```

**无需交叉编译**——用 host gcc + 系统 OpenSSL 即可。CMakeLists.txt 中 OpenSSL 路径需改为系统路径或直接依赖 CMake FindOpenSSL。

### 运行

```bash
./dongle_test
```

每次运行自动在 `/tmp/tbox_dongle_test_key.pem` 生成临时 P-256 密钥，测试结束后自动删除，不遗留文件。

### 测试用例详解

| # | 用例 | 检查点 | 为什么重要 |
|:--:|------|------|------|
| 1 | **factory** | `dongle_get("dummy")` 非 NULL 且 name 正确；`dongle_get("nonexistent")` 返回 NULL；4 个 `DONGLE_CAP_*` 标志位全部置位；7 个函数指针全部非 NULL | 接口契约：调用方依赖 caps 判断能力、依赖 name 区分后端、依赖函数指针非空防止崩溃 |
| 2 | **probe_no_key** | 删除密钥文件 + 清除环境变量 → `probe()` 返回 0 | 后端能正确报告"硬件/密钥不在位"，调用方据此给出友好报错 |
| 3 | **open_close** | `probe()`=1, `open()`=0, ctx 非空, `close()` 不崩溃 | 标准生命周期，测试密钥加载和资源释放是否正确 |
| 4 | **sign** | 32 字节 digest 签名成功，DER 长度 64–72；16 字节 digest **被拒绝**（返回非 0） | 契约强制执行：ECDSA P-256 只签 SHA-256 摘要；长度错误应拒绝而非崩溃 |
| 5 | **sign_verify** | 签名 → `get_pubkey()` 拿公钥 → `ECDSA_do_verify()` 验签通过；**篡改 digest → 验签失败** | 最强测试，证明 `sign()` 输出的是对特定 digest 的有效 ECDSA 签名，不是随机数据 |
| 6 | **get_pubkey** | 公钥 DER 被 `d2i_PUBKEY()` 成功解析，`EVP_PKEY_id()==EVP_PKEY_EC` | 返回的公钥格式正确，可被 TA 侧解析和使用 |
| 7 | **serial_attr** | `get_serial()`=`0xDEAD0001`；`get_attr("name")`=`"dummy"`；`get_attr("model")` 非空；`get_attr("nonexistent")` 返回 -1 | 元数据查询接口完整，不存在属性正确报错 |
| 8 | **double_open** | `open()` 两次得到不同 ctx；`close(NULL)` 安全不崩溃 | 资源隔离：多次打开互不干扰；析构函数安全处理 NULL |
| 9 | **detect** | `dongle_detect()` 在有 dummy key 时返回非 NULL，`probe()`=1 | 自动检测链正常工作，优先级正确（YubiKey 不在时降级到 dummy） |

### 关键实现细节

**密钥生成**（`gen_key()`）：每次测试用例开头调用，通过 OpenSSL EVP API 生成新 P-256 密钥，写入 `/tmp/tbox_dongle_test_key.pem`，并通过 `setenv("TBOX_DUMMY_KEY", ...)` 让 dummy 后端找到它。每个用例独立生成，测试间互不干扰。

**签名验证**（`verify_sig()`）：使用 `ECDSA_do_verify()` 而非 `EVP_DigestVerify()`。原因是 `EVP_DigestVerify` 在 OpenSSL 1.1.x 中会对输入再做一次 SHA-256（二次 hash），导致验证值不匹配。`ECDSA_do_verify` 直接对原始 hash 验签，兼容 1.1.x 和 3.x。

**防篡改验证**（test #5）：对同一 digest 签名后，翻转 digest 中一个字节，再次验签——预期失败。这确保签名确实绑定到指定 digest，而非恒定值。

### 本测试不覆盖

- **YubiKey 真实硬件** — dummy 后端用本地文件模拟，YubiKey 的 `yk_probe()`/`yk_sign()` 等仅链接未执行
- **TA 侧 SO-PIN 逻辑** — 不测试 `CMD_SO_UNLOCK_REQ`/`CMD_SO_UNLOCK_VERIFY`、失败计数器、dongle 白名单、冷却机制
- **CA CLI SO 命令** — 不测试 `do_so_unlock()` 两阶段协议、参数解析
- **多线程/并发** — 所有测试单线程顺序执行

## test_so_lifecycle.sh (集成测试)

### 测试目标

`test_so_lifecycle.sh` 是**端到端集成测试**，覆盖从 CA CLI 到 TA 安全世界的完整链路：

```
┌─────────────────────────────────────────────┐
│  test_so_lifecycle.sh ← 本测试覆盖           │
│                                             │
│  CA CLI (tbox_keystore)                     │
│    ├── --init-so-pin      → CMD_SO_PIN_INIT      (12)
│    ├── --provision-dongle → CMD_PROVISION_DONGLE (13)
│    ├── --so-unlock        → CMD_SO_UNLOCK_REQ    (14)
│    │                      → dongle_ops.sign()         │
│    │                      → CMD_SO_UNLOCK_VERIFY (15)
│    ├── --so-lock          → CMD_SO_LOCK         (16)
│    └── --so-info          → CMD_SO_GET_INFO     (17)
│                                             │
│  TA (TEE Secure World)                      │
│    ├── so_pin_mgr.c — SO-PIN 验证 + 解锁协议  │
│    │   + 失败计数器 + dongle 白名单            │
│    ├── crypto_ops.c — ECDSA P-256 验签      │
│    ├── entry.c — 命令分发 + Gate 逻辑         │
│    └── pin_mgr.c — 写保护检查               │
└─────────────────────────────────────────────┘
```

对比 `dongle_test`（只测 REE 侧 dongle 层），本测试验证了 **TA 侧全部 SO-PIN 核心逻辑**。

### 涉及 TA 命令

| 命令 | ID | 阶段 | 测试的 TA 逻辑 |
|------|:--:|------|------|
| `CMD_PIN_INIT` | 0 | Setup | PIN 写入, `PIN_UUID` 持久化 |
| `CMD_KEY_GEN_RSA` | 1 | Setup / 解锁验证 | RSA 密钥生成, Gate PIN 检查, Gate 写保护 |
| `CMD_PROVISION_LOCK` | 10 | Phase B | `pin_mgr_lock()` → PIN_LOCKED, `LOCK_UUID` 持久化 |
| `CMD_SO_PIN_INIT` | 12 | Phase A | `so_pin_init()` → SHA-256 hash → `SO_PIN_UUID` |
| `CMD_PROVISION_DONGLE` | 13 | Phase A | `so_provision_dongle()` → SHA-256(pubkey) → `SO_DONGLE_UUID` 白名单 |
| `CMD_SO_UNLOCK_REQ` | 14 | Phase B/D | SO-PIN 验证, challenge 生成, 失败计数器检查, 冷却检查 |
| `CMD_SO_UNLOCK_VERIFY` | 15 | Phase B | 公钥白名单匹配, `SHA256(challenge\|\|dongle_index)` 构建, `crypto_ecdsa_verify()` P-256 验签, 状态 LOCKED→UNLOCKED |
| `CMD_SO_LOCK` | 16 | Phase C | `so_pin_lock()` → SO_LOCKED, `SO_LOCK_UUID` 持久化 |
| `CMD_SO_GET_INFO` | 17 | 各 Phase | `so_pin_get_info()` → 状态/失败计数/冷却时间 |

### 前提

- TEE + TA 已部署（QEMU 或真机）
- `tbox_keystore` 在 PATH（CA 可执行文件已编译并部署）
- Dummy dongle 密钥（脚本内置自动生成，无需手动执行 `make gen-dummy-key`）：
  ```bash
  # 可选手动生成：
  cd host && make gen-dummy-key
  # → 生成 /tmp/dummy-dongle-key.pem (P-256 密钥)
  ```

### 运行

```bash
cd examples/dongle_test
chmod +x test_so_lifecycle.sh
./test_so_lifecycle.sh
```

设置 `CLI` 环境变量可指定 CA 路径：`CLI=/path/to/tbox_keystore ./test_so_lifecycle.sh`

### 测试阶段详解

#### Phase A: SO 灌装（3 个检查点）

| 步骤 | CLI 命令 | 验证内容 |
|:--:|------|------|
| A1 | `--init-so-pin <SO_PIN>` | `so_pin_init()` 成功写入, SO 状态 UNSET→PROVISIONED |
| A2 | `--provision-dongle --dongle dummy` | `so_provision_dongle()` 调用 dongle→get_pubkey()→SHA-256→白名单 |
| A2b | `--provision-dongle-from-file <der>` | 从独立生成的公钥文件注册第二把 dongle，验证**多 dongle 支持** |
| A3 | `--so-info` | 状态=`PROVISIONED`, dongle 数量=`2` |

**验证点**：
- SO-PIN SHA-256 hash 正确写入 `SO_PIN_UUID` 持久化对象
- Dongle 公钥被正确 hash 并存入 `SO_DONGLE_UUID` 白名单（索引 0）
- 从文件导入的第二把 dongle 追加到白名单（索引 1），不覆盖第一把
- `CMD_SO_GET_INFO` 返回状态和 dongle 计数正确

#### Phase B: 锁定 + SO 解锁（5 个检查点）

| 步骤 | CLI 命令 | 验证内容 |
|:--:|------|------|
| B1 | `--lock` | `pin_mgr_lock()` → `CMD_PROVISION_LOCK` 成功, TA 状态 LOCKED |
| B2 | `--gen-rsa test-key` | **预期失败**——`cmd_needs_write()` + `pin_mgr_is_locked()` → `TEE_ERROR_ACCESS_DENIED` |
| B3 | `--so-unlock --so-pin <SO_PIN> --dongle dummy` | 两阶段协议完整执行: Phase 1 SO-PIN 验证 + challenge 生成, Phase 2 dongle 签名 + TA ECDSA 验签 → UNLOCKED |
| B4 | `--gen-rsa test-key --size 2048 --sign` | **预期成功**——SO UNLOCKED 状态下 Gate 2 豁免, 写操作恢复 |
| B5 | `--delete test-key` | 清理测试密钥 |

**验证点**：
- `CMD_PROVISION_LOCK` 后写保护生效（`cmd_needs_write` 被 Gate 2 拦截）
- `CMD_SO_UNLOCK_REQ` + `CMD_SO_UNLOCK_VERIFY` 完整两阶段握手
- TA 侧 `so_unlock_verify()` 内部: 公钥 hash 白名单匹配 + `crypto_ecdsa_verify()` P-256 验签通过
- SO UNLOCKED 后写操作恢复（`so_pin_is_unlocked()` 返回 1, Gate 2 放行）
- `--so-info` 确认状态=`UNLOCKED`

#### Phase C: 重新锁定（2 个检查点）

| 步骤 | CLI 命令 | 验证内容 |
|:--:|------|------|
| C1 | `--so-lock` | `so_pin_lock()` → `SO_LOCK_UUID` 持久化为 0, 状态 UNLOCKED→LOCKED |
| C2 | `--gen-rsa test-key2` | **预期失败**——重新锁定后写保护再次生效 |

**验证点**：
- `CMD_SO_LOCK` 显式锁定后 SO 状态正确回到 LOCKED
- 写保护在锁定后立即恢复（不是延迟或缓存）

#### Phase D: 错误路径（5 个检查点）

| 步骤 | CLI 命令 | 验证内容 |
|:--:|------|------|
| D1 | `--so-unlock --so-pin <WRONG_PIN>` | **预期失败**——`so_pin_hash_and_check()` 比对不匹配 → `TEE_ERROR_ACCESS_DENIED` |
| D2 | `--so-info` | `fail_consecutive=1`——失败计数器递增 |
| D3 | `--so-unlock --so-pin <WRONG_PIN>` (×2) | 连续 3 次错误后触发**冷却机制** |
| D4 | `--so-info` | 显示 "Cooldown"——`cooldown_left > 0`, 新请求被 `so_check_fail_counter()` 拦截 |
| D5 | `--so-unlock --dongle-index 99` | **预期失败**——白名单越界, `dongle_index >= dl.count` → `TEE_ERROR_ACCESS_DENIED` |

**验证点**：
- SO-PIN 错误时 `so_record_failure()` 递增计数器
- 连续 3 次失败触发 60 秒冷却 (`SO_FAIL_MAX_CONSECUTIVE=3`, `SO_FAIL_COOLDOWN_SECS=60`)
- 冷却期间 `CMD_SO_UNLOCK_REQ` 被 `so_check_fail_counter()` 拒绝, 返回 `TEE_ERROR_BAD_STATE` + 剩余秒数
- 非法 dongle index 被 `so_unlock_verify()` 拒绝（`dongle_index >= dl.count`）

#### 未测试（需手动验证）

| 场景 | 原因 |
|------|------|
| 冷却期后正确恢复 | 需等待 60 秒, 脚本默认跳过（`test_recover_after_cooldown` 已注释, 手动取消注释即可） |
| 1000 次累计失败 → SO_BRICKED | 运行时间过长, 需单独压力测试 |
| YubiKey 真实硬件解锁 | 需要物理 YubiKey + `--dongle yubikey` 标志 |
| `TA_CloseSessionEntryPoint` 自动锁定 | 本脚本未测试会话关闭行为（CA 主动调 `--so-lock`） |

### 关键实现细节

**错误中断机制**：脚本使用 `set -e`，任何 `[FAIL]` 会立即退出。这确保错误路径测试中，如果预期失败的命令反而成功，测试立即终止而非继续执行。

**check_ok / check_fail 辅助函数**：
- `check_ok` — 命令必须成功（退出码 0），否则 FAIL
- `check_fail` — 命令必须失败（退出码非 0），成功反而是 FAIL
- 两者都自动将 stdout/stderr 重定向到 `/dev/null`，保持输出整洁

**SO-PIN 恢复**（Phase D 后）：当前脚本在 Phase D 结束后直接 teardown，**不验证冷却恢复**。因为恢复需要等待 60 秒。如需验证，取消 Phase E 的注释并单独运行。

**环境隔离**：
- 所有临时文件写入 `/tmp/tbox_so_test/`，teardown 时删除
- SO-PIN 和 Provisioning PIN 使用硬编码测试值（独立于任何真实凭证）
- 第二把 dongle 的公钥用独立生成的临时密钥（不影响默认 dummy dongle）

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
