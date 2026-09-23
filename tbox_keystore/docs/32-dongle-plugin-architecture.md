# 32 — Dongle 可插拔设计（本地软狗 + 远程签名狗）

> **一句话**：把 dongle 后端从"编译期静态链接"改成"运行期插件"，并支持两种形态——
> **本地软狗**（`.so` + 本地 `.key`，开发/CI）与 **远程签名狗**（`.so` 在设备、**私钥在远端**，通过 SSH 请求签名，生产/现场）。
>
> **状态**：设计/实施方案。**P1–P10 全部完成**（远端签名服务、TA 内验签、CA 配合、
> 插件框架、本地软狗插件化、远程签名狗插件、白名单/限频/审计、构建收敛、
> 云端 transport 接口预留、文档同步）。
> 代码见 [remote-signer/](../remote-signer/)、`ta/`（§8）、`dongle/`。
> 唯一未实现的是 **云端 transport 本体**（接口与配置已就位，见 §7.4 / P9）。
>
> ✅ **两种 dongle 形态均可用了**：本地软狗（`dummy.so` + `<dir>/dummy.key`）
> 与远程签名狗（`remote.so` + SSH 到上位机/云端，含每设备身份、白名单、限频、审计）。
>
> ✅ **P8 已清掉全部"迁移中破损"**（见下方修订，此前记账的三项均已修复）：
> - `examples/dongle_test/` → 改为经**插件加载器**驱动，RSA-2048 断言，**9/9 通过**
> - `dongle_yubikey.c` → 不再编入构建，源码保留并在文件头注明**为何不可用**及**如何作为插件回归**
> - `host/Makefile` → 收敛为 **CMake 薄包装**（原 `CC ?=` 失效、缺交叉 OpenSSL 路径两个 bug 一并消除）
>
> **分支策略**：**以 QEMU 分支为准**（本工作区即 QEMU 分支）。先在 QEMU 验证通过，再移植到真机分支。
>
> **修订记录**：初版仅含本地软狗（P-256）。本版按确认结论修订为：
> ① 增加远程 SSH 签名形态；② 密钥类型统一改 **RSA-2048**；③ 验签改在 **TA 内**完成（闭合 doc 28 的安全缺口）；④ 新增审计日志；
> ⑤ 补充 **§8.6 尺寸限制**——现有代码按 ECDSA 尺寸写死，RSA-2048 公钥**灌不进白名单**。

---

## 1. 背景与现状

### 1.1 现有 dongle 抽象层

```
dongle/
├── dongle_ops.h        # 统一接口（虚表）
├── dongle_factory.c    # 静态注册表 + 弱符号 + detect/get
├── dongle_dummy.c      # 软狗：本地 RSA-2048 密钥文件
└── dongle_yubikey.c    # 真狗：YubiKey（ykman CLI / libykpiv）
```

```c
struct dongle_ops {
	const char *name;       /* "yubikey" | "dummy"        */
	uint32_t    caps;       /* DONGLE_CAP_*               */
	int  (*probe)(void);                                  /* 硬件在不在 */
	int  (*open)(struct dongle_ctx **ctx);
	void (*close)(struct dongle_ctx *ctx);
	int  (*sign)(...);      /* 对 32B SHA-256 摘要签名     */
	int  (*get_pubkey)(...);
	int  (*get_serial)(...);
	int  (*get_attr)(...);
};
```

### 1.2 不够"可插拔"的三个点

| 问题 | 现状 | 后果 |
|------|------|------|
| **后端是编译期定的** | `host/Makefile` 的 `DONGLE_BACKENDS ?= dongle_dummy` 条件编入 `.o` | 换后端要**重新编译** CA |
| **注册表是静态的** | `dongle_factory.c` 写死 `{"yubikey",...},{"dummy",...}` + 弱符号 | 只能支持**编译进来**的那几种 |
| **"设备"与"身份"没分离** | dummy 的 `probe()` 已是"密钥文件存在即插入"，但这是后端内部实现 | 语义散落，不成为框架能力 |

### 1.3 两种软狗形态

| | 本地软狗 | **远程签名狗** |
|---|---|---|
| 私钥位置 | **设备上**（PEM 文件） | **远端**（上位机 / 云端） |
| root 被拿下 | 拷走 `.key` → **可无限伪造、对所有设备有效** | 拿不到私钥，只能"借用"**这一台**的签名能力 |
| 设备被克隆 | 克隆体天然拥有狗 | 克隆体需另行认证 |
| 依赖 | 无 | 解锁时需网络可达 |
| 适用 | 开发 / CI / 离线测试 | **生产 / 现场售后** |

> 远程形态把"软狗最大的弱点（私钥在设备上）"解决了，是本次设计的核心价值。

---

## 2. 目标与非目标

### 2.1 目标

1. **运行期加载**：按名加载 `<插件目录>/<name>.so`（**只开这一个文件**）；只有自动探测时才扫描目录。增减后端无需重编译
2. **两种形态共存**：本地软狗（开发）与远程签名狗（生产）都是**插件**，同一套 ABI
3. **"插入"语义统一**：各形态有明确的"在/不在"判定（见 §6.1、§7.2）
4. **密钥类型统一为 RSA-2048**，并让 **TA 在安全世界内完成验签**，闭合 doc 28 的安全缺口
5. **每设备独立身份 + 远端策略 + 审计日志**
6. **选择方式**：`--dongle <name>` 直接加载 `<插件目录>/<name>.so`（**不接受路径**，见 §6.2）；无参时扫描目录自动探测

### 2.2 非目标（本期明确不做）

| 不做 | 说明 |
|------|------|
| **运行中热插拔** | 进程内插件表只增不减；运行中放入/移除需重启 |
| **插件签名校验** | 已确认开发期不设防（生产落地方式见 §10.2） |
| **云端 transport 实现** | 本期**只留接口**，先跑通上位机（Ubuntu + Python） |
| **改 challenge 格式** | 设备身份由**传输层**（每设备 SSH 身份）提供，无需改 TA 的 challenge |

---

## 3. 总体架构

```
┌────────────────────────── TBox 设备 ──────────────────────────┐
│  optee_example_tbox_keystore (CA)                             │
│      │  dongle_detect() / dongle_get("<name>")                │
│      ▼                                                        │
│  dongle_factory.c（插件加载器）                                │
│      │  按名 dlopen / 扫描 dlopen + ABI 校验                  │
│      ├───────────────┬────────────────────┐                   │
│      ▼               ▼                    ▼                   │
│  dummy.so        remote.so           (其他插件)                │
│  （本地软狗）     （远程签名狗）                                │
│      │               │                                        │
│      │ 读本地        │ 用【本设备专属 SSH 身份】                 │
│      │ dummy.key     │ 请求远端签名                            │
│      │               ▼                                        │
│      │           ssh client                                   │
│      │               │                                        │
│      │               ▼  SSH（传输加密 + 主机密钥强校验）        │
│      │        ┌──────────────────────────────┐                │
│      │        │ 远端签名服务（Ubuntu + Python）│                │
│      │        │  tbox-dongle-sign             │                │
│      │        │   ① 认证调用方（SSH 公钥指纹） │                │
│      │        │   ② 策略：白名单/限频/审计     │                │
│      │        │   ③ RSA-2048 签名（私钥只在此）│                │
│      │        │   ④ 审计日志（文本）           │                │
│      │        └──────────────────────────────┘                │
│      │               │                                        │
│      └───────┬───────┘                                        │
│              ▼ 返回 {pubkey_der, sig}                          │
│              │                                                │
└──────────────┼────────────────────────────────────────────────┘
               ▼  CA 把 pubkey + sig 交给 TA
   ┌──────────────────────────────────────────────┐
   │  TA（**需改造**，见 §8）                       │
   │    CMD_SO_UNLOCK_CONFIRM(18) 加 pubkey+sig     │
   │    原子完成：RSA 验签 ∧ 白名单匹配 → UNLOCKED   │
   └──────────────────────────────────────────────┘
```

**关键**：`dongle_detect()` / `dongle_get()` 的签名与行为保持不变 →
[keystore_client.c:496](../../host/keystore_client.c#L496) 那行不用改。

---

## 4. 密钥类型决策：RSA-2048

### 4.1 为什么不用 ECDSA P-256

| | ECDSA P-256 | **RSA-2048** |
|---|---|---|
| TA 内能否验签 | ❌ OP-TEE 3.2 不支持 ECDSA transient object，调用即 **panic**（[docs/30](30-ecc-p256-ta-unsupported-debug-log.md)） | ✅ **`crypto_rsa_verify()` 已实现**（[crypto_ops.c:48](../../ta/crypto_ops.c#L48)，`TEE_ALG_RSASSA_PKCS1_V1_5_SHA256`） |
| 验签在哪做 | 只能挪到 **CA 侧**（REE，不可信） | **TA 内**（安全世界） |
| 安全后果 | `CMD_SO_UNLOCK_CONFIRM` 无参数、**不验签不查白名单** → 已知缺口（[docs/28](28-yubikey-full-lifecycle.md)） | 缺口**闭合** |

**结论**：RSA-2048 让我们能把验签放回安全世界，这正是 [docs/29](29-rsa-yubikey-provisioning.md) 选择 RSA 的原因。本方案直接复用 doc 29 的 TA 设计。

> ### ⚠️ 常见误解澄清："TA 不是已经用 RSA-2048 了吗？"
>
> **对，但指的是另一条路径。** TA 现有的 RSA-2048 能力服务于**业务密钥**
> （`CMD_KEY_GEN_RSA` / `CMD_SIGN` / `CMD_VERIFY`，即 HTTPS/MQTTS 用的那批密钥）；
> 而 **dongle 验签路径上，TA 目前什么都不验**：
>
> | 事实 | 证据 |
> |---|---|
> | `crypto_rsa_verify()` 唯一调用点在**业务路径** | [ta/entry.c:243](../../ta/entry.c#L243)，位于 `cmd_verify()`（`CMD_VERIFY`=6） |
> | dongle 解锁确认**不接收任何参数** | `cmd_so_unlock_confirm()` 的 `exp_pt` 是 **4 个 `TEE_PARAM_TYPE_NONE`** |
> | TA 只是**信任 CA 已验过** | `so_unlock_confirm()` 日志原文：`"SO unlock confirmed (CA verified ECDSA)"` |
> | 验签实际发生在**不可信的 CA 侧** | [host/keystore_client.c:737](../../host/keystore_client.c#L737) `ECDSA_do_verify()` |
> | `CMD_SO_UNLOCK_VERIFY`(15) **从未实现** | 头文件有定义，但 [ta/entry.c](../../ta/entry.c) 中**没有任何 `case`** |
>
> 所以：**"TA 支持 RSA-2048" ≠ "TA 在 dongle 路径验签"**。后者是本次改造**新增**的能力。

### 4.2 尺寸影响（接口与缓冲区要跟着改）

| 项 | 原（P-256） | 现（RSA-2048） |
|---|---|---|
| 签名长度 | 64–72 B（DER） | **256 B** |
| 公钥 DER | ~91 B | **~294 B** |
| 白名单条目 | `SHA-256(pubkey DER)`，32 B | **不变** ✅（与密钥类型无关） |
| 摘要 | SHA-256，32 B | **不变** ✅ |

> 白名单格式不用动，是这次选型的一个便利点。

---

## 5. 插件 ABI 契约

容器放在 `dongle/dongle_ops.h`。

### 5.1 ABI 版本号

```c
/*
 * 插件 ABI 版本。任何对 struct dongle_ops 布局/语义的破坏性改动都必须递增；
 * 主程序拒绝加载版本不匹配的插件。
 */
#define DONGLE_PLUGIN_ABI_VERSION   1
```

### 5.2 插件必须导出的符号

```c
/* 必需 */
const struct dongle_ops *dongle_plugin_get_ops(void);
uint32_t dongle_plugin_abi_version(void);

/*
 * 可选：加载器把"插件目录"告知插件（便于本地软狗解析配套 .key）。
 * 无论插件是按名加载还是扫描加载，收到的始终是**插件目录**，不是 .so 路径。
 * 改这个契约（或新增语义不同的符号）需要 bump DONGLE_PLUGIN_ABI_VERSION。
 */
void dongle_plugin_set_dir(const char *dir);
```

### 5.3 `struct dongle_ops` 的改动

```c
struct dongle_ops {
	const char *name;       /* 自报标识；--dongle <name> 对应 <name>.so */
	uint32_t    caps;       /* DONGLE_CAP_*                        */
	uint32_t    priority;   /* 新增：探测优先级，大者先试，0 为默认  */
	const char *key_type;   /* 新增："RSA-2048"（供日志/诊断）       */
	int  (*probe)(void);
	...（其余回调不变，但 sign 的语义见 5.4）
};
```

排序：**priority 降序 → 同 priority 按插件自报的 `ops->name` 升序**（结果确定，不依赖 `readdir` 顺序）。

### 5.4 `sign()` 的语义（密钥类型改 RSA 后）

```c
/*
 * sign — 对 32 字节 SHA-256 摘要做 RSA-2048 PKCS#1 v1.5 签名。
 * digest  : 32B SHA-256（注意：不是原始报文）
 * sig_der : 输出缓冲，至少 256 字节；实际写入 256 字节
 * 返回 0 成功，负值失败。
 */
int (*sign)(struct dongle_ctx *ctx,
	    const uint8_t *digest, size_t digest_len,
	    uint8_t *sig_der, size_t *sig_len);
```

### 5.5 为什么必须有版本守卫

`.so` 与主程序独立编译、可各自升级。若 `struct dongle_ops` 增删字段而插件未重编，
主程序会按新布局读旧插件的内存 → **函数指针错位 → 崩溃**。
版本不匹配时**拒绝加载并告警**是唯一安全做法。

---

## 6. 本地软狗（开发 / CI）

### 6.1 「插入」判定

| `.so` | `.key` | `probe()` | 判定 |
|:---:|:---:|:---:|------|
| ✗ | ✗ | — | 没插 |
| ✗ | ✓ | — | **无效**：只有密钥没驱动 → 忽略 |
| ✓ | ✗ | 0 | **驱动在、狗不在** → 未插入 |
| ✓ | ✓ | 1 | ✅ **已插入** |

> **加载插件 ≠ 设备插入**：由 `probe()` 给最终判定。

### 6.2 目录布局与插件解析规则

```
/oemdata/opt/optee/dongle/
├── dummy.so            # 软狗驱动
├── dummy.key           # 软狗"狗内私钥"（PEM，RSA-2048）
└── remote.so           # 远程签名狗驱动（无 .key，见 §7）
```

**命名约定 —— 这就是 `--dongle` 的解析规则**：`--dongle <name>` **直接加载
`<插件目录>/<name>.so`**，不再扫描目录。所以 `.so` 的文件名**必须**是
`<name>.so`；配套密钥 `<name>.key` 同名、放同一目录。

| 写法 | 行为 |
|------|------|
| `--dongle dummy` | 打开 `<插件目录>/dummy.so` —— **只开这一个文件** |
| `--dongle dummy.so` | ❌ 后缀由加载器自己加 → 实际会去找 `dummy.so.so` |
| `--dongle /opt/x.so` | ❌ **不接受路径**（理由见下） |
| （不带 `--dongle`） | 扫描目录下全部 `*.so`，按 `priority` 排序后逐个 `probe()` |

**为什么不接受路径**：`<name>` 会被拼进 `<目录>/<name>.so`。若允许 `/`，就能跳出
插件目录（`../../tmp/evil`）；而且同一个文件会获得**第二种路径拼写**，使加载器的
路径去重失效、把同一个插件加载两次（两份独立的插件静态状态）。因此 `<name>` 被
限制为**纯文件名**：只允许 `[A-Za-z0-9._-]`、不以 `.` 开头、长度 ≤64。

> ✅ **按名加载只 `dlopen` 那一个文件**——目录里的其他 `.so` 完全不会被碰。
> 这既省掉了遍历开销，也意味着目录里放了一个无关的坏 `.so` 时，
> 按名加载不会再受它干扰。

**目录是可配的**：`/oemdata/opt/optee/dongle` 只是编译期默认值，运行时用
**`TBOX_DONGLE_DIR`** 覆盖（单个目录，不支持冒号分隔）。它同时决定 `.so`
和配套 `.key`/`remote.conf` 的位置。

> ⚠️ **不要试图用 `LD_LIBRARY_PATH`**：插件由加载器按 `<目录>/<名字>.so`
> 的**完整路径 `dlopen`** 打开（含 `/` 时 `dlopen` 不查库搜索路径），
> 因此该变量对"加载哪个插件"**不生效**。
>
> 之所以不接 `LD_LIBRARY_PATH`：自动探测要**扫描目录内所有 `*.so` 逐个加载**，
> 而库搜索路径里通常是 `/usr/lib`、`/lib` 这类大目录——接上去会尝试加载
> 几百个无关系统库（慢、刷屏），且让**通用库路径**决定"由谁持有狗私钥签名"，
> 攻击面明显扩大。插件目录与库搜索路径分开是设计意图。
>
> （`LD_LIBRARY_PATH` 仍然作用于**插件自身的依赖**，如 `dummy.so` 需要
> `libssl.so.1.1`/`libcrypto.so.1.1`——那部分由动态链接器解析。）

> ℹ️ **对已部署的插件透明**：本次改动只换了加载器的**查找算法**，
> `struct dongle_ops` 与所有回调签名都没动，`DONGLE_PLUGIN_ABI_VERSION` 保持 `1`。
> 已部署的 `dummy.so` / `remote.so` **不需要重编**。

### 6.3 密钥路径解析顺序（首个匹配生效）

1. 环境变量 `TBOX_DONGLE_KEY_DUMMY` — 逐插件显式覆盖（多狗并存用）
2. **`<插件目录>/dummy.key`** — 仅当该文件**确实存在**时
3. `$TBOX_DUMMY_KEY` — 旧行为（开发机 / CI 仍在用）
4. `/tmp/dummy-dongle-key.pem` — 旧默认值

> ⚠️ 第 2 步**带存在性判断**是刻意的：加载器总会把插件目录告知插件，
> 若第 2 步无条件生效，所有把密钥放在 `/tmp` 或用环境变量指定的既有脚本
> 都会失效。加了存在性判断后，两种用法可共存（已实测，见 §12.1 用例 9-10）。

> ⚠️ **想换一把狗？必须用 `$TBOX_DONGLE_KEY_DUMMY`**（第 1 条），
> 不能用 `$TBOX_DUMMY_KEY`（第 3 条，会被目录里的 key 覆盖）。
> 为避免误用，当 `$TBOX_DUMMY_KEY` 被设置但未生效时，插件会打印：
>
> ```
> [dummy] warning: $TBOX_DUMMY_KEY=/tmp/other.key is IGNORED — using <dir>/dummy.key
>         (the plugin-directory key takes precedence; set $TBOX_DONGLE_KEY_DUMMY to override)
> ```
>
> 这条警告是必需的：否则"用未授权的狗做缺口验证"会**静默**改用已授权的那把，
> 从而得出相反的错误结论（已实际踩到）。

### 6.4 dummy 改造点

| # | 改动 |
|:--:|------|
| 1 | 密钥类型 **P-256 → RSA-2048**（`dummy_sign` 改用 `EVP_PKEY_sign` / `RSA_sign`，签名 256B） |
| 2 | `key_path()` 按 §6.3 顺序解析 |
| 3 | 新增 3 个导出符号（§5.2）；原 `dongle_dummy_get_ops()` 改为内部函数 |
| 4 | `dummy_ops.priority = 10`、`key_type = "RSA-2048"` |
| 5 | `GENKEY_MAIN` 生成工具改为产 **RSA-2048** 密钥；CMake 目标名 **`dummy_genkey`** |

> **目标端密钥生成**：QEMU / 真机上**没有 `openssl` 命令行**，但 CA 本身已依赖
> `libcrypto`，所以 `dummy_genkey` 只链接库、不 shell out。用法：
> `dummy_genkey [/path/to/dummy-dongle-key.pem]`（默认 `$TBOX_DUMMY_KEY` 或
> `/tmp/dummy-dongle-key.pem`）。开发机上的 `make gen-dummy-key` 仍走 openssl CLI。

### 6.5 ⚠️ UNLOCKED 不会自动过期（已知缺口，建议修复）

`--so-unlock` 成功后的 UNLOCKED 状态**不会自行失效**。`TA_CloseSessionEntryPoint`
的注释写得很明确：

```
UNLOCKED state persists across sessions until:
  - explicit CMD_SO_LOCK (--so-lock)
  - 5-minute idle timeout (NOT YET IMPLEMENTED)   ← 未实现
  - TA restart
  - 1000 SO-PIN failures
```

**后果**：维护完若忘记 `--so-lock`，**写保护会一直关着**。

- QEMU 环境（存储为内存盘，`QEMU_PSS_AUTOMOUNT=n`）重启即重置
- **真机存储是持久的** → `so_pin_restore()` 会把 UNLOCKED 恢复回来
  → **写保护跨重启持续关闭**

**注意**：`--lock`（provision 写保护）与 SO 状态是**两套独立的锁**。
`--lock` 不改变 SO 状态；且写操作门禁是
`pin_mgr_is_locked() && !so_pin_is_unlocked()` ——
**LOCKED + UNLOCKED 的组合本来就是"允许写入"**（SO 解锁的意义正在于此）。
所以看到 `--lock` 之后 `--so-info` 仍显示 UNLOCKED **不是 bug**。

**建议**（未实施）：补上原设计里的空闲自动锁（5 分钟或可配置），
至少在 `--so-info` 输出里加一条醒目提示。

---

## 7. 远程签名狗（生产 / 现场）

### 7.1 形态：拉模式（TBox 主动连远端）

TBox 侧只有**驱动** `remote.so`；**私钥在远端**，解锁时 TBox 主动 SSH 过去请求签名。

### 7.2 「插入」判定

| `remote.so` | 远端可达 **且** 本设备被授权 | 判定 |
|:---:|:---:|------|
| ✗ | — | 未插入 |
| ✓ | ✗ | **驱动在、狗不在** → 未插入 |
| ✓ | ✓ | ✅ **已插入** |

`probe()` = 一次轻量 SSH 探测（`BatchMode` + `ConnectTimeout`）。
⚠️ 这是**网络操作**，必须有短超时：**默认 2000 ms**（可配置）。
否则 `dongle_detect()` 遍历插件时会拖慢每次启动。

### 7.3 远端协议（hex 文本，便于调试）

TBox → 远端（通过 SSH 执行一条命令）：

```
tbox-dongle-sign ping                       → OK
tbox-dongle-sign getpub                     → hex(DER pubkey)        # RSA-2048, ~294B
tbox-dongle-sign sign <hex 32B digest>      → hex(DER sig)           # 256B
tbox-dongle-sign info                       → key=value（model/serial/version）
tbox-dongle-sign audit [--tail N] [--device <id>]   → 审计日志查询（见 §7.7）
```

- 退出码：0 成功；非 0 为分类错误码
- 同一条 SSH 连接用 **ControlMaster 复用**，避免 `probe`/`getpub`/`sign` 三次握手

### 7.4 传输抽象（PC 与云端统一）

`remote.so` 内部做一层传输抽象，上层 `sign`/`getpub` 语义一致：

```
remote.so
   └── transport 抽象
         ├── transport_ssh        ← 上位机 PC（ssh 子进程）  【本期实现】
         └── transport_http_mtls  ← 云端（双向 TLS）          【本期只留接口】
```

配置决定用哪个；云端实现时**不动上层逻辑**。

### 7.5 每设备独立身份（防签名预言机）

- 每台 TBox 有**自己的** SSH 密钥对（`/etc/tbox/dongle/id_ed25519`），公钥登记到远端
- 远端据此知道"**是哪台设备在请求签名**"，可做：**设备白名单 / 频次限制 / 审计**
- ✅ **无需改 TA**（设备身份由传输层提供，不动 challenge 格式）

**为什么必须这样**：TA 的 challenge 是纯随机 32 字节（`TEE_GenerateRandom`），**不含设备标识**。
若所有设备共用凭据、远端来者不拒地签，则一台被攻陷的 TBox 能替**所有设备**签名。
每设备身份把爆炸半径限制在**单台设备**。

### 7.6 配置

完整样例见 [dongle/remote.conf.example](../../dongle/remote.conf.example)，
部署到 `/etc/tbox/dongle/remote.conf`。

查找顺序：`$TBOX_REMOTE_DONGLE_CONF` → `<插件目录>/remote.conf` → 上述默认路径。

```
transport   = ssh                     # ssh（已实现） | http_mtls（预留）
host        = signer.example.com
user        = tbox-device
port        = 22
key         = /etc/tbox/dongle/id_ed25519   # 本设备专属 SSH 身份（§7.5）
known_hosts = /etc/tbox/dongle/known_hosts  # 必须预置（强制校验主机密钥）
ssh_bin     = ssh                     # 嵌入式常为 dropbear 的 dbclient
timeout_ms  = 2000
remote_cmd  =                         # **留空**：强制命令模式下只发子命令（见下）

# --- 云端（预留，P9）：字段**会被解析**，但传输层未实现 ---
# transport   = http_mtls
# endpoint    = https://ca.example.com/v1/dongle
# client_cert = /etc/tbox/dongle/device.crt
# client_key  = /etc/tbox/dongle/device.key
```

环境变量可覆盖任一键（便于开发/CI）：`TBOX_REMOTE_DONGLE_<KEY>`，例如
`TBOX_REMOTE_DONGLE_HOST` / `TBOX_REMOTE_DONGLE_TIMEOUT_MS` / `TBOX_REMOTE_DONGLE_ENDPOINT`。

> **P9 的"预留"具体指什么**：`http_mtls` 的 vtable 槽位与全部配置键**都已就位**；
> 选它会**明确报错**（`RESERVED, not implemented yet`）而**不会静默成功**——
> 配置错的设备绝不能看起来像"没插狗"。实现云端只需填
> `transport_http_mtls_call()` 一个函数，调用方无需改动。

> ⚠️ **`remote_cmd` 必须留空（推荐部署下）**：配合 §7.7 的 sshd 强制命令
> （`command="... serve --device X"`），sshd 执行服务、客户端敲的整串作为
> `$SSH_ORIGINAL_COMMAND` 传进去——所以插件只能发**子命令**本身。
> 填了前缀（如 `tbox-dongle-sign`）会被 `serve()` 当成子命令名，
> 报 `未知子命令`。仅"普通 shell 账号"部署才需要填完整命令。

### 7.7 远端服务（Ubuntu + Python）

**实现**：Python + `cryptography` 库，提供 `tbox-dongle-sign` 命令。

```
/opt/tbox-dongle-sign/
├── tbox_dongle_sign.py     # 主程序（ping/getpub/sign/info/audit）
├── devices.json            # 设备白名单：SSH 指纹 → 设备ID/策略
├── keys/
│   └── dongle.pem          # RSA-2048 私钥（**只存在这里**，权限 0400）
└── /var/log/tbox-dongle/audit.jsonl   # 审计日志
```

**SSH 侧加固**（每设备一条 `authorized_keys`）：

```
command="/opt/tbox-dongle-sign/tbox-dongle-sign serve",no-port-forwarding,no-pty,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA... device-001
```

- `command=` 强制只能执行签名服务；子命令由 `SSH_ORIGINAL_COMMAND` 传入
- 每行一条 = 一台设备；**撤销设备 = 删这一行**

**签名实现要点**：对 32 字节 SHA-256 摘要做 RSA PKCS#1 v1.5 签名，等价于

```python
priv.sign(challenge, padding.PKCS1v15(), hashes.SHA256())     # 内部做 SHA-256
# 或显式：priv.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
```

与 TA 的 `TEE_ALG_RSASSA_PKCS1_V1_5_SHA256` + `TEE_AsymmetricVerifyDigest(hash)` **一一对应**。

### 7.8 审计日志

**格式**：JSON Lines（一行一条，便于 `grep`/`jq`/导入）

```json
{"ts":"2026-09-15T10:23:41.123Z","device":"device-001","fp":"SHA256:ab12...","action":"sign","digest":"3f2a...","result":"ok","ms":12,"src":"10.0.0.5"}
{"ts":"2026-09-15T10:25:02.004Z","device":"device-002","fp":"SHA256:cd34...","action":"sign","digest":"9e1b...","result":"denied","reason":"device not in allowlist","src":"10.0.0.9"}
```

**记录字段**：时间戳、设备 ID、SSH 指纹、操作、摘要、结果、耗时、来源 IP。

**查看入口**（"审计日志界面"）：本期给**只读查询**，两种任选：

| 方式 | 说明 |
|---|---|
| CLI 报表 | `tbox-dongle-sign audit --tail 50` / `--device device-001 --since 1d`，格式化表格输出 |
| 简易 Web | 一个只读页面（读同一份 jsonl），支持按设备/时间过滤 |

> 具体做哪种（或都要）见 §13 待确认。

### 7.9 与 doc 29（YubiKey 方案）的关系

两者**不冲突**，而是**同一目标下"私钥承载方式"的两种选择**：

| | [doc 29](29-rsa-yubikey-provisioning.md)（YubiKey） | 本文 §7（远端签名服务） |
|---|---|---|
| 私钥承载 | YubiKey 硬件（PIV Slot 9a） | 远端服务的密钥文件——**也可以是 YubiKey 或 HSM** |
| 谁发起 | CA 操作**插在设备上**的 YubiKey | CA 通过 SSH 请求**远端**签名 |
| 设备需插硬件 | 是 | **否** |
| 依赖网络 | 否 | 是 |
| **TA 侧验签** | **完全相同**（RSA-2048 验签 + 白名单原子匹配） | **完全相同** |

**关键点**：§8 的 TA 改造对两者**完全通用**——TA 只认"公钥 + 签名 + 白名单"，
**不关心私钥在哪里**。所以：

- ✅ **最推荐的组合**：远端签名服务的私钥**就用 YubiKey/HSM 承载**（服务端插狗）
  → 私钥永远在硬件里，**且不在设备上**，安全性最高
- doc 29 描述的是"YubiKey 插在**设备**上"的形态；本文 §7 描述的是"YubiKey/密钥在**远端**"的形态
- 两者共用同一套 TA 改造（§8），**先做哪个都不影响另一个**
- 本文 §5 的插件框架恰好让这两种形态可以**并存**（`yubikey.so` 与 `remote.so` 各是一个插件）

---

## 8. TA 侧改造（闭合安全缺口）

> 本节内容与 [docs/29 §7.3](29-rsa-yubikey-provisioning.md) 一致，直接复用那份设计。

### 8.1 现状缺口（doc 28）

```c
/* ta/so_pin_mgr.c 现状 */
void so_unlock_confirm(void)
{
	so_reset_consecutive();
	g_so_state = SO_STATE_UNLOCKED;      /* ← 不验签名、不查白名单 */
	DMSG("SO unlock confirmed (CA verified ECDSA), TA UNLOCKED");
}
```
只检查 `CMD_SO_UNLOCK_REQ` 成功过。CA 在不可信的 REE，**替换 CA 即可跳过 dongle**。

### 8.2 改造后

**`CMD_SO_UNLOCK_CONFIRM`(18) 加参数**：

```c
/* param[0] (memref) dongle 公钥 DER（RSA-2048, ~294B） */
/* param[1] (memref) RSA PKCS#1 v1.5 签名（256B）        */
```

**`ta/so_pin_mgr.c` 中原子完成两步**：

```c
TEE_Result so_unlock_confirm(const uint8_t *pubkey_der, size_t der_len,
                             const uint8_t *sig, size_t sig_len)
{
	/* ① 公钥 DER → TEE_ObjectHandle（新增函数） */
	res = rsa_import_pubkey_from_der(pubkey_der, der_len, &rsa_key);

	/* ② SHA-256(challenge) */
	res = so_sha256(g_so_challenge, 32, chg_hash, 32);

	/* ③ RSA 验签（证明持有 dongle 私钥） */
	res = crypto_rsa_verify(rsa_key, 2048, chg_hash, 32, sig, sig_len);

	/* ④ SHA-256(pubkey_der) → 白名单匹配（证明 dog 已授权） */
	so_sha256(pubkey_der, der_len, pk_hash, 32);
	for (i = 0; i < dl.count; i++)
		if (memcmp(pk_hash, dl.entries[i].pubkey_hash, 32) == 0)
			goto unlocked;          /* ③ ∧ ④ 全过才解锁 */

	so_record_failure();
	return TEE_ERROR_ACCESS_DENIED;

unlocked:
	so_reset_consecutive();
	g_so_state = SO_STATE_UNLOCKED;
	return TEE_SUCCESS;
}
```

**关键**：③ 与 ④ 在**同一个函数、同一段代码**内不可分割地完成 → **CA 无法在中间篡改**。这是闭合缺口的核心。

### 8.3 新增 TA 函数

| 函数 | 位置 | 说明 |
|---|---|---|
| `rsa_import_pubkey_from_der()` | `ta/crypto_ops.c` | DER → `TEE_AllocateTransientObject` + `TEE_PopulateTransientObject`（`TEE_ATTR_RSA_MODULUS` / `TEE_ATTR_RSA_PUBLIC_EXPONENT`） |
| `so_sha256()` | `ta/so_pin_mgr.c` | SHA-256 封装（若尚未有） |

### 8.4 白名单灌装

现有 `CMD_PROVISION_DONGLE`(13) 已能登记单只 dongle 的公钥哈希，**格式不用改**（哈希与密钥类型无关）。
[docs/29](29-rsa-yubikey-provisioning.md) 规划的批量 `CMD_PROVISION_DONGLE_MANIFEST`(19)（可信服务器签名的 manifest 批量灌装）**本期可选**，不在必需路径上。

### 8.5 CA 侧配合

`host/keystore_client.c` 的 `do_so_unlock()`：
- 从 dongle 取 `pubkey_der`（`get_pubkey()`）与 `sig`（`sign(challenge)`）
- 一并传给 `CMD_SO_UNLOCK_CONFIRM`
- **CA 不再需要自己做 ECDSA 验签**（原来那步 OpenSSL 验签可移除，或保留作预检查）

### 8.6 ⚠️ 必须一并修的尺寸限制（否则 RSA-2048 连白名单都灌不进去）

现有代码把 dongle 公钥长度**按 ECDSA 尺寸写死成 256 字节**。
RSA-2048 公钥 DER ≈ **294 字节**、签名 **256 字节**，会在以下三处直接失败：

| 位置 | 现状 | 问题 |
|------|------|------|
| [ta/so_pin_mgr.c](../../ta/so_pin_mgr.c) `so_provision_dongle()` | `if (der_len < 88 \|\| der_len > 256) return TEE_ERROR_BAD_PARAMETERS;` | **294 > 256 → TA 直接拒绝登记白名单** |
| [host/keystore_client.c](../../host/keystore_client.c) `do_provision_dongle()` | `uint8_t pubkey_der[256];` | CA 缓冲区**装不下** 294B |
| [host/keystore_client.c](../../host/keystore_client.c) `do_so_unlock()` | `uint8_t pubkey_der[256];`<br>`uint8_t sig_der[128];` | 公钥装不下；**签名也装不下**（256B > 128B） |

**修法**：

| 项 | 现值 | 改为 |
|---|---|---|
| 公钥缓冲区 / TA 上限 | 256 B | **512 B**（留余量） |
| 签名缓冲区 | 128 B | **512 B**（与 engine 的 `local_sig[512]` 一致） |

> 备注：若要支持 **RSA-4096**（公钥 DER ~550B），上述 512 仍不够，需另议（当前 TA 的
> `CMD_KEY_GEN_RSA` 也只支持到 4096，本方案按 2048 收敛）。

---

## 9. 影响面清单（文件级）

| 文件 | 改动 | 类别 |
|------|------|:--:|
| `dongle/dongle_ops.h` | +ABI 版本、+入口符号声明、`struct dongle_ops` +`priority`/`key_type`、`sign()` 语义改 RSA | 框架 |
| `dongle/dongle_factory.c` | **重写**：静态注册表 → `dlopen` 加载器（公开 API 不变） | 框架 |
| `dongle/dongle_dummy.c` | RSA-2048 + 导出符号 + 密钥路径 | 本地软狗 |
| `dongle/dongle_remote.c` | **新增**：远程签名狗插件 + transport 抽象 | 远程狗 |
| `dongle/dongle_yubikey.c` | **从构建移除**（源码保留，可后续做成插件回归） | 清理 |
| `host/keystore_client.c` | `do_so_unlock()` 改为传 pubkey+sig；**缓冲区 256→512**（公钥/签名，见 §8.6）；include 改 `"dongle_ops.h"`（走 `-I`） | CA |
| `host/Makefile` | **收敛为 CMake 薄包装**（`make` / `make plugins` / `gen-dummy-key`）——不再自带编译规则，消除"两套构建定义" | 构建 |
| **`dongle/CMakeLists.txt`** | **新增**：编 `dummy.so` / `remote.so` / `dummy_genkey`；可独立配置，也被父工程 `add_subdirectory` | 构建 |
| `tbox_keystore/CMakeLists.txt` | `add_subdirectory(dongle)`；CA 仍链接 `dongle/dongle_factory.c`（加载器） | 构建 |
| `ta/include/tbox_keystore_ta.h` | `CMD_SO_UNLOCK_CONFIRM`(18) 参数说明更新 | TA |
| `ta/so_pin_mgr.c` | `so_unlock_confirm()` 改为原子验签+白名单；**`so_provision_dongle()` 公钥长度上限 256→512**（见 §8.6） | TA |
| `ta/crypto_ops.c` | +`rsa_import_pubkey_from_der()` | TA |
| `ta/entry.c` | `cmd_so_unlock_confirm` 传递参数 | TA |
| `examples/dongle_test/dongle_test.c` | 适配插件加载 + RSA；+插入/拔出用例 | 测试 |
| `examples/dongle_test/CMakeLists.txt` | 不再静态编后端；+`-ldl` | 测试 |
| `examples/dongle_test/README.md` | 补充"先安装插件"步骤 | 文档 |
| **远端** `tbox-dongle-sign`（新仓库/目录） | Python 服务 + 设备白名单 + 审计日志 | 远端 |
| `docs/24-so-pin-yubikey-unlock.md` | 涉及 dongle 加载方式与验签位置的段落 | 文档 |

### 目录重组：dongle 层从 `host/` 提出来（方案 A）

改造完成后 `host/dongle/` 被整体上提为 `tbox_keystore/dongle/`：

```
tbox_keystore/
├── host/          # 只剩 CA：keystore_client.c + Makefile
└── dongle/        # dongle 子系统（自带 CMakeLists，可独立构建）
    ├── dongle_ops.h        # 插件 ABI 契约 —— CA 与插件**共享**
    ├── dongle_factory.c    # 插件加载器 —— **链进 CA**（不是插件）
    ├── dongle_dummy.c      # 插件：本地软狗
    ├── dongle_remote.c     # 插件：远程签名狗
    └── dongle_yubikey.c    # 未构建
```

**一句话说明边界**：`dongle/` 里除 `dongle_factory.c` 外都是**独立 `.so`**，
对 CA 零依赖；`dongle_factory.c` 逻辑上属于这一层，但必须被**链进 CA**——
因为要由 CA 来 `dlopen` 插件。CA 与插件之间唯一的耦合面就是 `dongle_ops.h`。

> 产物位置（CMake `add_subdirectory` 的常态）：
> CA 在 `build/tbox_keystore/keystore`，插件与 `dummy_genkey` 在
> `build/tbox_keystore/dongle/`。目标名不变，`make dummy_plugin` 等照旧可用。

### ⚠️ 原"容易踩的坑"的最终处置

计划里曾担心 `host/Makefile` 的 `ifeq (dummy)` 分支删掉后 CA 会缺 OpenSSL。
最终没有采用"打补丁"的方式，而是**把 Makefile 收敛成 CMake 薄包装**——
根因是当时存在**两套构建定义**（Makefile 与 CMake 各写一份），
它同时导致了两个 bug：`CC ?=` 对 make 内建变量无效（总是用宿主 `cc`，
接着链 aarch64 libteec 失败）、以及从未指向交叉 OpenSSL。
现在构建定义只剩 CMake 一处，这两个问题连同"依赖提升"的顾虑一起消失。

---

## 10. 安全分析

### 10.1 威胁与对策

| # | 威胁 | 对策 |
|:--:|------|------|
| 1 | **MITM 伪造成远端** | SSH **主机密钥强校验**：预置 `known_hosts`，**禁止** `StrictHostKeyChecking=no` |
| 2 | **签名预言机** | **每设备独立 SSH 身份** + 远端白名单/限频/审计 |
| 3 | **重放** | TA 每次 `TEE_GenerateRandom` 出新 challenge → 天然防重放 ✅ |
| 4 | **TBox 凭据泄露** | 仅对**这一台设备身份**有效，远端可**即时吊销**（删 `authorized_keys` 一行） |
| 5 | **CA 被替换绕过 dongle** | **TA 内原子验签+白名单**（§8）→ 闭合 doc 28 缺口 ✅ |
| 6 | **网络不可达** | 解锁失败（可用性问题，非安全问题）。**绝不回退到本地软狗**——否则等于给攻击者留后门 |
| 7 | **本地软狗 .key 被拷走**（开发形态） | 仅用于开发/CI；生产用远程形态规避 |

### 10.2 生产落地建议（插件加载面）

`dlopen` 任意 `.so` = 任意代码执行。生产环境建议：

1. **设备上不安装**非必需插件（只留 `remote.so`）
2. 或用编译开关把加载器整体编掉（`CFG_DONGLE_PLUGIN=0`）
3. 更严格：加载前校验 `.so` 签名/哈希白名单（**本期不实现**，§12 预留 hook）

✅ **按名加载收窄了这一面**：`--dongle <name>` 只 `dlopen` 那一个文件，
目录里其他 `.so` 不会被加载。旧行为是"扫描目录、逐个 dlopen"，
一个无关的坏 `.so` 也会被执行到——按名加载不受其影响。

⚠️ 但 `<name>` **必须**是纯文件名：允许路径就等于允许 `../../tmp/evil`，
同时会让同一文件拿到第二种路径拼写、破坏加载器的路径去重（见 §6.2）。

> 注意 §10.1#5 的价值：**即使 CA 被替换，也绕不过 TA 的验签+白名单**。
> 这使插件加载面的风险**显著低于**改造前。

---

## 11. 实施阶段

| 阶段 | 内容 | 可独立验证 |
|:--:|------|:--:|
| **P1** ✅ | 远端协议 + `tbox-dongle-sign`（Python，先在 Ubuntu 上手工跑通 ping/getpub/sign） | `ssh host tbox-dongle-sign sign <hex>` |
| **P2** ✅ | TA 改造：`CMD_SO_UNLOCK_CONFIRM` 加参数 + `rsa_import_pubkey_from_der()` + 原子验签；**`so_provision_dongle()` 公钥上限 256→512**（§8.6） | TA 编译 + 单测 |
| **P3** ✅ | CA 配合：`do_so_unlock()` 传 pubkey+sig；**缓冲区 256→512**（§8.6）；本地软狗转 RSA-2048 | `--so-unlock` 成功 |
| **P4** ✅ | 插件框架：`dongle_ops.h` ABI + `dongle_factory.c` 重写为加载器 | 空目录 → `detect()==NULL` |
| **P5** ✅ | 本地软狗插件化（RSA + 导出符号 + `.so`）；密钥路径规则 §6.3 | 插入/拔出用例 |
| **P6** ✅ | 远程签名狗插件（`remote.so` + transport_ssh + 配置 + probe 超时） | 远端可达/不可达用例 |
| **P7** ✅ | 每设备 SSH 身份 + 远端白名单/限频 + 审计日志（含查看入口） | 审计日志可查 |
| **P8** ✅ | 构建改造、移除 yubikey 静态路径、`dongle_test` 适配 | `make` + 测试全绿 |
| **P9** ✅ | 云端 transport 接口预留（`transport_http_mtls` 桩 + 配置项**已解析** + 明确报错） | 编译通过 + 诊断准确 |
| **P10** ✅ | 文档与脚本同步（含 `remote.conf.example`、各 README、本文件状态） | 人工复核 |

---

## 12. 测试与验收

### 12.1 插件与插入语义

| # | 场景 | 期望 |
|:--:|------|------|
| 1 | 插件目录为空 | `dongle_detect()` → NULL |
| 2 | 只有 `dummy.so`，无 `dummy.key` | 加载成功但 `probe()==0` → **未插入** |
| 3 | 只有 `dummy.key`，无 `.so` | 未插入 |
| 4 | `dummy.so` + `dummy.key` | ✅ 插入；`sign()` 返回 256B 签名 |
| 5 | 删除 `.key` 后重启 | 回到场景 2（**拔出**） |
| 6 | `--dongle dummy` | 打开 `<插件目录>/dummy.so` —— **只 `dlopen` 这一个文件** |
| 7 | ABI 版本不匹配的 `.so` | **拒绝加载并告警**（按名加载时该后端即不可用） |
| 8 | 非 dongle 的普通 `.so` | 缺入口符号被忽略，不崩溃 |
| 9 | 目录无 `.key`，但设了 `$TBOX_DUMMY_KEY` | 旧路径仍生效（向后兼容） |
| 10 | 目录有 `.key` **且**设了 `$TBOX_DUMMY_KEY` | **目录内 `.key` 优先**（§6.3 顺序） |
| 11 | `--dongle dummy.so`（带后缀） | ❌ 失败——找的是 `dummy.so.so`；报错提示**去掉 `.so` 后缀** |
| 12 | `--dongle ../x` / `--dongle /abs/x.so` / `--dongle a/b` | ❌ **被拒**（名字必须是纯文件名，见 §6.2） |
| 13 | `--dongle nonexistent` | 失败信息含**请求的完整路径** + 目录里已装的 `*.so` 列表 |
| 14 | 目录里有无关的坏 `.so`，按名加载 | **不受影响**——该文件根本不会被 `dlopen` |
| 15 | 先 `dongle_get("dummy")` 再 `dongle_detect()` | 同一文件**只加载一次**（路径去重）；`loaded plugin: dummy` 只出现一次 |

> 用例 1–10 已在宿主端到端实测通过（P4 / P5 验证，含"插入→拔出→再插入"）。
> 用例 11–15 为**按名加载**本次新增，由 `examples/dongle_test/` 覆盖
> （用例 1 的名字校验断言 + 用例 9 的去重依赖）。

### 12.2 远程签名狗

| # | 场景 | 期望 |
|:--:|------|------|
| 16 | 远端可达且设备已授权 | `probe()==1`；`sign()` 成功 |
| 17 | 远端不可达（拔网线/关服务） | `probe()==0`（**2s 内返回**，不卡死） |
| 18 | 设备未登记（公钥不在 `authorized_keys`） | SSH 拒绝 → 视为未插入 |
| 19 | 远端策略拒绝（不在 `devices.json`） | 返回 denied，**审计日志有记录** |
| 20 | 篡改 `known_hosts` 模拟 MITM | **连接被拒绝**（主机密钥校验失败） |
| 21 | 网络中途断开 | 报错清晰，**不回退到本地软狗** |

### 12.3 端到端验收

```bash
# 二进制名随 CMake 项目名（当前为 keystore；若改回则填 optee_example_tbox_keystore）
CLI=./keystore

# ========== 0. "插入"本地软狗：驱动 + 密钥放入插件目录 ==========
DGN=/oemdata/opt/optee/dongle                  # 默认插件目录（可用 $TBOX_DONGLE_DIR 覆盖）
mkdir -p "$DGN"
cp dummy.so "$DGN/"                       # 驱动（CMake 目标 dummy_plugin 的产物）
dummy_genkey "$DGN/dummy.key"             # "狗内私钥"（目标机无 openssl CLI，用本工具）

# ========== 1. 首次灌装（必须在 --lock 之前完成）==========
# ⚠️ SO-PIN 必须先 --init-so-pin 灌装（只能一次），--so-unlock 才能用
# ⚠️ --provision-dongle 必须在 --lock 之前（锁后写操作被禁，除非已 SO 解锁）
$CLI --init-pin 31323334                 # 普通 PIN
$CLI --init-so-pin <SO-PIN hex>          # SO-PIN（一次）
$CLI --provision-dongle --dongle dummy   # 登记白名单
$CLI --lock                              # 出厂锁定

# ========== 2. 售后解锁（本地软狗 / 开发）==========
$CLI --so-unlock --so-pin <同一 SO-PIN hex> --dongle dummy
$CLI --so-lock                           # 维护完再锁回

# ========== 3. 模拟拔出 ==========
mv "$DGN/dummy.key" /tmp/            # 拿走密钥 → 下次启动探测不到
# mv "$DGN/dummy.so"  /tmp/          # 拿走驱动 → dlopen 失败并给出明确报错

# ========== 远程签名狗（生产）==========
# Ubuntu 侧：tbox-dongle-sign serve（由 ssh command= 强制调用，见 §7.7）
export TBOX_DONGLE_DIR=/oemdata/opt/optee/dongle
ssh tbox-signer@<host> getpub | tr -d '\n' | xxd -r -p > dongle-pub.der
./optee_example_tbox_keystore --provision-dongle-from-file dongle-pub.der
./optee_example_tbox_keystore --so-unlock --so-pin <hex> --dongle remote

# Ubuntu 侧查看审计
tbox-dongle-sign audit --tail 20
```

### 12.4 缺口闭合验证（重要）

**原理**：改造后 TA 必须**自己**验签 + 查白名单。拿一把**未登记**的狗去解锁必须被拒；
改造前 `so_unlock_confirm()` 是空壳，**任何狗都能解锁**。

> ⚠️ **关键前提**：要指定"另一把狗"，必须用优先级**最高**的 `$TBOX_DONGLE_KEY_DUMMY`。
> 用 `$TBOX_DUMMY_KEY` 会被插件目录里的 `dummy.key` 覆盖（§6.3），
> 那样实际测到的是**已授权**的那把狗，会得出**相反的错误结论**（已实测踩过）。

```bash
CLI=./keystore        # 二进制名随 CMake 项目名

# ---- 前置：全新设备 ----
$CLI --init-pin 31323334
$CLI --init-so-pin 31323334
$CLI --provision-dongle --dongle dummy     # 登记插件目录里那把狗
$CLI --lock

# ---- ① 用"未登记"的狗解锁 → 必须被拒 ----
dummy_genkey /tmp/other.key
TBOX_DONGLE_KEY_DUMMY=/tmp/other.key \
    $CLI --so-unlock --so-pin 31323334 --dongle dummy
#   预期：TA rejected unlock: bad signature, or dongle not in TA whitelist

# ---- ② 换回已登记的那把 → 应成功 ----
$CLI --so-unlock --so-pin 31323334 --dongle dummy
#   预期：✓ SO unlock successful
$CLI --so-lock                              # 收尾：锁回（见 §6.5 注意）

# ---- 等价做法：把插件目录里的 key 临时挪走，$TBOX_DUMMY_KEY 即生效 ----
```

**判据**：① 被拒（缺口闭合），② 成功（正常路径不受影响）。

### 12.5 RSA-2048 尺寸回归（验证 §8.6 的修复）

| # | 场景 | 期望 |
|:--:|------|------|
| 17 | 用 **RSA-2048 公钥（~294B）** 执行 `--provision-dongle` | **登记成功**（修复前会因 `der_len > 256` 被 TA 拒绝） |
| 18 | `do_so_unlock()` 取公钥（294B）与签名（256B） | **无缓冲区溢出**，验签通过（修复前 `pubkey_der[256]` / `sig_der[128]` 装不下） |

---

## 13. 待确认 / 后续

| # | 事项 | 说明 |
|:--:|------|------|
| 1 | **审计"界面"形态** | CLI 报表 / 简易 Web / 两者都要？（本期先做只读查询） |
| 2 | **插件目录最终路径** | 暂定 `/oemdata/opt/optee/dongle/`。**已定**：`--dongle <name>` 解析为 `<该目录>/<name>.so`，**不接受路径**（§6.2） |
| 3 | **本地软狗旧密钥路径是否保留兜底** | §6.3 第 3 条 |
| 4 | **`CMD_PROVISION_DONGLE_MANIFEST`(19)** | doc 29 的批量白名单灌装，是否本期一并做？（当前用 `CMD_PROVISION_DONGLE`(13) 逐个登记已够） |
| 5 | **yubikey 是否以插件形式回归** | `dongle_yubikey.c` 源码保留，将来可做成 `yubikey.so`（框架天然支持） |
| 6 | **P-256 支持是否彻底移除** | 本次统一 RSA-2048；若将来支持 P-256，需等 OP-TEE 升级（3.2 无法在 TA 内验签） |

---

## 相关文档

- [24-so-pin-yubikey-unlock.md](24-so-pin-yubikey-unlock.md) — SO-PIN + dongle 双因子解锁设计
- [28-yubikey-full-lifecycle.md](28-yubikey-full-lifecycle.md) — SO 解锁闭环与**安全缺口分析**（本方案要闭合的正是它）
- [29-rsa-yubikey-provisioning.md](29-rsa-yubikey-provisioning.md) — **RSA-2048 + TA 内原子验签**的完整设计（§8 直接复用）
- [30-ecc-p256-ta-unsupported-debug-log.md](30-ecc-p256-ta-unsupported-debug-log.md) — 为什么 ECDSA 不能在 TA 内验签
- [31-key-management-and-secure-services.md](31-key-management-and-secure-services.md) — 钥匙管理与安全能力总述（dongle 角色）
- [dongle/dongle_ops.h](../../dongle/dongle_ops.h) — 当前接口定义
- [examples/dongle_test/README.md](../../examples/dongle_test/README.md) — dongle 单元测试说明
