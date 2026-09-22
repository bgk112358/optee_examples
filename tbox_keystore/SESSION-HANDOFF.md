# 会话交接摘要

> **来源**：原会话 `d89c7047-e38c-4f24-95e0-ab85542a62d4`（2026-08-11 → 2026-09-22，4581 行 / 8.9 MB）
> **终止原因**：超出模型 1M token 上下文上限（`API Error 400 … requested 1056572 tokens`，2026-09-22T02:33:39Z）
> **本摘要重建自**：原始 session 记录 + 仓库实测状态（非推测）
> **生成时间**：2026-09-22

---

## 目标

**TBox 安全服务系统** —— 用 ARM TrustZone + OP-TEE 替代离散 HSM 安全芯片，为 TBox 的 HTTPS / MQTTS 提供密钥管理与密码学运算。核心链路：

```
OpenSSL ENGINE (REE) → CA → TEEC/SMC → TA (Secure World)
```

**原会话最后一项任务**：把 `tbox_keystore/engine` 并入 `optee_examples_AG519M` 顶层 cmake 构建，并统一 ENGINE 库名。

---

## 约束

| 约束 | 说明 |
|------|------|
| **OP-TEE 3.2 无 ECDSA** | `TEE_AllocateTransientObject(TEE_TYPE_ECDSA_*)` 直接 TA panic → 密钥统一 RSA-2048 |
| **改 C 代码禁用 `sed`** | 本项目多次因 sed 插行破坏 if/else 块。用 Read + Edit/Write |
| **新增 TA 源文件** | 必须登记到 `ta/sub.mk` |
| **ASCII 图** | 生成 HTML 时必须 `white-space: pre` 不折行，否则框线错位 |
| **交叉编译 OpenSSL** | 一律用显式路径 `three_part/openssl/out`，**不要用 `find_package(OpenSSL)`**（会找到宿主 x86_64 版本） |
| **例外** | `examples/dongle_test` 故意用宿主 OpenSSL —— 它在开发机上跑，无 TEE 依赖 |

---

## 已确认结论（用户明确拍板）

| # | 决策 | 确认时间 |
|:-:|------|---------|
| 1 | **ENGINE 库名统一为 `libengkeystore.so`**（改文档 + 示例，非改回旧名） | 09-22 02:26 |
| 2 | **示例自包含（方案乙）**：每个示例 `add_subdirectory(../../engine engine_build)`，单独 `cmake && make` 即可 | 09-22 02:26 |
| 3 | **mqtts 也用 `libengkeystore.so`** | 09-22 02:26 |
| 4 | **dongle 插件目录保留现状**：只用 `TBOX_DONGLE_DIR`，**不接** `LD_LIBRARY_PATH` | 09-22 01:42 |
| 5 | doc 33 HTML：A4 / 紧凑排版 / 去掉逐章分页 | 09-22 01:14 |
| 6 | doc 33 标题去掉「（从零开始）」，MD 与 HTML 同步 | 09-22 01:50 |
| 7 | **`--dongle <name>` 改为按文件名直接加载**：打开 `<TBOX_DONGLE_DIR>/<name>.so`，**不遍历目录**；配套 `.key` 仍从 `TBOX_DONGLE_DIR` 找；**不接受路径**；自动探测仍扫描 | 09-22 |
| 8 | 本次文档同步范围：**核心 + 冲突项**（次级文档不逐行改） | 09-22 |

> 决策 4 的原因：加载器按 `<目录>/<名字>.so` **完整路径 `dlopen`**（含 `/` 时 dlopen 不查库搜索路径），故 `LD_LIBRARY_PATH` 对"加载哪个插件"不生效；且刻意不接是为了避免扫描 `/usr/lib` 等大目录（慢、刷屏、攻击面扩大）。`LD_LIBRARY_PATH` 仍影响**插件自身的依赖**（如 `libssl.so.1.1`）。
>
> 决策 7 **修订**了决策 4 的背景：既然按名加载不再扫描目录，"扫目录"这条理由只对**自动探测**成立，但结论不变——**仍然不接 `LD_LIBRARY_PATH`**，仍只用 `TBOX_DONGLE_DIR`。决策 4 的结论继续有效。

---

## 关键数据 / 代码 / 配置

### 路径

| 用途 | 路径 |
|------|------|
| 工作空间根 | `/home/test0923/workspace/OP-TEE/` |
| 项目根 | `optee_examples_AG519M/tbox_keystore/` |
| 交叉 OpenSSL | `/home/test0923/workspace/OP-TEE/three_part/openssl/out`（1.1.1b） |
| TEE Client | `optee400/optee_client/export-ca_arm64/{include,lib}` |
| aarch64 编译器 | `optee400/toolchains/aarch64/bin/aarch64-none-linux-gnu-gcc` |
| TA dev kit | `optee400/optee_os/out/arm/export-ta_arm64` |

### 命名（本次统一后）

| 项 | 值 |
|---|---|
| CMake 目标名 | `engkeystore` |
| 产物库名 | `libengkeystore.so` |
| 源码文件名 | `e_tbox_keystore.c` ← **不改** |
| 导出符号 | `ENGINE_load_tbox_keystore` |
| 部署路径 | `/usr/lib/engines-1.1/` |
| TA UUID | `f8e9209a-3c7d-4d6b-a15e-7f328b11c049` |

### 构建命令

```bash
# 项目级（顶层 cmake 自动 glob 子目录）
cd optee_examples_AG519M/build
cmake -DCMAKE_C_COMPILER=<aarch64 gcc> .. && make

# 单个示例（自包含）
cd tbox_keystore/examples/<name>/build
cmake -DCMAKE_C_COMPILER=<aarch64 gcc> .. && make
```

> ⚠️ 示例仍需手传 `-DCMAKE_C_COMPILER=`（示例目录没有 toolchain 文件）。这是已知不便，未改。

---

## 待办与未解决

### 🔴 阻塞项

**1. mqtts 的 paho 库需重编**
- 现象：`ld: cannot find -leng-paho-mqtt3cs`
- 原因：mqtts 链接 `eng-paho-mqtt3cs` / `eng-paho-mqtt3c`（为 ENGINE 打过补丁的名字），但 `three_part/mqtt/out/lib/` 里装的仍是 **07-23 构建的 `libpaho-mqtt3c[s].so`**
- 影响：`mqtts_pub` / `mqtts_sub` / `tcpprobe_mqtt` 链接失败（`gen_csr` 不受影响）
- **与 engine 集成无关**，是更早记账的待办

### 🟡 待决策

**2. 历史文档里的旧库名残留**（10 处，均在历史/参考类文档）
- `docs/15-engine-debug-issues.md`（4 处）、`docs/20-mqtts-debug-issues.md`（1 处）—— 原会话已判定**不改**（历史调试记录）
- `docs/13-openssl-engine-integration.md`（4 处）、`docs/19-hsm-chip-reference-architecture.md`（1 处）—— **未分类，待你决定**
- 注：`docs/21`、`docs/31`（现状文档）已改完

### 🟢 长期待办（原会话已有记录）

| # | 事项 |
|:-:|------|
| 3 | `examples/aes`、`examples/rsa` **待设备实测**（编译已过） |
| 4 | doc 29 剩余部分：`CMD_PROVISION_DONGLE_MANIFEST`(19) 批量 manifest 灌装 + `gen-manifest.sh` / `sign-manifest.sh` |
| 5 | VMware 环境 YubiKey 直通问题（`ykman piv info` 报 "No YubiKey Detected"） |
| 6 | `dongle_yubikey.c` 未构建（源码保留，文件头注明原因） |

---

## 本次接续所做的验证与修复

### 验证结果

| 项 | 结果 |
|---|---|
| 项目级构建 | ✅ `engkeystore` 目标编出，aarch64 ELF，`NEEDED libssl.so.1.1 / libcrypto.so.1.1` |
| 3 个示例**裸 cmake** 全新构建 | ✅ `https_client` / `tls_mutual_auth` / `engine_test` 全部通过 |
| 产物依赖 | ✅ 三者 `NEEDED libengkeystore.so` |
| 符号导出 | ✅ `ENGINE_load_tbox_keystore` |
| mqtts | ⚠️ 引擎部分 ✅（`engkeystore` + `ssl_config` 编出），卡在 paho |

### 修复的缺陷（原会话遗漏）

**示例的 `find_package(OpenSSL 1.1 REQUIRED)` 在交叉构建下必挂。**

原会话为 `engine/CMakeLists.txt` 修掉了这个 bug，但 4 个示例仍保留 `find_package` —— 裸 cmake 会找到**宿主 x86_64 的 OpenSSL 3.0.2**，编译即失败（`fatal error: openssl/ssl.h: No such file or directory`）。

已改为显式交叉路径（与 `engine`、`examples/rsa` 统一）：

```cmake
set(OPENSSL_DIR "/home/test0923/workspace/OP-TEE/three_part/openssl/out"
    CACHE PATH "cross-built OpenSSL (libssl/libcrypto)")
# …
target_include_directories(<t> PRIVATE ${OPENSSL_DIR}/include)
target_link_directories(<t> PRIVATE ${OPENSSL_DIR}/lib)
target_link_libraries(<t> ssl crypto engkeystore)
```

改动文件：`examples/{https_client,tls_mutual_auth,engine_test,mqtts}/CMakeLists.txt`

### 文档修复

- `docs/21`、`docs/31`：`e_tbox_keystore.so` → `libengkeystore.so`（含 ASCII 框图内，**逐行校验显示宽度**保证框线不错位）
- 顺带修正 `docs/21:50`、`docs/31:22` 两处**原本就存在**的框线差一列问题

### 设备实测反馈修复：`0xffff0001` 提示（2026-09-22 追加）

**现象**：在真实设备 `ag519mab` 上 `--so-info` 显示 `SO State: LOCKED`，执行
`keystore --gen-rsa test-key --size 2048` 返回 `KEY_GEN_RSA failed: 0xffff0001`。

**结论：不是 bug，是设计如此。** `ta/entry.c` 的 Gate 2 写保护门：

```c
if (cmd_needs_write(cmd_id) && pin_mgr_is_locked() && !so_pin_is_unlocked()) {
	EMSG("TA is locked, write operation denied");
	return TEE_ERROR_ACCESS_DENIED;      /* = 0xffff0001 */
}
```

写保护名单（`cmd_needs_write`）：`KEY_GEN_RSA` / `KEY_GEN_AES` / `KEY_DELETE` /
`PIN_INIT` / `SO_PIN_INIT` / `PROVISION_DONGLE`。
`SO_UNLOCK_REQ`/`CONFIRM` **故意豁免**（否则锁死无法解锁）。
解法：先 `--so-unlock --so-pin <hex> --dongle <name>`（有时限，完事 `--so-lock`）。

**已修复的缺陷**：`ACCESS_DENIED` 有两个来源（Gate 2 写保护 / Gate 1 PIN 未灌装），
host 侧却只抛裸错误码。已新增 `die_if_write_denied()` 辅助函数
（`host/keystore_client.c`），在 **7 个调用点**覆盖全部 6 条写命令：

```
TA denied the write: locked (run --so-unlock) or no PIN provisioned (run --init-pin); see --so-info
```

> 已核实 `acl_check` 只用于 SIGN/VERIFY/ENCRYPT/DECRYPT，**不是**这 6 条命令的
> `ACCESS_DENIED` 来源，故提示不会误报。`do_so_unlock()` 保持独立处理（那里
> `ACCESS_DENIED` 意为 bricked / 签名不在白名单）。

**文档同步**：`docs/33` 排查表该行原先只写 TA 侧 `EMSG` 文本
（`TA is locked, write operation denied`）——那是**安全世界日志**，运维在终端上看不到。
已补上 host 侧可见现象（含旧版裸 `0xffff0001`）与两条分支处置。MD 与生成的 HTML 均已更新
（HTML 标签配对校验通过；生成脚本已丢失，本次为等价手工补丁）。

---

## 最近上下文

原会话终止前的最后动作：改文档残留时撞上 1M 上限。用户随后要求压缩上下文，连续两次请求均因同样的超限报错失败 —— **摘要从未生成**。

本摘要 + 上方代码修复即为该任务的补做。

---

## 变更记录：`--dongle` 改为按文件名加载（2026-09-22 追加）

**改动**：`--dongle <name>` 从"扫描目录下所有 `*.so` 再按插件自报的 `ops->name` 匹配"
改为**直接打开 `$TBOX_DONGLE_DIR/<name>.so`**。自动探测（不带 `--dongle`）仍扫描。

**核心文件**：`dongle/dongle_factory.c`（注册表加 `path` 去重键、`load_plugin` 改返回
`ops*`、新增 `valid_backend_name`/`find_by_path`/`find_by_name`/`hint_available`、
`dongle_get` 重写为**路径优先→名字兜底**）、`dongle/dongle_ops.h`（注释 + ABI 说明）、
`host/keystore_client.c`（帮助文本）、`examples/dongle_test/`（新增名字校验断言 + README）。

**两个必须记住的设计点**：

1. **`valid_backend_name()` 是安全边界**，不只是格式校验。名字会被拼进
   `<dir>/<name>.so`：允许 `/` 就能跳出插件目录（`../evil`），而且会让同一文件拿到
   **第二种路径拼写**，使路径去重失效、把同一个插件加载两次。
2. **`g_loaded` 已改名 `g_scanned`** —— 它只表示"目录扫描跑过"，**不是**"插件已加载"。
   按名加载不会置位它，所以 `dongle_detect()` 之后仍会扫描（这是对的）。
   误把它当"已加载"标志会破坏去重。

**验收断言**（`examples/dongle_test/`）：
```bash
./dongle_test 2>&1 | grep -c "loaded plugin: dummy"   # 期望 1
```
用例 1 先按名加载、用例 9 后扫描，同一文件不得加载两次。

**ABI 未变**（`DONGLE_PLUGIN_ABI_VERSION` 仍为 1），已部署的 `.so` 无需重编。

**文档漂移（已知，未处理）**：
- `docs/31`、`docs/27`、`dongle/remote.conf.example`、`examples/*/README` 等**次级文档**
  仍描述"扫描插件目录"，本次按决策 8 未逐行修改
- `docs/32` 的 §3 架构图（约第 101-115 行）有**5 处既有的 CJK 宽度错位**
  （行 105/109/110/112/113，HEAD 里就存在，非本次引入）——本次只保证了改动的第 106 行对齐

---

## 后续新会话如何接续

1. 读本文件 + `optee_examples_AG519M/CLAUDE.md`（项目主上下文）
2. 若要动 mqtts → 先解决待办 #1（重编 paho）
3. 若要改历史文档库名 → 先确认待办 #2
4. 原始完整记录仍在：
   `~/.claude/projects/-home-test0923-workspace-OP-TEE/d89c7047-e38c-4f24-95e0-ab85542a62d4.jsonl`
   （可用脚本按时间戳抽取任意片段，无需重新推理）
