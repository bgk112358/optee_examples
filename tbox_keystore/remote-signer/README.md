# remote-signer — TBox 远端签名服务（远程签名狗）

> **状态**：**P1 已实现**（协议 + 签名服务 + 自测）。设备侧插件（`remote.so`）见
> [docs/32-dongle-plugin-architecture.md](../docs/32-dongle-plugin-architecture.md) §7，属后续阶段。
>
> 运行环境：**上位机 Ubuntu**（或云端）。**私钥只存在这里，永不下发到设备。**

## 概述

TBox 设备在售后解锁时需要"持有 dongle"的证明。本服务把这把私钥**移出设备**，
放在上位机/云端：设备通过 SSH 发来摘要，本服务用 RSA-2048 私钥签名后返回。

```
TBox 设备                                   上位机（本服务）
  CA                                          tbox-dongle-sign
   │  challenge ──SHA256──▶ digest               │
   │                                             │
   │  ── SSH: sign <digest> ─────────────────────▶ 用 dongle.pem 签名
   │  ◀────────────────── hex(签名 256B) ─────────│
   │                                             │
   ▼ 把「公钥 + 签名」交给 TA
  TA: RSA 验签 ∧ 白名单匹配 → UNLOCKED
```

**安全意义**：设备被 root、被克隆，都拿不到私钥——只能"借用"这一台设备的签名能力，
且上位机可随时吊销（删 `authorized_keys` 一行）。

## 文件

| 文件 | 说明 |
|------|------|
| `tbox-dongle-sign` | 主程序（Python 3，可执行） |
| `selftest.py` | 自测（22 项，覆盖签名格式/参数校验/serve 模式） |
| `devices.json.example` | 设备白名单 / 策略样例（拷贝为 `devices.json`） |
| `README.md` | 本文档 |

## 依赖

```bash
sudo apt install python3 python3-cryptography
```

> 开发机验证：Python 3.10.12 + cryptography 3.4.8 通过。

## 部署

### 1. 安装到 `/opt`

```bash
sudo mkdir -p /opt/tbox-dongle-sign
sudo cp tbox-dongle-sign /opt/tbox-dongle-sign/
sudo chmod 755 /opt/tbox-dongle-sign/tbox-dongle-sign
```

### 2. 生成私钥（管理员本地执行，**不经 SSH**）

```bash
sudo /opt/tbox-dongle-sign/tbox-dongle-sign genkey
# → /opt/tbox-dongle-sign/keys/dongle.pem  (RSA-2048, 0600)
#   并打印公钥 SHA-256
```

目录默认布局：

```
/opt/tbox-dongle-sign/
├── tbox-dongle-sign
└── keys/
    └── dongle.pem        # RSA-2048 私钥，0600，永不外传
```

> 可用环境变量覆盖路径（便于开发/测试）：
> `TBOX_DONGLE_SIGN_HOME` / `TBOX_DONGLE_SIGN_KEY` / `TBOX_DONGLE_SIGN_DEVICES`

### 3. 配置 SSH 强制命令（每台设备一行）

在签名服务账号（如 `tbox-signer`）的 `~/.ssh/authorized_keys` 中：

```
command="/opt/tbox-dongle-sign/tbox-dongle-sign serve --device device-001",no-port-forwarding,no-pty,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA...设备1公钥... device-001
```

> ⚠️ **身份必须写进 `command=` 里**（`serve --device <id>`）。
> 行尾的 `device-001` 是 authorized_keys 的**注释字段，不会传给程序**——
> 只写注释的话服务认不出是哪台设备。

- `command=` 强制只能执行本服务，**设备拿不到 shell**
- 每台设备一行 → **设备身份由 SSH 公钥提供**
- **吊销设备 = 删除该行**（或把 `devices.json` 里对应条目的 `enabled` 置 false）

### 3b. 设备白名单 / 限频 / 审计（P7）

```bash
sudo cp devices.json.example /opt/tbox-dongle-sign/devices.json
sudo chmod 600 /opt/tbox-dongle-sign/devices.json

# 取设备真实指纹填入 fingerprint 字段
ssh-keygen -lf device-001.pub        # → SHA256:xxxx
```

| 能力 | 说明 |
|------|------|
| **白名单** | 未登记 / `enabled:false` 的设备一律拒绝（`EXIT_POLICY`=4）。**`devices.json` 不存在时失败关闭** |
| **指纹校验** | 条目填了 `fingerprint`，就要求 sshd 开启 `ExposeAuthInfo yes`；服务用本次认证的实际公钥指纹比对，防拼凑/盗用 authorized_keys 行 |
| **限频** | `rate_limit: {max, window_sec}`，计数落在 `$TBOX_DONGLE_SIGN_STATE`（服务每次调用是新进程，状态必须落盘；已加 flock） |
| **审计** | 每次调用（**含被拒的**）追加一行 JSON 到 `$TBOX_DONGLE_SIGN_AUDIT`（默认 `/var/log/tbox-dongle/audit.jsonl`） |

审计字段：`ts / device / fp / action / digest / result / ms / src / reason`

**查看入口**：

```bash
tbox-dongle-sign audit --tail 20                    # 最近 20 条（表格）
tbox-dongle-sign audit --device device-001 --since 1d
tbox-dongle-sign audit --result denied --tail 50     # 只看被拒的
tbox-dongle-sign audit --json --tail 5               # 原始 JSON Lines
```

> 策略**仅对带 `--device` 的 SSH 调用生效**；管理员在本机直接执行子命令
> （不带 `--device`）不受白名单限制，但仍会以 `device=local` 记入审计。

### 4. 验证

```bash
# 服务端本地自测（22 项）
python3 selftest.py

# 从设备侧验证连通性
ssh tbox-signer@<host> ping
# → OK

# 取公钥（用于 TBox 登记白名单）
ssh tbox-signer@<host> getpub
```

## 协议

| 子命令 | 输入 | 输出 |
|--------|------|------|
| `ping` | — | `OK`（密钥缺失时报错，不会假"在线"） |
| `getpub` | — | `hex(DER 公钥)`，RSA-2048 ≈ 294 字节 |
| `sign <hex>` | 32 字节 SHA-256 **摘要**（非原始报文） | `hex(DER 签名)`，256 字节 |
| `info` | — | `key=value`：service/version/key_type/pubkey_der_len/pubkey_sha256 |
| `serve` | — | SSH 强制命令模式，读 `$SSH_ORIGINAL_COMMAND` |
| `genkey` | — | 生成私钥（仅管理员本地） |

**退出码**：`0` 成功 / `1` 用法错误 / `2` 参数错误 / `3` 密钥缺失 / `4` 策略拒绝 / `5` 内部错误

> **签名语义**：签的是**摘要**，用 `Prehashed(SHA256) + PKCS#1 v1.5`，
> 与 TA 的 `TEE_ALG_RSASSA_PKCS1_V1_5_SHA256` + `TEE_AsymmetricVerifyDigest` **一一对应**。
> 自测第 [4] 项专门验证了这一点。

## 与 TBox 侧的对接

```bash
# 0. 前置（仅首次，且必须在 --lock 之前）
optee_example_tbox_keystore --init-pin 31323334           # 普通 PIN
optee_example_tbox_keystore --init-so-pin <SO-PIN hex>    # ⚠️ SO-PIN 必须先灌装，只能一次

# 1. 从上位机取公钥，存成文件
ssh tbox-signer@<host> getpub | tr -d '\n' | xxd -r -p > dongle-pub.der

# 2. 在 TBox 上登记进 TA 白名单（一次性，需在 --lock 之前）
optee_example_tbox_keystore --provision-dongle-from-file dongle-pub.der

# 3. 之后即可通过 remote 插件解锁（SO-PIN 用第 0 步的同一个）
optee_example_tbox_keystore --so-unlock --so-pin <同一 SO-PIN hex> --dongle remote
```

> ⚠️ **白名单登记会被现有 TA 拒绝**：`so_provision_dongle()` 目前的公钥长度上限是
> **256 字节**，而 RSA-2048 公钥是 **294 字节**。这正是
> [docs/32 §8.6](../docs/32-dongle-plugin-architecture.md) 记录的阻塞点，
> 需在 **P2** 中把上限放宽到 512 字节。

## 安全须知

| # | 事项 |
|:--:|------|
| 1 | **私钥权限必须 0600**；服务会检查并在过宽时告警 |
| 2 | **禁止**在设备侧关闭 SSH 主机密钥校验（`StrictHostKeyChecking=no`）——那会让 MITM 伪造成"签名狗" |
| 3 | 每台设备**独立 SSH 身份**，不要共用凭据（否则一台失陷 = 全部设备可签） |
| 4 | 定期检查 `authorized_keys`，及时删除已停用设备 |

## 已完成 / 后续

| 阶段 | 内容 | 状态 |
|:--:|------|:--:|
| **P1** | 协议 + 签名服务（`ping`/`getpub`/`sign`/`info`/`genkey`/`serve`） | ✅ |
| **P7** | 设备白名单 `devices.json`（含指纹交叉校验） | ✅ |
| **P7** | 频次限制（`rate_limit`，状态落盘 + flock） | ✅ |
| **P7** | 审计日志 `audit.jsonl` + 查看入口（`audit --tail/--device/--result/--since/--json`） | ✅ |
| **P9** | 云端 transport（`transport_http_mtls`）—— 本期只留接口 | 未实现 |

## 相关文档

- [docs/32-dongle-plugin-architecture.md](../docs/32-dongle-plugin-architecture.md) — 总体设计（§7 本篇的上下文，§8 TA 改造）
- [docs/28-yubikey-full-lifecycle.md](../docs/28-yubikey-full-lifecycle.md) — 当前安全缺口（本方案要闭合的）
- [docs/29-rsa-yubikey-provisioning.md](../docs/29-rsa-yubikey-provisioning.md) — RSA-2048 + TA 内验签的完整设计
