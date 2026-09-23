# 33 — Dongle 部署手册

> **读者**：负责把这套东西部署到实际设备上的工程师。
> **前提**：不需要读过本项目的其他文档，照做即可。每一步都给了**验证方法**，
> 做完能看到明确结果再进下一步。
>
> 覆盖两种 dongle 形态的完整部署、灌装与售后解锁流程。
> 设计背景见 [docs/32](32-dongle-plugin-architecture.md)，本文只讲"怎么做"。

---

## 0. 先用 5 分钟弄清楚你要部署什么

### 0.1 这套东西是干什么的

设备出厂后写保护会被"锁死"，防止别人再往里塞密钥。但售后总有要换密钥／换件的时候，
所以留了一条**需要"加密狗"才能打开的解锁通道**——而且要求 **SO-PIN + 加密狗双因子**。

"加密狗"有两种实现，本文都覆盖：

```
┌───────────────────────────── 设备 (T-Box) ────────────────────────────┐
│  keystore (命令行工具)                                                │
│      │                                                                │
│      ▼                                                                │
│  /oemdata/opt/optee/dongle/ ← 插件目录，--dongle dummy 开 dummy.so    │
│      ├── dummy.so    ┐                                                │
│      └── remote.so   ┘  两个插件，任选其一或都装                      │
└───────────────────────────────────────────────────────────────────────┘
        │                                    │
        │ (dummy)                            │ (remote)
        ▼                                    ▼
  读本地 dummy.key                   ssh 到【上位机】请求签名
  （私钥就在设备上）                  （私钥只在上位机，设备上没有）
```

### 0.2 两种形态怎么选

| | **形态 A：本地软狗** | **形态 B：远程签名狗** |
|---|---|---|
| 私钥在哪 | **设备上**（一个密钥文件） | **上位机**（设备上只有 SSH 身份） |
| 设备被 root / 被克隆 | 拷走文件即可伪造 → **不安全** | 拿不到私钥 → **安全** |
| 需要网络 | 不需要 | 解锁时需要能连到上位机 |
| **适用场景** | 开发、测试、CI、演示 | **生产、现场售后** |

> **生产环境请用形态 B。** 形态 A 的价值是"没硬件也能开发和验证流程"。

### 0.3 名词表（后面会一直用到）

| 名词 | 含义 |
|---|---|
| **PIN** | 出厂灌装的一次性口令，表示"这台设备已归属"。没灌 PIN，TA 不干任何活 |
| **SO-PIN** | Security Officer 口令，解锁用的第一因子。**必须先灌装，且只能一次** |
| **dongle 白名单** | TA 内部保存的"允许解锁的狗"的公钥哈希列表（最多 8 条） |
| **锁定 / `--lock`** | 出厂动作，锁死后禁止生成/删除密钥 |
| **解锁 / `--so-unlock`** | 售后动作，需要 SO-PIN + 白名单里的狗 |

### 0.4 关键前提（**先看这条，否则会卡住**）

> **产品以 OP-TEE 3.2 为准。** 本方案已改造成 **RSA-2048**，
> 因为 OP-TEE 3.2 **无法在安全世界里验 ECDSA 签名**（会 panic）。
> 因此：**所有狗都必须是 RSA-2048**，不能再用 ECDSA/P-256（包括 YubiKey 出厂预置的那种）。

---

# 第一部分：准备工作

## 1. 环境要求

### 1.1 开发机（用来编译，一次性）

| 项 | 要求 |
|---|---|
| 系统 | Linux x86_64 |
| 用途 | 编译 TA、CA、插件 |

### 1.2 设备（T-Box）

| 项 | 要求 |
|---|---|
| TEE | OP-TEE 3.2（产品版本） |
| 目录 | `/lib/optee_armtz/`（放 TA）、`/usr/bin/`、`/usr/lib/` |
| 已装库 | `libssl.so.1.1` / `libcrypto.so.1.1`（CA 和插件要用；**一般镜像里已有**） |

> ⚠️ 设备上**通常没有 `openssl` 命令行**——本文所有需要生成密钥的地方，
> 都已改用随本方案提供的 `dummy_genkey` 工具，不依赖 `openssl` CLI。

### 1.3 上位机（仅形态 B 需要）

| 项 | 要求 |
|---|---|
| 系统 | Ubuntu（或同类 Linux） |
| 软件 | `python3`、`python3-cryptography`、`openssh-server` |
| 网络 | 设备能 SSH 到它（生产环境建议内网/VPN，不要暴露公网） |

---

## 2. 编译（在开发机上执行一次）

```bash
cd <源码根>/optee_examples_AG519M
mkdir -p build && cd build

# 指定交叉编译器（按你实际的工具链路径改）
cmake .. -DCMAKE_C_COMPILER=<工具链>/aarch64-none-linux-gnu-gcc
make keystore dummy_genkey dummy_plugin remote_plugin
```

**产物在这两个地方**（注意不在一起）：

| 产物 | 路径 | 说明 |
|---|---|---|
| `keystore` | `build/tbox_keystore/keystore` | 设备端命令行工具（CA） |
| `dummy.so` | `build/tbox_keystore/dongle/dummy.so` | 插件：本地软狗 |
| `remote.so` | `build/tbox_keystore/dongle/remote.so` | 插件：远程签名狗 |
| `dummy_genkey` | `build/tbox_keystore/dongle/dummy_genkey` | 设备端密钥生成工具 |

TA 单独编译：

```bash
cd <源码根>/optee_examples_AG519M/tbox_keystore/ta
export TA_DEV_KIT_DIR=<optee_os>/out/arm/export-ta_arm64
export CROSS_COMPILE=<工具链>/aarch64-none-linux-gnu-
make
# 产物：f8e9209a-3c7d-4d6b-a15e-7f328b11c049.ta
```

**验证**：四个产物文件都存在且非空。

---

# 第二部分：把文件部署到设备

## 3. 设备端文件部署（两种形态都要做）

把编译产物拷到设备上（用 scp、U 盘、镜像打包均可）。

| # | 文件 | 设备目标路径 | 权限 |
|:--:|------|------|------|
| 1 | `f8e9209a-3c7d-4d6b-a15e-7f328b11c049.ta` | `/lib/optee_armtz/` | 644 |
| 2 | `keystore` | `/usr/bin/` | 755 |
| 3 | `dummy_genkey` | `/usr/bin/` | 755 |
| 4 | 插件（按形态选） | `/oemdata/opt/optee/dongle/` | 755 |

```bash
# 在设备上执行
DGN=/oemdata/opt/optee/dongle          # 默认插件目录（可换，见下方说明）
mkdir -p "$DGN"

# 按你的形态把插件拷进去：
#   形态 A： cp dummy.so  "$DGN/"
#   形态 B： cp remote.so "$DGN/"
# 两个都装也可以：--dongle dummy / --dongle remote 各开各的；
# 不带 --dongle 时自动探测会按优先级选
```

**验证**：

```bash
ls -l /lib/optee_armtz/f8e9209a-*.ta
ls -l /usr/bin/keystore /usr/bin/dummy_genkey
ls -l /oemdata/opt/optee/dongle/
keystore --help | head -3        # 能打印用法即部署成功
```

### 3.1 插件目录与 `--dongle` 的解析规则

`/oemdata/opt/optee/dongle` 只是**编译期默认值**，运行时用 `TBOX_DONGLE_DIR` 覆盖：

```bash
export TBOX_DONGLE_DIR=/opt/my-plugins
keystore --so-info
```

**`--dongle <name>` 直接打开 `<插件目录>/<name>.so`，不遍历目录**：

| 你输入的命令 | 实际打开的文件 |
|--------------|----------------|
| `--dongle dummy` | `<插件目录>/dummy.so` |
| `--dongle remote` | `<插件目录>/remote.so` |
| （不带 `--dongle`） | 扫描目录下所有 `*.so`，按 `priority` 自动探测 |

| 项 | 说明 |
|---|---|
| 覆盖方式 | 环境变量 `TBOX_DONGLE_DIR`（进程级，**不是**编译期） |
| 只读一个目录 | **不支持**多个目录；`TBOX_DONGLE_DIR=/a:/b` 会被当成一个名叫 `/a:/b` 的目录 |
| **名字不能带路径** | `--dongle /opt/x.so`、`--dongle ../x` **会被拒绝**——只接受纯文件名（`.so` 后缀由程序自己加，所以也别写 `.so`） |
| 文件名必须叫 `<name>.so` | 名字就是文件名。若插件文件叫 `impl.so`，`--dongle impl` 才能找到它 |
| 软狗密钥也要跟着走 | 形态 A 下 `dummy.key` 是**放在插件目录里**的（`<插件目录>/dummy.key`），目录一换、密钥位置也跟着换 |
| `remote.conf` 也能跟着走 | 找不到 `/etc/tbox/dongle/remote.conf` 时，会找 `<插件目录>/remote.conf` |

> 💡 **按名加载只会打开那一个文件**——目录里其他 `.so` 完全不会被碰。
> 所以目录里放了一个无关的坏 `.so` 时，按名加载不受影响
> （只有不带 `--dongle` 的自动探测才会去扫它）。

> ### ⚠️ 别用 `LD_LIBRARY_PATH`——它对这个**不生效**
>
> 插件是**程序自己 `dlopen` 打开**的（按 `<目录>/<名字>.so` 的完整路径），
> **不是**由动态链接器按库搜索路径解析的。所以：
>
> - 设 `LD_LIBRARY_PATH=/your/plugins` → **插件照样找不到**
> - 正确做法是设 **`TBOX_DONGLE_DIR`**
>
> 为什么这么设计：自动探测要**扫描目录里所有 `*.so` 并逐个加载**。
> 若接到 `LD_LIBRARY_PATH` 上（那里常有 `/usr/lib`、`/lib`），
> 会去尝试加载几百个无关系统库——**慢、刷屏，而且扩大了攻击面**
> （插件是"能拿狗私钥签名"的驱动，加载谁不该由通用库路径决定）。
>
> ✅ **`LD_LIBRARY_PATH` 仍然有用**，但作用在**另一件事**上：解析插件自身的依赖
> （如 `dummy.so` 需要 `libssl.so.1.1` / `libcrypto.so.1.1`）。

---

# 第三部分：形态 A —— 本地软狗（开发/测试用）

> 私钥就是一个文件，**放在设备上**。仅用于开发验证，不要用于生产。

## 4. 生成软狗密钥（= 插入狗）

```bash
dummy_genkey /oemdata/opt/optee/dongle/dummy.key
```

**验证**：看到 `Dummy dongle key generated: ... (RSA-2048)`，
且 `/oemdata/opt/optee/dongle/` 下同时有 `dummy.so` 和 `dummy.key`。

> **这就是"插狗"的意思**：插件目录里 `.so`（驱动）+ 同名 `.key`（狗内私钥）齐备。
> **拔狗 = 删掉 `dummy.key`**（下次运行即探测不到）。

## 5. 确认设备已认出这只狗

```bash
keystore --provision-dongle --dongle dummy
```

- **正常**：`[dongle] loaded plugin: dummy (RSA-2048)` → `Dongle registered in TA whitelist.`
- **报 `Cannot open key file`**：密钥没放对位置（见 §4）
- **报 `No dongle available`**：插件没加载——确认 `<插件目录>/dummy.so` 存在（按名加载找的就是这个名字），或 ABI 不匹配。报错上一行会打印请求的完整路径和目录里已装的 `*.so`

> 如果这一步报 `devices.json 不存在` 之类，那是形态 B 的东西，形态 A 用不到。

然后跳到 **第六部分**（灌装与解锁）。

---

# 第四部分：形态 B —— 远程签名狗（生产用）

> 私钥**只存在于上位机**。设备上只有一把 SSH 身份密钥。
> 分三小段做：**① 上位机 → ② 设备端 → ③ 登记与解锁**。

## 第一部分：上位机（签名服务器）

### 6. 安装依赖

```bash
sudo apt update
sudo apt install python3 python3-cryptography openssh-server
python3 -c "import cryptography; print('cryptography', cryptography.__version__)"
# 能打印版本号即 OK
```

### 7. 部署服务程序

把源码里的 `tbox_keystore/remote-signer/tbox-dongle-sign` 拷到上位机：

```bash
sudo mkdir -p /opt/tbox-dongle-sign
sudo cp tbox-dongle-sign /opt/tbox-dongle-sign/
sudo chmod 755 /opt/tbox-dongle-sign/tbox-dongle-sign
```

### 8. 生成签名私钥（**这是整套系统的信任根**）

在上位机上执行（**不经过 SSH**，管理员本地操作）：

```bash
sudo /opt/tbox-dongle-sign/tbox-dongle-sign genkey
```

输出类似：

```
私钥已生成: /opt/tbox-dongle-sign/keys/dongle.pem (2048 位, 权限 0600)
公钥 SHA-256: 3f2a...（记下来，稍后要和设备端白名单对账）
```

**验证**：

```bash
sudo ls -l /opt/tbox-dongle-sign/keys/dongle.pem     # 权限必须是 0600
sudo /opt/tbox-dongle-sign/tbox-dongle-sign info     # 能打印 key_type=RSA-2048
```

> ⚠️ **这把私钥泄露 = 所有设备都能被解锁**。请按你们的安全规范保管
> （建议放加密磁盘、限制登录、留存备份）。

> 📌 这里用 `sudo` 生成，私钥属主是 **root**；而服务以 `tbox-signer` 运行，
> 所以**必须在 §9.3 把属主交给它**，否则服务读不到自己的私钥。

### 9. 建立服务账号 · 交接文件属主 · 配置 SSH 强制命令

#### 9.1 建服务账号

账号不存在的话，后面所有 `sudo -u tbox-signer` 都会直接报 `unknown user`：

```bash
sudo useradd -m -d /home/tbox-signer -s /bin/bash tbox-signer
sudo passwd -l tbox-signer          # 锁掉密码登录：只允许公钥

# ⚠️ 确认家目录真的建出来了
getent passwd tbox-signer           # shell 必须是 /bin/bash；家目录必须是 /home/tbox-signer
sudo ls -ld /home/tbox-signer       # 必须存在，且属主是 tbox-signer
```

> ⚠️ **`-m` 漏了会很难查**：家目录不存在时，问题不会在这里报错，而是到 §9.2
> 才以 `chmod: cannot access ...: No such file or directory` 的形式暴露出来。
> 所以上面两条检查**不要跳过**。

> ### ⚠️ shell 必须是**真 shell**——不能填 `/usr/sbin/nologin` 或 `/bin/false`
>
> 这是最容易踩的一个坑。`sshd_config(5)` 原文：
>
> > *"The command is invoked by using the user's login shell with the `-c` option."*
>
> 也就是说，sshd 执行 `authorized_keys` 里的 `command=` 时，实际动作是
> **`$登录shell -c '那条命令'`**。shell 设成 `nologin`，sshd 去执行的就是
> `nologin` 而不是你的服务——**强制命令永远不生效**（OpenSSH 邮件列表里
> Debian Buildbot 用户就踩过：`getpwnam` 返回 `/usr/sbin/nologin` 导致失败）。
>
> 限制手段是**下面的 `command=` + 四组 `no-*` 选项**，不是 nologin。

#### 9.2 准备 `authorized_keys`

```bash
# 以 root 执行 + 显式指定属主，一步到位
sudo install -d -o tbox-signer -g tbox-signer -m 700 /home/tbox-signer/.ssh
sudo install -o tbox-signer -g tbox-signer -m 600 /dev/null /home/tbox-signer/.ssh/authorized_keys
```

**验证**：

```bash
sudo ls -ld /home/tbox-signer /home/tbox-signer/.ssh
sudo ls -l  /home/tbox-signer/.ssh/authorized_keys
```
应看到 `.ssh` 是 `700 tbox-signer tbox-signer`、`authorized_keys` 是 `600 tbox-signer tbox-signer`。

> ### ⚠️ 不要用 `sudo -u tbox-signer mkdir -p ~tbox-signer/.ssh`
>
> 那是**以 `tbox-signer` 的身份**建目录。家目录不存在时，它需要先创建
> `/home/tbox-signer`，而 `/home` 通常是 `root:root 755` —— 它没有这个权限，
> 于是 `mkdir` 静默失败，**错误要到后面的 `chmod` 才以
> `No such file or directory` 的形式冒出来**，指向的却不是你真正做错的那一步。
>
> 用 `install -d` 以 root 执行就没这个问题：父目录会被一并建出，
> 属主/权限一次设对，不依赖 `sudo` 切换身份后的权限。

然后**为每台设备追加一行**（把 `<设备公钥>` 换成你在 §13 生成的设备公钥）：

```
command="/opt/tbox-dongle-sign/tbox-dongle-sign serve --device device-001",no-port-forwarding,no-pty,no-agent-forwarding,no-X11-forwarding ssh-ed25519 <设备公钥> device-001
```

> ⚠️ **两个极易出错的点**：
> 1. **设备 ID 必须写进 `command=` 里**（`serve --device device-001`）。
>    行尾那个 `device-001` 只是注释，**不会传给程序**——只写注释的话服务认不出设备。
> 2. 一行只能放**一台设备**。**吊销设备 = 删掉这一行**。

#### 9.3 把关键文件交给服务账号（**漏了这步服务跑不起来**）

§7 / §8 里的文件是用 `sudo` 建的，属主是 **root**；而服务以 `tbox-signer`
运行，**读不到自己的私钥**。必须改属主：

```bash
# ① 签名私钥所在的**目录**——必须一起改！
#    genkey 以 root 运行，会把该目录建成 0700 root；
#    服务账号进不去这个目录，连"文件存不存在"都判断不了。
sudo chown -R tbox-signer:tbox-signer /opt/tbox-dongle-sign/keys
sudo chmod 700 /opt/tbox-dongle-sign/keys

# ② 私钥文件本身
sudo chown tbox-signer:tbox-signer /opt/tbox-dongle-sign/keys/dongle.pem
sudo chmod 600 /opt/tbox-dongle-sign/keys/dongle.pem

# ③ 服务运行期目录：限流状态 + 审计日志
sudo install -d -o tbox-signer -g tbox-signer -m 700 /var/lib/tbox-dongle
sudo install -d -o tbox-signer -g tbox-signer -m 700 /var/log/tbox-dongle
```

> ### ⚠️ 只 chown 私钥文件是**不够的**——目录也要改
>
> `genkey` 内部是 `os.makedirs(key_dir, mode=0o700)`，所以
> `/opt/tbox-dongle-sign/keys/` 是 **0700 root**。
>
> **只把 `dongle.pem` 改属主，服务照样起不来**，而且报错极具误导性：
>
> ```
> tbox-dongle-sign: error: 私钥不存在: /opt/tbox-dongle-sign/keys/dongle.pem
>   先执行: ... genkey
> ```
>
> 说"不存在"，但 `ls` 明明看得见。原因是 `os.path.exists()` 在
> **父目录不可进入**时也返回 `False`（它吞掉了 `EACCES`）——
> 于是"权限问题"被报成了"文件不存在"。
>
> > 旧版服务就是这个误导性报错。现版本已区分开：
> > 父目录不可进入时会明确报 **"私钥读不到（**不是**不存在）"** 并给出 `chown` 命令。
>
> 所以上面的 **① 目录** 和 **② 文件** 两条都要执行。

**验证（就在这一步做，别拖到后面）**：

```bash
# 必须加 -u：用 sudo 跑是以 root 身份执行，属主没配对也照样通过——验不出问题
sudo -u tbox-signer /opt/tbox-dongle-sign/tbox-dongle-sign info
```

看到 `key_type=RSA-2048` 和三行路径**都打印出来**才算过。
若停在 `私钥读不到` / `私钥不存在`，回到上面把 ① 目录的 `chown -R` 补上。

> ### 🔍 一次性自检：四处属主一起查
>
> 这一节和 §10 加起来有**四处**要交给服务账号，漏掉任何一处都会在**后面某个不相干的时机**
> 才炸出来（而且报错往往指向别的地方）。跑这一段，逐条确认：
>
> ```bash
> sudo -u tbox-signer test -r /opt/tbox-dongle-sign/keys/dongle.pem \
>   && echo "① 私钥        OK" || echo "① 私钥        FAIL — 见 §9.3"
> sudo -u tbox-signer test -w /var/lib/tbox-dongle \
>   && echo "② 状态目录    OK" || echo "② 状态目录    FAIL — 见 §9.3"
> sudo -u tbox-signer test -w /var/log/tbox-dongle \
>   && echo "③ 审计目录    OK" || echo "③ 审计目录    FAIL — 见 §9.3"
> sudo -u tbox-signer test -r /opt/tbox-dongle-sign/devices.json \
>   && echo "④ 白名单      OK" || echo "④ 白名单      FAIL — 见 §10"
> ```
>
> 四条都 `OK` 才算这一节做完（④ 要等 §10 建完 `devices.json` 才有意义）。

> ⚠️ **`devices.json` 的属主在 §10 建完文件后一起改**（那里给了命令）。
> 这三处（私钥 / 白名单 / 运行期目录）是同一类问题：文件是 root 建的、
> 服务是 `tbox-signer` 跑的。

> 🔒 **安全权衡（要意识到）**：私钥必须对 `tbox-signer` 可读，而设备正是
> 以这个账号认证的。所以「拿到 `tbox-signer` 的 shell」=「拿到签名母钥」。
> `command=` 与四组 `no-*` 是**唯一屏障**——务必逐字核对 9.2 的格式。

### 10. 建立设备白名单 `devices.json`

```bash
sudo cp /opt/tbox-dongle-sign/devices.json.example /opt/tbox-dongle-sign/devices.json
sudo chmod 600 /opt/tbox-dongle-sign/devices.json
sudo vi /opt/tbox-dongle-sign/devices.json

# 交给服务账号（同 §9.3）——不改的话服务读不到白名单
sudo chown tbox-signer:tbox-signer /opt/tbox-dongle-sign/devices.json
```

内容格式（**每台设备一条**）：

```json
{
  "devices": [
    {
      "id": "device-001",
      "enabled": true,
      "fingerprint": "SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      "rate_limit": { "max": 30, "window_sec": 60 },
      "note": "产线第一批"
    }
  ],
  "default_policy": "deny"
}
```

| 字段 | 必填 | 说明 |
|---|:--:|---|
| `id` | ✅ | 必须与 authorized_keys 里的 `--device` **完全一致** |
| `enabled` | ✅ | `false` = 停用（保留记录便于审计） |
| `fingerprint` | 选填 | 填了就启用指纹校验，见 §11 |
| `rate_limit` | 选填 | `max` 次 / `window_sec` 秒；不填=不限频 |
| `note` | 选填 | 给人看的备注 |

**验证**：

```bash
sudo /opt/tbox-dongle-sign/tbox-dongle-sign audit --tail 5   # 能跑（暂时空）

# 关键：以服务账号的身份验证 §9.3 的属主交接是否生效
sudo -u tbox-signer /opt/tbox-dongle-sign/tbox-dongle-sign info      # 能读到私钥
sudo -u tbox-signer /opt/tbox-dongle-sign/tbox-dongle-sign audit --tail 5
```

> ⚠️ 上面两条**必须用 `sudo -u tbox-signer` 跑**。用 `sudo` 跑是以 root 身份
> 执行，属主没配对也照样通过——**验不出问题**。

> ⚠️ **`devices.json` 不存在时，带设备身份的调用一律拒绝**（失败关闭）。
> 这是刻意的：宁可拒绝，也不要放行一台没登记的设备。

### 11. （可选，推荐）开启指纹校验

只靠 authorized_keys 的 `--device` 标签，无法防止"有人拿到别人的公钥文件来冒用"。
开启指纹校验后，服务会拿**本次 SSH 认证实际使用的公钥**去比对：

```bash
# 1) 在上位机 sshd 配置里开启
sudo sh -c 'echo "ExposeAuthInfo yes" >> /etc/ssh/sshd_config'
sudo systemctl restart ssh

# 2) 取设备公钥的指纹，填进 devices.json 的 fingerprint 字段
ssh-keygen -lf /path/to/device-001.pub
# → SHA256:xxxx...    （把 "SHA256:xxxx..." 整串填进去）
```

> **配了指纹却没开 `ExposeAuthInfo`** → 调用会被**拒绝**（不会静默放行），
> 报错信息会明确告诉你原因。

### 12. 上位机自检

```bash
# 服务自身是否正常
sudo -u tbox-signer /opt/tbox-dongle-sign/tbox-dongle-sign ping
# 期望输出：OK

# 端到端（在本机模拟一次 SSH 调用）
sudo -u tbox-signer ssh -i <某台设备的私钥> localhost \
    "ping" 2>/dev/null
# 注意：实际使用时子命令由客户端传入，这里只验证 SSH 强制命令能跑通
```

---

## 第二部分：设备端

### 13. 生成设备专属 SSH 身份（**每台设备一把，不要共用**）

```bash
mkdir -p -m 700 /etc/tbox/dongle
ssh-keygen -t ed25519 -N "" -f /etc/tbox/dongle/id_ed25519
cat /etc/tbox/dongle/id_ed25519.pub
```

- 把 **`.pub` 的内容**交给上位机管理员，写进 §9 的 `authorized_keys`
- **`.pub` 的指纹**（`ssh-keygen -lf /etc/tbox/dongle/id_ed25519.pub`）填进 §10 的 `fingerprint`

> **为什么每台设备要独立**：服务端靠这个身份区分"是哪台设备在请求"。
> 如果所有设备共用一个身份，**一台设备被攻陷就等于所有设备可被签名**。

### 14. 预置 `known_hosts`（**这步不能省**）

插件**强制校验服务器主机密钥**（`StrictHostKeyChecking=yes`），没有它连不上：

```bash
ssh-keyscan -p 22 <上位机地址> > /etc/tbox/dongle/known_hosts
chmod 600 /etc/tbox/dongle/known_hosts
```

> **为什么强制**：不校验主机密钥，攻击者就能冒充签名服务器骗设备把 challenge 发过去。
>
> ⚠️ **上线前请与上位机管理员核对这个文件的指纹**，确保拿到的是真服务器的密钥。

### 15. 写设备端配置 `remote.conf`

```bash
cp /path/to/remote.conf.example /etc/tbox/dongle/remote.conf
vi /etc/tbox/dongle/remote.conf
```

最小配置（其余保持默认）：

```ini
transport = ssh
host      = <上位机地址>
user      = tbox-signer
port      = 22
key         = /etc/tbox/dongle/id_ed25519
known_hosts = /etc/tbox/dongle/known_hosts
timeout_ms  = 2000
remote_cmd  =                    # ← 留空！见下方说明
```

| 键 | 说明 |
|---|---|
| `host` / `user` / `port` | 上位机地址与签名服务账号 |
| `key` | §13 生成的设备身份私钥 |
| `known_hosts` | §14 预置的文件 |
| `remote_cmd` | **留空**（推荐部署下）。理由见下 |
| `ssh_bin` | SSH 客户端程序。**嵌入式上常是 dropbear 的 `dbclient` 而不是 `ssh`**，按实际改 |
| `timeout_ms` | 单次调用总超时；`probe`（探测）也用它，别设太大 |

> ### ⚠️ `remote_cmd` 为什么必须留空
>
> 配合 §9 的 sshd 强制命令部署，**sshd 负责执行服务**，客户端敲的整串会作为
> `$SSH_ORIGINAL_COMMAND` 交给它。所以插件必须**只发子命令**（如 `getpub`）。
>
> **如果这里填了 `tbox-dongle-sign`**，服务会把这个名字当成子命令名，
> 报错 `未知子命令: tbox-dongle-sign`，**部署直接卡住**。
>
> 只有当你们用的是**普通 shell 账号**（没有 `command=` 强制命令）时，才需要填完整命令：
> `remote_cmd = /opt/tbox-dongle-sign/tbox-dongle-sign`

> 未列出的键保持默认即可。配置内容**不需要重新编译插件**，改完直接生效。

### 16. 设备端连通性自检

```bash
keystore --provision-dongle --dongle remote
```

- **正常**：`[remote] connected: tbox-signer@<上位机> (294-byte pubkey)`
- **`Cannot open known_hosts` / `Host key verification failed`** → 回到 §14
- **`Permission denied`** → 设备公钥没加到上位机 authorized_keys（§9），或 `key` 路径不对
- **`RESERVED, not implemented`** → 配置文件里 `transport` 写成了 `http_mtls`，改成 `ssh`
- **卡住约 2 秒后失败** → 网络不通或上位机 sshd 没起（`timeout_ms` 生效，属正常保护）

---

## 第三部分：登记白名单与首次灌装

### 17. 把签名服务器的公钥登记进 TA 白名单

**在上位机上**导出公钥：

```bash
sudo /opt/tbox-dongle-sign/tbox-dongle-sign getpub
# 输出一串 hex
```

**在设备上**存成 DER 文件并登记：

```bash
# 方式一：上位机输出重定向过来（hex → 二进制）
ssh tbox-signer@<上位机> "tbox-dongle-sign getpub" | tr -d '\n' | xxd -r -p > /tmp/signer-pub.der

# 方式二：手动把 hex 存成文件后转换
# echo "<粘贴 hex>" | tr -d '\n' | xxd -r -p > /tmp/signer-pub.der

# 登记
keystore --provision-dongle-from-file /tmp/signer-pub.der
```

**验证**：输出 `Dongle registered from file: /tmp/signer-pub.der`

> 这一步把"允许解锁的狗"写进 TA。**每台设备都要单独登记**。
> 登记必须在 `--lock` 之前完成，否则会被写保护拒绝。

### 18. 首次灌装完整流程（**顺序不能变**）

> ⚠️ 三条硬性顺序约束，违反就会失败：
> 1. `--init-pin` / `--init-so-pin` **只能各执行一次**
> 2. `--init-so-pin` **必须在 `--so-unlock` 之前**（没灌 SO-PIN 无法解锁）
> 3. `--provision-dongle*` **必须在 `--lock` 之前**（锁后写操作被禁）

```bash
CLI=keystore          # 产物名，按实际改

# ① 灌装普通 PIN（一次性）
$CLI --init-pin 31323334

# ② 灌装 SO-PIN（一次性）—— 换成你们自己的口令，务必记录归档
$CLI --init-so-pin <SO-PIN hex>

# ③ 生成业务密钥（按项目需要，示例）
$CLI --gen-rsa device-key --size 2048 --sign --decrypt

# ④ 登记狗的白名单
#    形态 A：$CLI --provision-dongle --dongle dummy
#    形态 B：$CLI --provision-dongle-from-file /tmp/signer-pub.der   （见 §17）

# ⑤ 查看确认
$CLI --so-info

# ⑥ 出厂锁定（**最后一次写操作**）
$CLI --lock
```

**⑤ 的期望输出**：

```
SO State:       PROVISIONED
Dongles:        1 registered
Failures:       0 consecutive, 0 total (max 3/1000)
```

**⑥ 的验证**（锁定应生效）：

```bash
$CLI --gen-rsa test-key --size 2048
# 期望：失败（write operation denied）——失败才是对的
```

> **SO-PIN 的 `hex` 是什么**：你选的一串字节的十六进制表示。例如想要 "1234"
> 就写 `31323334`。**`--init-so-pin` 和 `--so-unlock` 必须用完全相同的值**。
> 请按公司安全规范记录归档——**丢了 SO-PIN 且没有狗，设备就再也解不开锁**。

---

# 第五部分：售后解锁（实际使用时）

## 19. 解锁

```bash
CLI=keystore

# ① 先看当前状态
$CLI --so-info

# ② 解锁
#    形态 A：
$CLI --so-unlock --so-pin <SO-PIN hex> --dongle dummy
#    形态 B：
$CLI --so-unlock --so-pin <SO-PIN hex> --dongle remote

# ③ 维护操作（生成/删除密钥等）……
$CLI --gen-rsa temp-key --size 2048 --sign

# ④ ★ 收尾：重新锁上
$CLI --so-lock
$CLI --so-info        # 确认回到 LOCKED
```

**② 的期望输出**：`✓ SO unlock successful. TA is now UNLOCKED.`

> ⚠️ **④ 的收尾不要漏**：解锁状态**不会自动过期**（设计中提到的空闲超时**尚未实现**）。
> 忘了 `--so-lock`，写保护就一直开着。**请把"维护完必锁"写进你们的作业规范。**

## 20. 查看审计日志（形态 B）

```bash
# 最近 20 条
sudo /opt/tbox-dongle-sign/tbox-dongle-sign audit --tail 20

# 只看某台设备 / 只看被拒绝的 / 看最近一天
sudo /opt/tbox-dongle-sign/tbox-dongle-sign audit --device device-001 --since 1d
sudo /opt/tbox-dongle-sign/tbox-dongle-sign audit --result denied --tail 50

# 原始 JSON（便于导入你们的日志系统）
sudo /opt/tbox-dongle-sign/tbox-dongle-sign audit --json --tail 100
```

审计文件：`/var/log/tbox-dongle/audit.jsonl`（每行一条 JSON，
含 `ts/device/fp/action/digest/result/ms/src/reason`）。

---

# 第六部分：验收清单

按顺序打勾，**任何一项不过就不要继续**。

## 21. 部署验收

| # | 检查项 | 命令 / 方法 | 期望 |
|:--:|------|------|------|
| 1 | TA 已部署 | `ls /lib/optee_armtz/f8e9209a-*.ta` | 文件存在 |
| 2 | CLI 可用 | `keystore --help` | 打印用法 |
| 3 | 插件已加载 | `keystore --so-info` | 无 "plugin 加载失败" 报错 |
| 4 | **狗可被探测**（A） | 见 §5 | 登记成功 |
| 5 | **狗可被探测**（B） | 见 §16 | `connected: ... (294-byte pubkey)` |
| 6 | 上位机服务正常（B） | `tbox-dongle-sign ping` | `OK` |
| 7 | 白名单已配（B） | 见 §10 | `devices.json` 含该设备且 `enabled:true` |
| 8 | SO-PIN 已灌装 | `keystore --so-info` | `SO State: PROVISIONED`（或 LOCKED） |
| 9 | 狗已登记 | `keystore --so-info` | `Dongles: 1 registered` |
| 10 | 写保护已生效 | `keystore --gen-rsa test --size 2048` | **失败**（预期） |

## 22. ★ 安全验收（最重要的一条）

**目的**：证明"换一把没登记的狗解不开锁"——也就是说 **TA 真的在验签，而不是走形式**。

```bash
CLI=keystore

# 1) 准备一把"未登记"的狗
#    形态 A：
dummy_genkey /tmp/other.key
export TBOX_DONGLE_KEY_DUMMY=/tmp/other.key     # ← 必须用这个变量！见下方警告
#    形态 B：用另一台未登记设备的 SSH 身份，或临时把 devices.json 里该设备置 false

# 2) 尝试解锁 —— 必须失败
$CLI --so-unlock --so-pin <SO-PIN hex> --dongle dummy
#    期望：TA rejected unlock: bad signature, or dongle not in TA whitelist

# 3) 换回已登记的狗 —— 必须成功
unset TBOX_DONGLE_KEY_DUMMY
$CLI --so-unlock --so-pin <SO-PIN hex> --dongle dummy
#    期望：✓ SO unlock successful
$CLI --so-lock
```

> ⚠️ **形态 A 的坑**：换狗必须用 **`TBOX_DONGLE_KEY_DUMMY`**。
> 用 `TBOX_DUMMY_KEY` 会被插件目录里的 `dummy.key` **覆盖**，
> 那样你测的其实是**已登记的那把狗**，会得出**相反的错误结论**。
> （若真发生，插件会打印 `warning: $TBOX_DUMMY_KEY=... is IGNORED` —— 看到就该警觉。）

> **形态 B 的坑**：`TBOX_DONGLE_DIR` 默认指向 `/oemdata/opt/optee/dongle`；
> 换 identity 请改 `remote.conf` 的 `key` 或 `devices.json` 的 `enabled`。

## 23. 记录归档（交给运维）

| 项 | 记录内容 |
|---|---|
| SO-PIN | **按公司规范密封归档** |
| 签名私钥（B） | 备份位置、保管人 |
| `devices.json`（B） | 版本快照 |
| `known_hosts`（B） | 指纹核对记录 |
| 本设备序列号 ↔ `device id` 对照表（B） | 便于日后吊销 |

---

# 第七部分：故障排查（按现象查）

## 24. 设备端

| 现象 | 原因 | 处理 |
|------|------|------|
| `No dongle available` | 插件没加载，或文件名不对 | ① 确认 `<插件目录>/<name>.so` 存在（`--dongle dummy` 找的是 `dummy.so`）② 上一行的报错会打印**请求的完整路径**和目录里已装的 `*.so` |
| 插件放在别处、找不到 | 没设 `TBOX_DONGLE_DIR` | `export TBOX_DONGLE_DIR=<你的目录>`（**§3.1**） |
| 设了 `LD_LIBRARY_PATH` 仍找不到插件 | **该变量对插件加载不生效** | 改用 `TBOX_DONGLE_DIR`（**§3.1** 有解释） |
| **`--dongle dummy.so`** 报找不到 `dummy.so.so` | 名字里**不要带 `.so`**——后缀由程序自己加 | 改回 `--dongle dummy` |
| **`--dongle /opt/x.so`** 被拒（`invalid backend name`） | **不接受路径**，只接受纯文件名（`[A-Za-z0-9._-]`） | 把插件放进 `TBOX_DONGLE_DIR`，然后用 `--dongle <文件名去掉.so>` |
| 插件文件叫 `impl.so`，`--dongle impl` 找不到 | 旧版按插件**自报名字**匹配，新版按**文件名**解析 | 把文件改名为 `<name>.so`（**行为变更**，见 §3.1） |
| `... is not a dongle plugin` | 该 `.so` 不是 dongle 插件（缺导出符号） | 换成正确的插件文件。按名加载时**只有被点名的那个**会被加载 |
| `ABI mismatch (plugin=N, host=M)` | 插件与 CA 版本不配套 | **重新一起编译并同时部署** |
| `Cannot open key file` (A) | `dummy.key` 位置/权限不对 | 放到 `/oemdata/opt/optee/dongle/dummy.key` |
| `warning: $TBOX_DUMMY_KEY=... is IGNORED` | 目录里的 `.key` 优先于该变量 | 换狗用 `TBOX_DONGLE_KEY_DUMMY` |
| `ssh: host not configured` (B) | `remote.conf` 没配或路径不对 | 见 §15 |
| `未知子命令: tbox-dongle-sign` (B) | `remote_cmd` 不该填却填了 | 强制命令模式下**必须留空**（§15） |
| `Host key verification failed` (B) | `known_hosts` 缺失或不匹配 | 见 §14，并核对指纹 |
| `getpub failed (rc=3)` (B) | 上位机没有签名私钥 | 在上位机执行 `genkey`（§8） |
| `TA rejected unlock: ...` | 签名无效／狗不在白名单 | ① 确认狗已登记（§17）② 确认狗是**同一把**③ 形态 B 看审计日志 |
| `SO-PIN not provisioned` | 没执行 `--init-so-pin` | 见 §18 第 ② 步 |
| `PIN not yet provisioned` | 没执行 `--init-pin` | 见 §18 第 ① 步 |
| `TA denied the write: locked (run --so-unlock) or no PIN provisioned` —— 旧版二进制只显示裸 **`0xffff0001`**（= `TEE_ERROR_ACCESS_DENIED`） | 写保护生效中：TA 已灌装锁定，SO 未解锁 | 先 `--so-unlock`（§19）。若这台 TA **从未灌装**（PIN 未设），改为 `--init-pin`。用 `--so-info` 看当前状态 |
| `SO cooldown active, N seconds remaining` | 连续 3 次 SO-PIN 错 | 等待 N 秒 |
| `SO permanently bricked` | 累计 1000 次 SO-PIN 失败 | **设备报废**，无解 |

## 25. 上位机（B）

| 现象 | 原因 | 处理 |
|------|------|------|
| `unknown user: tbox-signer` | 服务账号没建 | 见 §9.1 |
| `chmod: cannot access '.../.ssh/authorized_keys': No such file or directory`（**§9.2 的 chmod 步骤**） | 家目录不存在（`useradd` 漏了 `-m`）→ `sudo -u tbox-signer mkdir` 没权限建父目录、**静默失败** | 用 §9.1 的两条检查确认家目录；改按 **§9.2** 的 `install -d` 重建 |
| `mkdir: cannot create directory '/home/tbox-signer': Permission denied` | 同上——以 `tbox-signer` 身份建目录，而 `/home` 不可写 | 同上 |
| **`私钥不存在: .../keys/dongle.pem`**（但 `ls` 看得见）—— 旧版服务会误报；新版报 **`私钥读不到（不是不存在）`** | **`keys/` 目录是 0700 root**，服务账号进不去（`os.path.exists()` 在父目录不可进入时也返回 False） | 见 **§9.3**：**目录和文件都要 `chown`**（`chown -R` + `chmod 700`） |
| `私钥无法读取: ... Permission denied` | 文件在、但权限位不对 | `chmod 600` + `chown tbox-signer:tbox-signer`（§9.3） |
| **`internal error: [Errno 13] Permission denied: '/var/lib/tbox-dongle'`** —— 旧版服务会这么报（完全看不出该做什么）；新版报 **`状态目录不可用`** 并附命令 | §9.3 第 ③ 步没做：服务账号对该目录没有写权限（限流状态要落盘） | `sudo install -d -o tbox-signer -g tbox-signer -m 700 /var/lib/tbox-dongle`（§9.3） |
| `审计目录不可进入: /var/log/tbox-dongle (权限 0700)` | 同上，审计目录属主没配对 | `sudo install -d -o tbox-signer -g tbox-signer -m 700 /var/log/tbox-dongle`（§9.3） |
| `devices.json 无法解析: ... Permission denied` | 白名单属主没交给服务账号（措辞是"无法解析"，实际是读不到） | 见 **§10** 最后的 `chown` |
| `拒绝: devices.json 不存在` | 没建白名单文件 | 见 §10 |
| `拒绝: 设备未登记: xxx` | `id` 与 `--device` 不一致 | 两处必须逐字相同（§9 / §10） |
| `拒绝: 设备已停用` | `enabled:false` | 改回 `true` |
| `拒绝: 指纹不匹配` | 填的指纹与实际公钥不符 | 重新 `ssh-keygen -lf` 取指纹（§11） |
| `... 但 sshd 未开启 ExposeAuthInfo` | 配了指纹但没开该项 | 见 §11 第 1 步 |
| `拒绝: 限频触发` | 超过 `rate_limit` | 调整限额，或等待窗口 |
| `审计写入失败` | `/var/log/tbox-dongle` 无权限 | 检查目录权限（服务账号需可写，见 §9.3） |
| 设备**能连上但服务执行报错** | shell 设成了 `nologin`/`false`，sshd 执行的是 nologin 而不是服务 | 改成真 shell（`/bin/bash`），见 **§9.1** |
| 设备连不上 | 网络/防火墙/sshd | 在设备上 `ssh tbox-signer@<上位机> ping` 手工试 |

---

# 第八部分：安全注意事项（交付时必须交代）

## 26. 必须遵守

| # | 事项 |
|:--:|------|
| 1 | **生产必须用形态 B**（远程签名狗）；形态 A 的私钥在设备上，可被拷走 |
| 2 | **签名私钥只在上位机**，权限 `0600`，按规范备份与保管 |
| 3 | **每台设备独立 SSH 身份**；共用身份 = 一台失陷等于全部 |
| 4 | **`known_hosts` 必须与上位机核对指纹**后再上线，绝不能关主机密钥校验 |
| 5 | **SO-PIN 归档保管**；丢了 SO-PIN 且没有狗 = 设备永久锁死 |
| 6 | **维护完必须 `--so-lock`**（解锁不会自动过期） |
| 7 | **吊销设备**：删 authorized_keys 那一行 + `devices.json` 置 `enabled:false` |
| 8 | 若设备端被完全攻陷，攻击者能用**这台设备**的身份请求签名——所以**限频与审计要开**，并定期巡检 |

## 27. 已知限制（如实告知，便于你们评估）

| # | 限制 | 影响 |
|:--:|------|------|
| 1 | **解锁状态不会自动过期** | 忘了 `--so-lock` → 写保护一直开着。设计中提到的"空闲自动锁"**尚未实现** |
| 2 | **云端 transport 未实现** | 配置里可写 `transport = http_mtls`，但会明确报错；目前只能用 `ssh` |
| 3 | **批量白名单灌装未实现** | 多台设备需逐台 `--provision-dongle-from-file` |
| 4 | **插件不做签名校验** | 插件目录里放什么就加载什么；生产环境请限制该目录的写权限，只放必需插件 |
| 5 | **YubiKey 硬件狗暂不可用** | 源码保留未编译；如需使用需先按插件 ABI 移植并把 PIV 密钥换成 RSA-2048 |

---

## 附录 A：文件路径速查

**设备端**

| 路径 | 内容 |
|------|------|
| `/lib/optee_armtz/f8e9209a-….ta` | TA |
| `/usr/bin/keystore` | 命令行工具（CA） |
| `/usr/bin/dummy_genkey` | 密钥生成工具（无 openssl CLI 时用） |
| `/oemdata/opt/optee/dongle/dummy.so` | 插件：本地软狗（`--dongle dummy` 打开的就是它） |
| `/oemdata/opt/optee/dongle/remote.so` | 插件：远程签名狗（`--dongle remote`） |
| `/oemdata/opt/optee/dongle/dummy.key` | 软狗私钥（**形态 A**） |
| `/etc/tbox/dongle/remote.conf` | 远程狗配置（形态 B） |
| `/etc/tbox/dongle/id_ed25519` | 设备 SSH 身份（形态 B） |
| `/etc/tbox/dongle/known_hosts` | 服务器主机密钥（形态 B） |

**上位机（形态 B）**

| 路径 | 内容 |
|------|------|
| `/opt/tbox-dongle-sign/tbox-dongle-sign` | 服务程序 |
| `/opt/tbox-dongle-sign/keys/dongle.pem` | **签名私钥**（0600） |
| `/opt/tbox-dongle-sign/devices.json` | 设备白名单 |
| `/var/log/tbox-dongle/audit.jsonl` | 审计日志 |
| `/var/lib/tbox-dongle/state.json` | 限频计数状态 |
| `~tbox-signer/.ssh/authorized_keys` | 每台设备一行（含 `--device`） |

## 附录 B：命令速查

```bash
# —— 首次灌装（顺序固定）——
keystore --init-pin <hex>
keystore --init-so-pin <hex>
keystore --gen-rsa device-key --size 2048 --sign --decrypt
keystore --provision-dongle --dongle dummy            # 形态 A
keystore --provision-dongle-from-file <pub.der>       # 形态 B
keystore --so-info
keystore --lock

# —— 售后维护 ——
keystore --so-unlock --so-pin <hex> --dongle dummy    # 或 --dongle remote
keystore --gen-rsa temp-key --size 2048 --sign
keystore --so-lock                                    # 别忘

# —— 诊断 ——
keystore --so-info
keystore --info <label>

# —— 上位机 ——
tbox-dongle-sign genkey
tbox-dongle-sign getpub
tbox-dongle-sign info
tbox-dongle-sign ping
tbox-dongle-sign audit --tail 20
```

## 附录 C：环境变量（调试用）

**设备端**

| 变量 | 作用 |
|---|---|
| `TBOX_DONGLE_DIR` | **插件目录**（默认 `/oemdata/opt/optee/dongle`）。换目录、或部署到非默认位置时必须设它；**只支持单个目录**。`--dongle <name>` 打开的就是 `<该目录>/<name>.so`（也决定 `dummy.key` / `remote.conf` 的位置）。插件加载**不看 `LD_LIBRARY_PATH`**（§3.1） |
| `TBOX_DONGLE_KEY_DUMMY` | 指定软狗密钥，**优先级最高**（换狗测试用这个） |
| `TBOX_DUMMY_KEY` | 旧接口指定软狗密钥（**会被插件目录里的 `dummy.key` 覆盖**） |
| `TBOX_REMOTE_DONGLE_CONF` | 指定 `remote.conf` 路径 |
| `TBOX_REMOTE_DONGLE_{HOST,USER,PORT,KEY,KNOWN_HOSTS,SSH_BIN,TIMEOUT_MS,CMD}` | 覆盖对应配置项 |

**上位机**

| 变量 | 作用 |
|---|---|
| `TBOX_DONGLE_SIGN_HOME` | 服务根目录（默认 `/opt/tbox-dongle-sign`） |
| `TBOX_DONGLE_SIGN_KEY` | 签名私钥路径 |
| `TBOX_DONGLE_SIGN_DEVICES` | `devices.json` 路径 |
| `TBOX_DONGLE_SIGN_AUDIT` | 审计日志路径 |
| `TBOX_DONGLE_SIGN_STATE` | 限频状态路径 |

---

## 相关文档

| 文档 | 内容 |
|------|------|
| [32-dongle-plugin-architecture.md](32-dongle-plugin-architecture.md) | 设计与实现（想理解"为什么这样做"看这里） |
| [31-key-management-and-secure-services.md](31-key-management-and-secure-services.md) | 密钥管理与安全能力总述（通俗版） |
| [29-rsa-yubikey-provisioning.md](29-rsa-yubikey-provisioning.md) | RSA-2048 方案设计 |
| [28-yubikey-full-lifecycle.md](28-yubikey-full-lifecycle.md) | 安全缺口的历史分析（已闭合） |
| [30-ecc-p256-ta-unsupported-debug-log.md](30-ecc-p256-ta-unsupported-debug-log.md) | 为何必须用 RSA 而非 ECDSA |
