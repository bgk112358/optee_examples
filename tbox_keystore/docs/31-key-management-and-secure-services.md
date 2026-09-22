# 31 — 钥匙是怎么管的，HTTPS/MQTTS 的安全又是从哪来的

> 写给不熟悉这套代码的人看：用大白话讲清楚两件事——
> ① T-Box 里的密钥（钥匙）从生到死怎么管，那个 USB 加密狗（dongle）在里面起什么作用；
> ② 我们怎么靠这些钥匙，让 HTTPS 和 MQTTS 变得安全。
> 里面凡是牵扯到文件/命令/模块的地方都给了真实名字，顺着名字去翻就能找到代码。

---

## 0. 先摆一张"总地图"，后面全在这张图上讲

这套系统的骨头就一句话：**私钥永远锁在安全世界里，普通世界只借它的"手"（运算能力），永远碰不到它的"心"（密钥本身）。**

```
┌────────────────────────────── 普通世界 (REE / Linux) ─────────────────────────────┐
│                                                                                    │
│  业务程序：  https_client / mqtts_pub / mqtts_sub / tls_mutual_auth               │
│     │                                                                              │
│     ▼  通过标准 OpenSSL API 要"签名/验签/解密"                                      │
│  ┌────────────────────┐                                                            │
│  │ OpenSSL 1.1.1      │                                                            │
│  │  + ENGINE          │  libengkeystore.so   ← 引擎,把 RSA 运算截下来转发给 TA     │
│  └────────┬───────────┘                                                            │
│           ▼  libteec (TEE Client API)                                              │
│           ▼  调用 TA 的 CMD_SIGN / CMD_VERIFY / CMD_RSA_DECRYPT                    │
├───────────┼──────────────────────── 安全世界 (TEE / TrustZone) ────────────────────┤
│           ▼                                                                        │
│  ┌──────────────────────────────────────────┐                                      │
│  │  tbox_keystore TA (f8e9209a-…-c049)      │   密钥全在这，以持久化对象存安全存储   │
│  │  entry.c  命令入口 + 三道门禁             │   私钥永不出这个框                    │
│  │  keystore.c 密钥的新建/存储/读取           │                                      │
│  │  pin_mgr.c    普通 PIN 管理               │                                      │
│  │  so_pin_mgr.c SO-PIN + 解锁/锁死          │                                      │
│  │  crypto_ops.c RSA/AES 实际运算            │                                      │
│  └──────────────────────────────────────────┘                                      │
└────────────────────────────────────────────────────────────────────────────────────┘
```

上面这条 **业务程序 → OpenSSL ENGINE → libteec → TA → 私钥运算** 的链路，就是第 2 部分要讲的 HTTPS/MQTTS 安全来源。第 1 部分先讲清这些私钥在 TA 里是怎么被管住的——毕竟门锁得先牢，钥匙才有意义。

---

# 第一部分：钥匙是怎么管的

## 1.1 钥匙存在哪：不在文件里，在"安全保险柜"里

传统 Linux 程序把私钥放在磁盘文件里（比如 `/etc/xxx.pem`），谁拿到 root 就能拷走。我们这里不行——**私钥作为 TEE 的"持久化对象"存在安全存储（Secure Storage）里**，对普通世界来说它就是一坨密文，谁也读不出来。真正能"用"它（签名/解密）的，只有 TA 里面的代码。

TA 里管这些钥匙的模块叫 `keystore.c`，每把钥匙有：

| 属性 | 说明 | 例子 |
|------|------|------|
| **label（名字）** | 唯一的钥匙标签，就像抽屉标签 | `device-key`、`ota-key`、`server-key` |
| **type（类型）** | RSA 还是 AES | RSA-2048 / AES-256 |
| **permissions（权限）** | 这把钥匙**允许**干什么 | SIGN / VERIFY / ENCRYPT / DECRYPT |

**每把钥匙生成时就定死了它允许干什么**，这个权限位（ACL）由 `acl.c` 把关。比如一把"只许验签不许签名"的钥匙，就算你拿到它也没法用它签东西——权限不够，TA 直接拒绝。

### 为什么出厂时明文要写清楚权限？
因为 TEE 是"代码写死才安全"的地方。业务侧（REE）是不可信的，如果权限是运行时由 REE 说了算，那攻击者改了 REE 就能让 TA 用任何钥匙干任何事。所以**权限在钥匙出生那一刻就被 TA 写死进存储**，后面 REE 改不了。

## 1.2 谁在操作 TA？—— 那个命令行工具 `keystore_client`

所有管钥匙、用钥匙的动作，都通过 CA 侧的 CLI 工具发起，
源码是 `host/keystore_client.c`。它只是"传话的"，真正的判断全在 TA。

> **关于工具名**：本文统一写作 `optee_example_tbox_keystore`。
> 实际产物名由 CMake 项目名决定（`tbox_keystore/CMakeLists.txt` 的
> `project(...)`），当前是 `keystore`——各脚本里的 `$CLI` / `$TBOX` 变量即指它。

它管钥匙的核心命令长这样（照真实 usage 抄的）：

```bash
# 灌装 PIN（一次性）→ 见 1.3
optee_example_tbox_keystore --init-pin <hex-pin>

# 造钥匙（要指定权限）
optee_example_tbox_keystore --gen-rsa device-key --size 2048 --sign --decrypt
optee_example_tbox_keystore --gen-aes ota-key   --size 256  --decrypt
#  ↑ 注意：RSA 的 VERIFY / EXPORT_PUB 是默认自带的，不用也不能写 --verify

# 查钥匙 / 删钥匙
optee_example_tbox_keystore --info  device-key
optee_example_tbox_keystore --delete device-key

# 用钥匙（签名验签等，这些只"用"不"改"）
optee_example_tbox_keystore --sign   device-key --data <hex|@file>
optee_example_tbox_keystore --verify device-key --data <hex|@file> --sig <hex|@file>
```

## 1.3 第一道门：普通 PIN（"这机器归谁"的标记）

- 出厂时管理员执行 `--init-pin`，把一串 PIN 灌进 TA（一次性，灌完就不能再灌）。
- 之后 TA 里**所有干活的操作（签名/验签/加解密）都要求"PIN 已灌装"**。没灌 PIN 的机器，TA 一律不干活（`pin_mgr_verify` 直接报 `PIN not yet provisioned`）。
- 这道门不是"每次操作都要输 PIN"，而是"没灌装就全停摆"——它防止的是**有人拿到一块没出厂的板子随便造钥匙**。

## 1.4 第二道门：写保护 + 出厂锁定（"板上钉钉，不许再改"）

产线灌完钥匙后执行 `--lock`（对应 TA 的 `CMD_PROVISION_LOCK`）。一锁，TA 就进入"只读+只算"状态：

```
锁定后：
  ✅ 还能做：签名、验签、加解密（用现有钥匙）
  ❌ 不能做：再造新钥匙(gen)、删钥匙(delete)、再灌 PIN —— 统统 ACCESS_DENIED
```

这就是"量产安全机制"：**设备出厂后，谁也别想往里面再塞钥匙或改钥匙**——除非走下一节的"安全官员解锁"流程。

## 1.5 钥匙不许"悄悄覆盖"

所有钥匙生成都是**禁止覆盖**策略：如果 `--gen-rsa device-key` 而 `device-key` 已存在，TA 返回"已存在"错误，**不会**静默把旧的覆盖掉。

> 为什么？防的是攻击者"我知道你有一个生产密钥，我用我自己的同标签密钥覆盖上去，以后我就能签你的包了"。标签必须和物理钥匙一一对应、不可替换。

## 1.6 那万一真要换钥匙呢？—— SO-PIN + USB 加密狗（dongle）

现实里总有售后场景：设备坏了要换件、密钥泄露要吊销重配、要临时做维护……但 1.4 说死了"锁定后不能改"。于是设计了**第二条解锁通道**，而且是**双人/双因子**的，不是随便一个人拿个 PIN 就能开锁。

### 1.6.1 两个概念先说清

| 概念 | 是什么 | 比喻 |
|------|--------|------|
| **SO-PIN** | Security Officer 口令，灌装阶段设的 | "安全官的口令" |
| **dongle（加密狗）** | 一个 USB 硬件，里面有一把**独立的密钥对**（私钥永不出狗） | "安全官的实体钥匙" |

解锁不是"知道 SO-PIN 就行"，而是 **"知道 SO-PIN（第一因子） + 手里有那把被白名单认证过的 dongle（第二因子）"** 两个同时满足。

### 1.6.2 dongle 在代码里长什么样

dongle 抽象成一套统一接口，在 `dongle/` 目录，接口定义在 `dongle_ops.h`：

```c
struct dongle_ops {
    int  (*probe)(void);            // 有没有这只狗
    int  (*open)(struct dongle_ctx **ctx);
    void (*close)(struct dongle_ctx *ctx);
    int  (*sign)(struct dongle_ctx *ctx, ...);     // 用狗里的私钥签名
    int  (*get_pubkey)(struct dongle_ctx *ctx,...); // 拿出狗的公钥
    int  (*get_serial)(...);        // 读狗序列号
    ...
};
```

有几种**后端**实现同一套接口，都是**插件**——编译成独立的 `.so`，
CA 在运行时从插件目录 `dlopen` 加载，所以"换后端不用重编 CA"：

| 形态 | 文件 / 产物 | 私钥在哪 | 用在哪 |
|------|------|---------|--------|
| **本地软狗** | `dongle_dummy.c` → `dummy.so` | 设备上一个密钥文件：`<插件目录>/dummy.key` | 开发 / CI / 离线测试 |
| **远程签名狗** | `dongle_remote.c` → `remote.so` | **远端**（上位机 / 云端）；设备只持 SSH 身份 | **生产 / 现场售后** |
| （预留）YubiKey | `dongle_yubikey.c` | 狗内硬件 | 源码保留，**当前不在任何构建中** |
| 加载器 | `dongle_factory.c` | — | 扫描插件目录、`dlopen`、ABI 校验 |

> **"插狗"在软狗上是什么意思**：把 `.so`（驱动）和配套 `.key`（狗内私钥）
> 放进插件目录（默认 `/usr/lib/tbox/dongle/`）——**放进去 = 插入，拿走 = 拔出**。
> 远程形态则不需要设备上有 `.key`：私钥始终留在远端。

> 说人话：**同一套"拿狗签名、取狗公钥"的代码，底下接的可以是本地文件、
> 也可以是一台远端服务器**——业务代码（CA、TA）完全不用改。

### 1.6.3 SO 解锁的完整流程（两阶段握手）

一次售后解锁，TA 侧的状态机会这样走：

```
UNSET ──灌SO-PIN──▶ PROVISIONED ──正常使用/出问题──▶ LOCKED ──解锁──▶ UNLOCKED ──再锁──▶ LOCKED
  │                    │                                    ▲
  └──────── 累计 1000 次 SO-PIN 错误 ────────────────────────┴──▶ BRICKED（永久锁死，彻底报废）
```

对应 CLI 和命令（真实命令）：

```bash
# ① 灌装阶段（只能一次）：设 SO-PIN
optee_example_tbox_keystore --init-so-pin <hex>

# ② 灌装阶段：把某只狗的"公钥"登记进 TA 白名单（可重复，用于多只狗）
optee_example_tbox_keystore --provision-dongle --dongle dummy
#    或从文件登记（远程签名狗就是走这条：先取回它的公钥 DER）：
optee_example_tbox_keystore --provision-dongle-from-file <pub.der>

# ③ 售后：要解锁时
optee_example_tbox_keystore --so-unlock --so-pin <hex> --dongle dummy
#    远程形态则用 --dongle remote
#    维护完记得收尾：--so-lock
```

TA 内部（`so_pin_mgr.c` 的 `CMD_SO_UNLOCK_REQ` / `CMD_SO_UNLOCK_CONFIRM`）实际做的是**挑战-应答**：

1. **Phase 1**：CA 把 SO-PIN 交给 TA 验 → TA 回一个随机 `challenge`（一次性，防重放）。
2. CA 把 challenge 拿给 dongle：**用狗里的私钥对 challenge 签名**。
3. **Phase 2**：CA 把"狗的公钥 + 狗的签名"交回 TA → TA 验签 → 验白名单 → 全过才 `UNLOCKED`。

错误处理（真实逻辑）：
- 连续 **3 次** SO-PIN 错 → 进入 **60 秒冷却**（防在线爆破）。
- 累计 **1000 次**错 → **永久 BRICKED**，这颗 TA 彻底报废（比锁死更狠，救不回来）。

> 一句话理解这套双因子：**就算有人偷到 SO-PIN，没有白名单里那只狗，照样解不开锁；就算有人偷到狗，不知道 SO-PIN 也白搭。**

### 1.6.4 验签到底在哪验？——**现在是在 TA 里验的**（缺口已闭合）

这里有一段演进史（详见 docs/28 的缺口分析、docs/30 的调试记录）：

- OP-TEE **3.2** 不支持 ECDSA transient object——TA 里一旦
  `TEE_AllocateTransientObject(TEE_TYPE_ECDSA_*)` 直接 **panic**（docs/30）。
- 而 YubiKey 出厂自带的狗钥匙恰好是 **ECDSA P-256**。所以**早期**方案里
  "TA 内验 dongle 签名"根本做不了，只能把验签挪到 **CA 侧**（REE，不可信）。
  那时的 `CMD_SO_UNLOCK_CONFIRM` 是个**无参空壳**，只检查"Phase 1 是否成功过"——
  **攻击者替换 CA 就能绕过狗**。这是一个被坦诚记录下来的安全缺口（docs/28）。
- ✅ **现在（已实施）**：密钥改用 **RSA-2048**（OP-TEE 3.2 原生支持），
  TA 在 `so_unlock_confirm()` 内**原子完成**「RSA 验签 ∧ 白名单匹配」；
  CA 只负责把「狗的公钥 + 狗的签名」递进去，**不参与任何判定**。

**一句话判据**：改造后，即使 CA 被替换、攻击者也知道 SO-PIN，
只要没有白名单里的那只狗，TA 一律拒绝 → **缺口闭合**。

> 实现见 `ta/so_pin_mgr.c` 的 `so_unlock_confirm()` 与 `ta/crypto_ops.c` 的
> `rsa_import_pubkey_from_der()`；设计见 docs/32 §8；RSA 版完整方案 docs/29。

## 1.7 钥匙管理全景小结（依赖关系图）

```
钥匙的一生：
  出厂 ──init-pin──▶ 解锁"能干活"
       ──gen-rsa/gen-aes + 权限──▶ 造出钥匙（禁止覆盖,存安全存储）
       ──lock──▶ 写死（gen/delete 全禁）
  售后 ──SO-PIN + dongle 双因子──▶ 临时 UNLOCKED（才能改）
        ──so-lock──▶ 再锁回去
        ──1000次错──▶ BRICKED（报废）

涉及的模块（谁依赖谁）：
  host/keystore_client.c (CLI 入口)
     ├─▶ libteec ──▶ ta/entry.c（命令分发 + 门禁）
     │                   ├─▶ ta/pin_mgr.c    普通 PIN
     │                   ├─▶ ta/so_pin_mgr.c SO-PIN/解锁/白名单/状态机
     │                   │      └─▶ ta/crypto_ops.c  rsa_import_pubkey_from_der()
     │                   ├─▶ ta/keystore.c   持久化密钥(安全存储)
     │                   └─▶ ta/acl.c + ta/crypto_ops.c  权限 + 运算
     └─▶ dongle/dongle_factory.c（插件加载器，**链进 CA**）
             └─ dlopen ──▶ dongle/dummy.so      本地软狗（<插件目录>/dummy.key）
                       └─▶ dongle/remote.so     远程签名狗（SSH 到上位机/云端）
                       两个插件都只实现 dongle_ops.h 那套接口，对 CA 零依赖
```

---

# 第二部分：HTTPS / MQTTS 的安全能力是怎么来的

## 2.1 先搞懂"TLS 双向认证"要什么

HTTPS、MQTTS 的"安全"本质都是 **TLS**。TLS 双向认证（mutual TLS, mTLS）要求：

- **服务端**有一对 私钥+证书（证明"我是服务器"）；
- **客户端**也有一对 私钥+证书（证明"我是合法设备"）；
- 握手时**双方都要用自己的私钥做一次签名**（CertificateVerify），对方拿你的证书里的公钥验。

问题来了：**如果私钥是普通文件，谁拷走谁就是"合法设备"。** 我们的做法是——私钥不放文件，放 TA（第 1 部分讲的钥匙），TLS 握手里那一下签名，走到 TA 里做。这样就算整个 REE 被攻破，**攻击者也伪造不了设备的身份**，因为签名的私钥他永远拿不到。

## 2.2 关键部件：OpenSSL ENGINE（`e_tbox_keystore.c`）

OpenSSL 默认用软件实现 RSA（私钥在内存里算）。我们写了一个 **ENGINE**（源码 `engine/e_tbox_keystore.c`，编译出 `libengkeystore.so`），作用是**把 OpenSSL 的 RSA 运算"截胡"下来，转手发给 TA**：

```
OpenSSL 要 rsa_sign / rsa_verify / rsa_priv_dec
        │
        ▼
e_tbox_keystore ENGINE（拿到的是一个"钥匙标签 label"，不是私钥）
        │  TEEC_InvokeCommand(CMD_SIGN, label, data, ...)
        ▼
TA：按 label 找到那把锁在安全存储里的真私钥 → 算 → 把结果还给 OpenSSL
```

关键点：**ENGINE 手里只有公钥 + 标签字符串**，没有私钥。私钥一次都没出过安全世界。

对外它只暴露一个函数，所有例子都是靠它接进来的：

```c
extern int ENGINE_load_tbox_keystore(void);   // 注册 ENGINE 到 OpenSSL
```

## 2.3 证书呢？证书是公开的，放文件

TLS 要"验"对方，靠的是**证书（cert）**。证书里只有**公钥**和身份信息，是公开数据，**可以放文件、不怕被看**。真正值钱的是证书对应的**私钥**——它在 TA 里。

所以每个角色通常是：**证书放 `/tmp/xxx.crt`（公开），私钥放 TA（安全）**，靠 ENGINE 把两者"对上"。

这套机制在不同示例里有两种证书组织方式：

### 方式一：自签名、两两互认（`tls_mutual_auth` / `https_client` 早期）
服务端、客户端各一份自签名证书，双方把对方证书当 CA 信任。适合演示、快速验证。
```
server-key (TA) ──自签──▶ /tmp/tbox-server.crt
client-key (TA) ──自签──▶ /tmp/tbox-client.crt
双方互相 load_verify_locations 对方的证书
```

### 方式二：一根 Root CA 往下签（`mqtts`，生产推荐）
根 CA 只签 broker 和设备，设备只信根 CA——这才是标准公钥基础设施。
```
Root CA (root-ca.crt, 自签名, 放设备当信任锚)
  ├── 签发 broker.crt  → EMQX Broker    （broker 的私钥在 broker 那，软件密钥）
  ├── 签发 pub.crt     → mqtts_pub       （pub-key  私钥在 TA）
  └── 签发 sub.crt     → mqtts_sub       （sub-key  私钥在 TA）
```
设备验 broker、broker 验设备，最终都归结到"信不信那根根 CA"。

## 2.4 HTTPS：`https_client` 这个例子

`examples/https_client/https_client.c`，一个标准的 OpenSSL HTTPS 客户端，但私钥走 ENGINE：

```c
ENGINE_load_tbox_keystore();                    // ① 注册 ENGINE
ENGINE *e = ENGINE_by_id("tbox_keystore");
EVP_PKEY *pkey = ENGINE_load_private_key(e, "client-key", ...); // ② 从 TA 拿 client-key
SSL_CTX_use_PrivateKey(ctx, pkey);              // ③ 告诉 OpenSSL 我的私钥在这
SSL_CTX_use_certificate_file(ctx, "client.crt"); // ④ 我的证书（公开）
SSL_CTX_load_verify_locations(ctx, "server-sw.crt"); // ⑤ 信任对端
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL); // ⑥ 强制双向
```

**依赖链**：`https_client` → `libengkeystore.so`（ENGINE）→ `libteec` → TA。
配套场景：服务器那头可以就是一个 `openssl s_server`（软件密钥），验客户端时照样验得过——因为验的是客户端**证书里的公钥**，而签名是 TA 用真私钥做的。

## 2.5 MQTTS：`mqtts_pub` / `mqtts_sub` 这个例子

MQTT 本身不加密，MQTTS = MQTT over TLS。难点在 **paho.mqtt.c 这个库**：它把 TLS 配置写死在内部，不让你方便地插 ENGINE。所以我们给 paho 打了一个小补丁（`examples/mqtts/paho_patch/`），加了 `SSLSocket_setExternalConfigCallback` 回调，让 paho 在创建 TLS 上下文时把控制权交出来。

```
mqtts_pub / mqtts_sub
    │  (paho.mqtt.c 1.3.16, 打了补丁)
    ▼
SSLSocket 检测到特殊标记 → 调外部回调
    ▼
ssl_config.c 的 tbox_ssl_config_ex(ctx, "pub-key"|"sub-key", "/tmp/pub.crt"|"/tmp/sub.crt")
    │   实际做的是和 2.4 一样的事：
    │   ENGINE 加载 TA 私钥 + 挂证书 + 信任 root-ca + 强制双向
    ▼
连上 EMQX Broker（双向 TLS）
```

两个进程（发布、订阅）用**两把不同的 TA 钥匙**（`pub-key`、`sub-key`），这里有个现实原因：**OP-TEE 3.2 的 REE 文件系统对同一把持久化对象的并发访问会冲突**，两个进程各用各的钥匙就绕开了（详见 docs/16）。

**依赖链**：`mqtts_pub/sub` → `paho.mqtt.c`（带补丁）→ `ssl_config.c` → `libengkeystore.so` → `libteec` → TA。broker 侧用 EMQX，配双向认证 + 信任根 CA。

## 2.6 底层能力的调用（第 1、2 部分怎么接上的）

ENGINE 里那些 `CMD_SIGN/CMD_VERIFY/CMD_RSA_DECRYPT`，最终都由 TA 的 `crypto_ops.c` 用安全世界的密码学引擎完成。而同样的"签名/验签"能力，还有更底层的文件级示例：
- `examples/rsa/rsa_crypt.c`：对文件 SHA-256 后 RSA-2048 签名/验签（可测每秒能签多少次）。
- `examples/aes/aes_crypt.c`：对任意大小文件 AES-CBC 加解密（含 PKCS#7、IV 可选零/随机）。

它们共用同一套 TA 命令，只是入口更底层、不经过 TLS。

---

## 3. 一张图串起全部依赖

```
                        业务层
   https_client   mqtts_pub   mqtts_sub   tls_mutual_auth
        │            │            │             │
        │      paho.mqtt.c(带补丁)│             │
        └─────────── ssl_config.c ──────────────┘   （mqtts 专用注入层）
                        │
                        ▼
            ┌────────────────────────┐
            │ OpenSSL + ENGINE       │  libengkeystore.so
            │ (libengkeystore.so)    │  ── 只认 label, 无私钥
            └───────────┬────────────┘
                        │ TEEC_InvokeCommand(CMD_SIGN/VERIFY/RSA_DECRYPT, label, …)
                        ▼
            ┌────────────────────────┐
            │ libteec (TEE Client)   │
            └───────────┬────────────┘
                        ▼
            ┌────────────────────────┐
            │  tbox_keystore TA      │  私钥在安全存储,永不出安全世界
            │  entry.c / keystore.c │
            │  pin_mgr/so_pin_mgr   │  ← 1.3~1.6 的门禁全在这
            │  acl.c / crypto_ops.c │
            └────────────────────────┘

  密钥来源：host/keystore_client.c (CLI) 造钥匙、灌 PIN、lock
            dongle/ (dongle 子系统，插件) 解锁用：
              dummy.so   本地软狗（开发/CI）
              remote.so  远程签名狗（生产/现场，私钥在远端）
```

**三句话总结：**
1. **钥匙**在 TA 里被三层看管：普通 PIN（不许空机器干活）、禁止覆盖 + 出厂 lock（不许事后塞/换钥匙）、SO-PIN + dongle 双因子（换钥匙只能安全官来，且要验白名单）。
2. **安全能力** = 把 TLS 握手里"用私钥签名"的那一步，通过 OpenSSL ENGINE 转发进 TA，用 TA 里锁着的真私钥完成，私钥全程不落地。
3. **所有示例**共用同一条 TA 命令通道，只是入口不同：TLS 走 ENGINE，底层直接走 libteec；真机钥匙用 YubiKey，开发用 dummy。

---

## 相关文档

- 架构总览：[01-architecture-overview.md](01-architecture-overview.md)
- 密钥存储机制：[05-key-storage.md](05-key-storage.md)
- PIN 管理：[09-pin-management.md](09-pin-management.md)
- ENGINE 集成（TLS 那条链路）：[13-openssl-engine-integration.md](13-openssl-engine-integration.md)
- HTTPS 客户端示例：[17-https-client-demo.md](17-https-client-demo.md) / `examples/https_client/`
- MQTTS 双向认证示例：[18-mqtt-mutual-auth-demo.md](18-mqtt-mutual-auth-demo.md) / [20-mqtts-debug-issues.md](20-mqtts-debug-issues.md) / `examples/mqtts/`
- 多进程并发问题：[16-multi-process-concurrency-analysis.md](16-multi-process-concurrency-analysis.md)
- **dongle 可插拔的完整设计（本地软狗 + 远程签名狗）**：[32-dongle-plugin-architecture.md](32-dongle-plugin-architecture.md)
- SO-PIN + dongle 设计（ECDSA 版历史）：[24-so-pin-yubikey-unlock.md](24-so-pin-yubikey-unlock.md)
- **安全缺口的历史分析**（该缺口现已闭合，本文 §1.6.4）：[28-yubikey-full-lifecycle.md](28-yubikey-full-lifecycle.md)
- RSA-2048 方案（**已实施**，TA 内原子验签）：[29-rsa-yubikey-provisioning.md](29-rsa-yubikey-provisioning.md)
- TA 不支持 ECDSA P-256 验签的调试记录：[30-ecc-p256-ta-unsupported-debug-log.md](30-ecc-p256-ta-unsupported-debug-log.md)
- 产品说明书：[21-product-manual.md](21-product-manual.md)
