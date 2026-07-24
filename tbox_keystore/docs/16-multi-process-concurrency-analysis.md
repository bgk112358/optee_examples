# 多进程并发访问 TEE 安全存储的方案分析

> **背景**：当前 tbox_keystore TA 在 OP-TEE 3.2 的 REE FS 后端下，同一时刻只有一个进程能正常访问持久化对象。问题 #8（同 session reopen）和问题 #11（跨进程冲突）暴露了这个限制。真实产线场景中，TLS 服务、OTA 服务、日志加密服务等多个业务可能同时需要 TEE 密钥操作。
>
> **核心矛盾**：OP-TEE 3.2 REE FS 对持久化对象的并发访问支持不完善——同一对象在同一会话内不能 reopen，不同会话之间也不能同时 open。

---

## 一、问题本质

### 1.1 三条并发限制

```
限制 A：同 session 内同一对象 close → reopen 失败
  现象：CMD_KEY_EXPORT_PUB 打开→关闭对象后，CMD_SIGN 打开同一对象被拒
  错误：TEE_ERROR_ACCESS_CONFLICT (0xffff0003)
  状态：✅ 已通过 session 缓存规避

限制 B：不同 session（同进程）同时持有同一对象失败
  现象：单进程内，两个 ENGINE 实例各开一个 TEEC 会话，第二个会话打不开对象
  状态：❓ 未测试（当前每个进程只有一个 ENGINE 实例）

限制 C：不同 session（不同进程）同时持有同一对象失败
  现象：server 进程的 session 持有 client-key 对象后，client 进程的 session 打不开
  错误：TEE_ERROR_ITEM_NOT_FOUND (0xffff0008)
  状态：⚠️ 当前通过"每个进程只操作自己的 key"绕开，但限制真实并发能力
```

### 1.2 根因分析

OP-TEE 3.2 的 `tee_ree_fs.c`（REE FS 后端）在实现上存在以下问题：

- `TEE_OpenPersistentObject` 打开文件后，文件描述符的元数据（访问模式、锁状态）没有在 `TEE_CloseObject` 后正确重置
- 不同 TEEC 会话之间缺少对象访问的协调机制
- REE FS 依赖 Linux 文件系统但不使用标准文件锁（flock/fcntl），而是依赖 OP-TEE 内部的 handle 状态机
- RPMB 后端同样受影响——GP TEE 规范没有定义跨会话的持久化对象共享语义

---

## 二、方案对比总表

| 方案 | 并发能力 | 改动量 | 安全性 | 推荐度 |
|------|:---:|:---:|:---:|:---:|
| A. TA 内 session 缓存 | ★★ | 低（已实现） | 不降低 | ⭐⭐⭐⭐⭐ |
| B. 代理守护进程 | ★★★★ | 中 | 需额外保护 IPC | ⭐⭐⭐⭐ |
| C. 升级到 RPMB FS | ★★ | 低 | 提升 | ⭐⭐⭐ |
| D. 多 key 副本 | ★★★ | 低 | 不降低 | ⭐⭐⭐ |
| E. 升级 OP-TEE 版本 | ★★★★★ | 高 | 随版本提升 | ⭐⭐⭐ |
| F. libteec 会话池（共享内存） | ★★★ | 中 | 复杂 | ⭐⭐ |

---

## 三、方案详细分析

### 方案 A：TA 内 session 级缓存（当前已实现，增强版）

**原理**

当前已实现 session 读缓存（`g_cache[CACHE_SLOTS]`），但每个 session 仍独立访问持久化存储。增强方向：将缓存从"只读缓存"扩展为"session 内预加载"，在会话打开时一次性加载所有需要访问的 key，之后永不触动持久化对象。

**实现**

```c
/* TA_OpenSessionEntryPoint 新增：预加载清单 */
static void preload_keys(void)
{
    static const char *preload_list[] = {
        "server-key", "client-key", "ota-key", "tls-key",
        "enc-key", NULL
    };
    for (int i = 0; preload_list[i]; i++) {
        uint8_t *data = NULL;
        size_t len = 0;
        if (keystore_read((const uint8_t *)preload_list[i],
                          strlen(preload_list[i]), &data, &len) == TEE_SUCCESS) {
            TEE_Free(data); // cache holds a copy already
        }
    }
}
```

**优点**：改动最小，已经在当前架构下工作
**缺点**：仍受限制 C 影响——如果两个进程的 session 都预加载了同一个 key，第二个 session 的预加载会失败（相同对象不能跨 session open）

**结论**：解决了限制 A，不解决限制 C。适合"每个进程只用自己的 key"的场景（当前状态）。

---

### 方案 B：密钥操作代理守护进程（Key Agent Daemon）

**原理**

一个专门的守护进程持有唯一的 TEEC 会话，所有其他业务进程通过本地 IPC（Unix domain socket / D-Bus / gRPC）向它请求密钥操作。

```
┌────────────┐  ┌────────────┐  ┌────────────┐
│ TLS 服务    │  │ OTA 服务    │  │ 日志服务    │
│ (REE)      │  │ (REE)      │  │ (REE)      │
└──────┬─────┘  └──────┬─────┘  └──────┬─────┘
       │               │               │
       │  本地 IPC (Unix Socket / D-Bus)│
       │               │               │
       └───────────────┼───────────────┘
                       ▼
            ┌─────────────────────┐
            │  tbox_keyd          │  ← 唯一 TEEC 会话持有者
            │  (REE 守护进程)      │
            │                     │
            │  • 序列化请求队列    │
            │  • 权限校验 (UID/PID)│
            │  • 审计日志          │
            └──────────┬──────────┘
                       │ TEEC_InvokeCommand
                       ▼
            ┌─────────────────────┐
            │  tbox_keystore TA   │  ← 单一 session
            │  (Secure World)     │
            └─────────────────────┘
```

**IPC 命令设计**

```c
struct keyd_request {
    uint32_t cmd;          // CMD_SIGN / CMD_VERIFY / CMD_RSA_DECRYPT / ...
    uint32_t flags;
    char     label[64];    // key label
    uint32_t in_len;
    uint32_t out_len;
    uint8_t  data[];       // in_len bytes input, out_len bytes output follow
};

struct keyd_response {
    int32_t  result;       // 0 = success
    uint32_t out_len;
    uint8_t  data[];       // output data
};
```

**守护进程代码骨架**

```c
/* tbox_keyd — Simplified key agent */
int main(void) {
    int listen_fd;
    struct sockaddr_un addr;

    /* 1. Init TEE — the only TEEC session in the system */
    TEEC_InitializeContext(NULL, &ctx);
    TEEC_OpenSession(&ctx, &sess, &TA_TBOX_KEYSTORE_UUID,
                     TEEC_LOGIN_PUBLIC, NULL, NULL, NULL);

    /* 2. Listen on Unix socket with restricted permissions */
    listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, "/run/tbox_keyd.sock");
    bind(listen_fd, ...);
    chmod("/run/tbox_keyd.sock", 0660);   /* only root:tbox group */
    listen(listen_fd, 16);

    /* 3. Accept & serve */
    while (1) {
        int client = accept(listen_fd, ...);
        struct keyd_request req;
        recv(client, &req, sizeof(req), ...);
        /* Authenticate client via SO_PEERCRED */
        /* Execute TA command */
        /* Send response */
        close(client);
    }
}
```

**ENGINE 适配（每个业务进程仍用 ENGINE，内部走 IPC）**

```c
/* Modified e_tbox_keystore.c — IPC variant */
static int tee_start(void) {
    /* Instead of TEEC_OpenSession, connect to keyd socket */
    g_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    connect(g_fd, &addr, sizeof(addr));
    return (g_fd >= 0);
}

static int tee_cmd(uint32_t cmd, TEEC_Operation *op) {
    /* Serialize TEEC_Operation → keyd_request → send → recv → deserialize */
    struct keyd_request req;
    req.cmd = cmd;
    memcpy(req.label, op->params[0].tmpref.buffer, ...);
    /* ... */
    send(g_fd, &req, sizeof(req), 0);
    recv(g_fd, &resp, sizeof(resp), 0);
    /* ... */
}
```

**代理守护进程的安全加固**

| 措施 | 说明 |
|------|------|
| Unix socket 权限 | `0660` + `root:tbox` 组，只有授权进程可连接 |
| SO_PEERCRED 验证 | 校验连接方的 UID/GID/PID |
| label 白名单 | 每个 UID 只能访问其授权 label 列表 |
| 速率限制 | 防止 fork 炸弹耗尽 TA 资源 |
| 审计日志 | 每个请求记录 (timestamp, UID, cmd, label, result) |

**优点**
- 彻底解决跨进程并发冲突——只有一个 TEEC 会话
- 权限模型清晰可控
- 支持审计和速率限制
- 业务进程无需直接依赖 libteec

**缺点**
- IPC 增加 ~0.5-1ms 延迟
- 守护进程成为单点故障（可加固）
- ENGINE 需要 IPC 适配层

**结论**：⭐ 生产环境的最佳方案。虽然增加 IPC 延迟，但换来完整的并发能力和安全审计。

---

### 方案 C：升级到 RPMB FS

**原理**

RPMB（Replay Protected Memory Block）是 eMMC 的安全分区，通过 HMAC 认证写操作。在并发场景下，RPMB 驱动在 OP-TEE Core 层面串行化所有访问。

**对比分析**

| 特性 | REE FS | RPMB FS |
|------|--------|---------|
| 并发 open 同一对象 | ❌ 已知问题 | ⚠️ 理论上 GP 规范允许，实际待测 |
| 跨进程访问 | ❌ 已知失败 | ⚠️ 不明确，但 RPMB 有硬件级请求串行化 |
| 防回滚 | ❌ | ✅ 硬件写计数器 |
| 性能 | ★★★★ | ★★（认证写开销 ~10ms） |
| 量产推荐 | 开发/原型 | ✅ 车规级 |

**关键不确定因素**

RPMB 是否能解决跨 session 并发打开同一对象的问题，取决于 OP-TEE 3.2 的 RPMB FS 实现。理论上 RPMB 请求在 OP-TEE Core 中被串行化，不会出现 REE FS 的文件描述符冲突。但 GP TEE 规范本身没有定义跨会话语义，需要实际测试验证。

**建议**：在 OP-TEE 3.2 中搭建 RPMB 测试环境，验证以下场景：
1. 同一 TA 的两个 session 同时 open 同一个持久化对象
2. 不同 TA 的两个 session 同时 open 各自的持久化对象
3. 一个 session open 对象 + 另一个 session 创建/删除对象

---

### 方案 D：多 key 副本策略

**原理**

为每个业务进程生成独立的密钥副本，不同 label 前缀隔离命名空间：

```bash
# 灌装时
tbox_keystore --gen-rsa tlsd-server-key --size 2048 --sign
tbox_keystore --gen-rsa otad-server-key --size 2048 --sign
tbox_keystore --gen-rsa logd-server-key --size 2048 --sign
```

每个守护进程 (tlsd/otad/logd) 只访问自己的 key，label 天然不冲突。

**优点**
- 改动为 0——当前架构天然支持
- 不同服务间的密钥互相隔离
- 一个 key 被泄露不影响其他服务

**缺点**
- 需要为每个服务签发不同的设备证书
- 密钥数量随业务线性增长（但存储开销很小，每个 key ~3KB）
- 不适用于"同一服务多实例"场景（如 nginx 多 worker 共享 key）

**结论**：对于"不同业务、不同 key"的场景，这是最简单但有效的方案。与方案 A 结合使用。

---

### 方案 E：升级 OP-TEE 版本

**原理**

OP-TEE 3.2 → 新版（如 4.x）中，REE FS 的实现持续被改进。GitHub 上可以看到 tee_ree_fs.c 从 3.2 到 4.x 经历了大重构，文件描述符管理和并发支持都有提升。

**改动量分析**

| 组件 | 需要升级 | 风险 |
|------|:---:|------|
| optee_os | ✅ | 平台移植工作量中等 |
| optee_client | ✅ | API 保持兼容 |
| Linux kernel OP-TEE driver | ⚠️ 可能需要 | 内核版本绑定 |
| TA 代码 | ❌ | GP API 向后兼容 |

**建议**：如果产品还在开发阶段，尽早升级到较新 OP-TEE 版本可以减少很多已知 bug。但如果硬件/内核已冻结，这可能不是短期选项。

---

### 方案 F：libteec 会话池（不推荐）

**原理**

在 libteec 层实现会话池——多个 REE 进程的 TEEC_OpenSession 不直接创建新 TA 实例，而是复用池中的已有会话。每个逻辑请求带上自己的上下文标识。

**为什么不可行**

- GP TEE 规范中 TEEC_Session 不允许跨进程共享（共享内存绑定到进程地址空间）
- OP-TEE 内核驱动为每个 TEEC_Session 分配独立的共享内存区域
- 实现需要修改内核驱动和 libteec，复杂度极高

---

## 四、推荐架构（组合方案）

```
┌─────────────────────────────────────────────────────────────────┐
│  生产环境分层架构                                                 │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                     │
│  │ nginx     │  │ ota-agent │  │ log-enc  │  ← 业务进程          │
│  │ (TLS)    │  │ (签名)    │  │ (加密)   │                     │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘                     │
│       │             │             │                             │
│       │ 本地 Unix Socket IPC      │                             │
│       │             │             │                             │
│       └─────────────┼─────────────┘                             │
│                     ▼                                           │
│  ┌──────────────────────────────────────┐                      │
│  │  tbox_keyd  (Key Agent Daemon)       │  ← 方案 B            │
│  │  • 唯一 TEEC 会话持有者               │                      │
│  │  • 请求队列 + 权限校验 + 审计          │                      │
│  │  • label 白名单: UID → [labels]       │                      │
│  └──────────────────┬───────────────────┘                      │
│                     │ TEEC_InvokeCommand                        │
│                     ▼                                           │
│  ┌──────────────────────────────────────┐                      │
│  │  tbox_keystore TA                    │  ← 方案 A + D        │
│  │  • Session 级预加载缓存               │                      │
│  │  • 多业务密钥隔离 (label 前缀)        │                      │
│  │  • CMD list: SIGN/VERIFY/DECRYPT/…   │                      │
│  └──────────────────────────────────────┘                      │
│                     │                                           │
│                     ▼                                           │
│  ┌──────────────────────────────────────┐                      │
│  │  Secure Storage (优先 RPMB)          │  ← 方案 C            │
│  └──────────────────────────────────────┘                      │
└─────────────────────────────────────────────────────────────────┘
```

### 分阶段落地

| 阶段 | 工作 | 适合场景 |
|:---:|------|------|
| **当前** | 方案 A + D（每进程自己的 key，session 缓存） | 开发验证、业务种类少的原型 |
| **Phase 1** | 实现 tbox_keyd 守护进程 + IPC ENGINE 适配层 | 多业务并发、需要审计的生产环境 |
| **Phase 2** | RPMB FS 迁移 + 压力测试 | 车规级量产 |
| **Phase 3** | OP-TEE 版本升级（如可行） | 长期维护策略 |

---

## 五、tbox_keyd IPC 协议设计

### 5.1 请求/响应格式

```c
/* Fixed header */
struct keyd_hdr {
    uint32_t magic;       /* 0x4B455944 "KEYD" */
    uint32_t version;     /* 1 */
    uint32_t cmd;         /* CMD_SIGN=5, CMD_VERIFY=6, CMD_RSA_DECRYPT=11, ... */
    uint32_t flags;
    uint32_t label_len;   /* ≤ 64 */
    uint32_t in_len;      /* input data length */
    uint32_t out_cap;     /* output buffer capacity */
    uint32_t reserved;
    /* followed by: label[label_len], in_data[in_len] */
};

struct keyd_resp {
    uint32_t magic;       /* 0x4B455944 */
    int32_t  result;      /* 0 = success, negative = GP TEE error */
    uint32_t out_len;     /* actual output length */
    uint32_t reserved;
    /* followed by: out_data[out_len] */
};
```

### 5.2 权限模型

```c
/* Label → UID whitelist */
static const struct {
    const char *label;
    uid_t       allowed_uid;
} g_acl[] = {
    { "tlsd-key",  80  },    /* nginx worker */
    { "otad-key",  1001 },   /* ota agent */
    { "logd-key",  1002 },   /* log encryptor */
    { NULL, 0 }
};
```

### 5.3 审计日志格式

```
2026-07-21T15:30:22Z uid=80 cmd=SIGN label=tlsd-key result=0 latency=3ms
2026-07-21T15:30:22Z uid=80 cmd=SIGN label=tlsd-key result=0 latency=2ms
2026-07-21T15:30:25Z uid=1001 cmd=RSA_DECRYPT label=otad-key result=0 latency=5ms
```

---

## 六、总结与建议

| 场景 | 推荐方案 | 原因 |
|------|----------|------|
| **不同业务不同 key**（当前 demo 状态） | A + D（已实现） | 零改动，满足需求 |
| **多个进程共享同一个 key**（TLS 多 worker） | B（tbox_keyd） | 唯一 TEEC 会话，解决跨进程冲突 |
| **生产安全审计要求** | B（tbox_keyd） | 权限校验 + 审计日志 |
| **车规级防回滚** | C（RPMB） | 硬件防回滚，满足 WP.29/ISO 21434 |
| **长期维护** | E（升级 OP-TEE） | 上游 bug 修复 + 安全更新 |

**当前立即可用**：方案 A + D，每个业务用自己的 key label。

**下一优先级**：实现方案 B（tbox_keyd），这是解决"多进程共享同一 key"的最有效方案，也是生产环境的标准架构。
