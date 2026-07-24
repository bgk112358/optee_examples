# MQTTS 双向认证调试问题全记录

> **目标**：基于 tbox_keystore ENGINE 实现 MQTTS 客户端，通过 paho.mqtt.c 连接 EMQX Broker，完成 CA 链式双向 TLS 认证。
>
> **环境**：OP-TEE 3.2 + OpenSSL 1.1.1b + paho.mqtt.c 1.3.16 + ARM aarch64
>
> **状态**：ENGINE 回调链路已通 ✅ — SSL_connect 证书验签待解决（Broker 证书与 CA 不匹配）

---

## 一、整体方案

### 1.1 架构选型：借鉴 HSM 芯片参考架构

参考 BYD T-Box 项目的 HSM SDK（[19-hsm-chip-reference-architecture.md](19-hsm-chip-reference-architecture.md)），其核心设计是：

```
应用 → paho.mqtt.c (打补丁: SSLSocket_setExternalConfigCallback)
     → ConfigSSLWithHsm(ctx) → HSM ENGINE → 芯片私钥操作
```

我们复用同样的模式，将 HSM 替换为 OP-TEE TA：

```
应用 → paho.mqtt.c (打补丁: SSLSocket_setExternalConfigCallback)
     → tbox_ssl_config(ctx) → e_tbox_keystore ENGINE → TEEC → TA
```

### 1.2 证书模型

采用标准 CA 链式信任模型（区别于早期 demo 的自签名双向锚定）：

```
Root CA (root-ca.crt, 自签名)
  ├── 签发 broker.crt   → EMQX Broker   (软件私钥)
  ├── 签发 pub.crt      → mqtts_pub      (pub-key, TA 内)
  └── 签发 sub.crt      → mqtts_sub      (sub-key, TA 内)
```

pub 和 sub 各自独立的 TA 密钥，避开 OP-TEE 3.2 跨进程并发限制。

---

## 二、实现过程

### 2.1 paho 源码补丁

参考架构中 paho 被打了一个补丁：新增 `SSLSocket_setExternalConfigCallback`，当 `MQTTClient_SSLOptions.privateKey == "__EXTERNAL_CONFIG__"` 时，paho 不读文件而调用外部回调。

改动三个文件：

| 文件 | 改动内容 |
|------|----------|
| `src/SSLSocket.c` | ① 全局 `g_ssl_ext_cb` + setter 实现 ② `SSLSocket_createContext` 中检测 `__EXTERNAL_CONFIG__` 触发回调 |
| `src/SSLSocket.h` | 回调类型声明（引用 `SSLSocketConfig.h`） |
| `src/SSLSocketConfig.h` | 新建公开头文件 —— 仅含 callback typedef + setter 声明，无内部依赖 |

### 2.2 公开头文件分离

`SSLSocket.h` 内部引用了 `SocketBuffer.h`、`Clients.h` 等 paho 私有头文件，不能直接安装给外部使用。新建 `SSLSocketConfig.h` 作为最小的公开头文件，只暴露：

```c
#include <openssl/ssl.h>
typedef int (*SSLSocket_externalConfigCallback)(SSL_CTX *ctx);
void SSLSocket_setExternalConfigCallback(SSLSocket_externalConfigCallback cb);
```

### 2.3 CMake 安装规则

paho 原有 `make install` 不安装任何头文件。修改 `src/CMakeLists.txt`：

```cmake
# 公开头文件
install(FILES MQTTClient.h MQTTAsync.h ... DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# 补丁公开头文件
install(FILES SSLSocketConfig.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/paho)
```

### 2.4 SSL 配置回调实现

`mqtts/ssl_config.c` 实现 `tbox_ssl_config_ex(ctx, key_label, cert_file)`：

1. `ENGINE_load_tbox_keystore()` → 注册 ENGINE
2. `ENGINE_load_private_key(key_label)` → 从 TA 加载私钥
3. `SSL_CTX_use_certificate_file(cert_file)` → 加载设备证书
4. `SSL_CTX_load_verify_locations(root-ca.crt)` → 加载信任锚

---

## 三、部署过程

### 3.1 构建链

```
three_part/openssl/out          ← OpenSSL 1.1.1b (交叉编译)
three_part/mqtt/out             ← paho.mqtt.c (带补丁)
engine/build/libe_tbox_keystore.so ← ENGINE 实现
mqtts/build/                    ← MQTTS 客户端程序
```

### 3.2 设备端部署

```bash
# 1. 灌装 TA 密钥
rm -rf /data/tee/*
./test/mqtt_ta_setup_keys.sh       → pub-key + sub-key

# 2. 生成证书
./test/mqtt_gen_certs.sh           → root-ca.crt, broker.crt, pub.crt, sub.crt

# 3. 部署 so 文件
cp libe_tbox_keystore.so /usr/lib/
cp libpaho-mqtt3cs.so* /usr/lib/

# 4. 配置 EMQX + 部署 Broker 证书

# 5. 运行测试
./test/mqtt_run_test.sh
```

---

## 四、问题全记录

### 问题 1：paho 源码头文件安装缺失

**现象**
```
fatal error: paho/SSLSocket.h: No such file or directory
```

**原因**
paho 的 `make install` 只安装 `.so` 和 cmake config，不安装任何头文件。`SSLSocket.h` 是内部头文件，更不会自动安装。

**解决**
修改 paho `src/CMakeLists.txt`，添加 `install(FILES ...)` 规则：公开头文件安装到 `include/`，`SSLSocketConfig.h`（仅对外暴露 callback 类型）安装到 `include/paho/`。

---

### 问题 2：SSLSocket.h 内部依赖导致编译失败

**现象**
```
fatal error: SocketBuffer.h: No such file or directory
```

**原因**
直接安装 `SSLSocket.h` 会导致它依赖的 `SocketBuffer.h`、`Clients.h` 等内部头文件全部需要暴露。

**解决**
新建 `SSLSocketConfig.h`，只放 callback typedef + setter 声明，不依赖任何内部头文件。

---

### 问题 3：SSLSocket_setExternalConfigCallback 符号未导出

**现象**
```
undefined reference to `SSLSocket_setExternalConfigCallback'
```

**原因**
`SSLSocket_setExternalConfigCallback` 定义在 `SSLSocket.c` 中，编译到 `libpaho-mqtt3cs.so` 时因默认 visibility 而被隐藏（`nm` 显示为 `t` — local symbol）。

**解决**
添加 `__attribute__((visibility("default")))` 强制导出：

```c
__attribute__((visibility("default")))
void SSLSocket_setExternalConfigCallback(SSLSocket_externalConfigCallback cb)
```

---

### 问题 4：设备端 paho 库版本不匹配

**现象**
```
/usr/bin/mqtts_pub: symbol lookup error: undefined symbol: SSLSocket_setExternalConfigCallback
```

**原因**
设备上 `/usr/lib/libpaho-mqtt3cs.so` 是旧版本（不带补丁）。编译时链接的是 `three_part/mqtt/out/lib/` 下的新版本，但运行时加载了旧版本。

**解决**
将带补丁的 `libpaho-mqtt3cs.so*` 部署到设备 `/usr/lib/`，覆盖旧版本。

---

### 问题 5：QEMU 网络不通

**现象**
```
MQTTClient_connect: rc=-1 (Failure)
```
telnet 无法连接外部 IP。

**原因**
QEMU user-mode 网络下，SLiRP 栈默认允许 guest 访问外网，但 hostfwd 需要单独配置。host 上 EMQX 绑定了特定 IP 时 guest 无法直达。

**解决**
在 `qemu_v8.mk:492` 添加端口转发：

```makefile
-net user,hostfwd=tcp::28883-192.168.100.48:8883 \
```

---

### 问题 6：paho 回调从未被调用（关键 bug）

**现象**
TCP 连通、paho TCP 模式可 CONNECT，但 SSL 模式下 `SSLSocket_createContext` 打出了 `createContext ENTER`，`ssl_config: ENTER` 却从未出现。

**原因**
补丁代码被放在 `if (opts->keyStore)` 块**内部**（第 614 行）。不设置 `keyStore` 时整个私钥处理块跳过，callback 永远不会触发。

**代码病灶**
```c
if (opts->keyStore)                          // ← 我们没设 keyStore
{
    // ... 证书链加载 ...
    if (g_ssl_ext_cb && ...)                 // ← 补丁代码在这里
    {
        rc = g_ssl_ext_cb(net->ctx);         // ← 永远不会执行
    }
}
```

**解决**
将 callback 检查从 `if (opts->keyStore)` 内部移出，改为独立 `else if`：

```c
if (opts->keyStore)
{
    // 原生路径：从文件加载证书
}
else if (g_ssl_ext_cb &&
         strcmp(opts->privateKey, "__EXTERNAL_CONFIG__") == 0)
{
    // 外部配置路径：调 callback 注入 ENGINE 凭据
    rc = g_ssl_ext_cb(net->ctx);
}
```

---

### 问题 7：TLS 握手 — 证书验证失败（当前问题）

**现象**
```
SSL_connect FAIL
error:0407008A:rsa routines:RSA_padding_check_PKCS1_type_1:invalid padding
error:1416F086:SSL routines:tls_process_server_certificate:certificate verify failed
```

**原因**
客户端持有的 `root-ca.crt` 与签发 EMQX `broker.crt` 的 CA 不是同一个。EMQX 上可能使用了自行生成的 broker 证书。

**解决方向**
确认 `broker.crt` 的 Issuer 与 `root-ca.crt` 的 Subject 一致。如果不一致，用 `mqtt_gen_certs.sh` 重新生成所有证书并统一部署。

---

## 五、验证流水线

```bash
# 1. TCP 层
telnet <broker> 8883                          # 必须显示 Connected

# 2. paho TCP 层
tcpprobe_mqtt <broker> 1883                   # 必须显示 CONNECT OK

# 3. ENGINE 回调
# 查看日志：ssl_config: ENTER + OK            # 必须出现

# 4. TLS 握手
# 查看日志：SSL_connect rc=1                  # 必须成功

# 5. 端到端
./mqtt_run_test.sh                            # 全部 PASS
```

---

## 六、paho 补丁要点总结

| 序号 | 改动 | 位置 | 行数 |
|:---:|------|------|:---:|
| 1 | 回调类型 + setter 声明 | `SSLSocketConfig.h` | 新增文件 |
| 2 | `#include "SSLSocketConfig.h"` | `SSLSocket.h` | 1 行 |
| 3 | 全局 g_ssl_ext_cb + setter 实现 | `SSLSocket.c` | ~10 行 |
| 4 | 独立 `else if` 分支触发回调 | `SSLSocket.c` | ~10 行 |
| 5 | `__attribute__((visibility("default")))` | `SSLSocket.c` | 1 行 |
| 6 | 头文件 install 规则 | `CMakeLists.txt` | 2 行 |

---

## 七、关键文件清单

| 文件 | 说明 |
|------|------|
| `three_part/mqtt/paho.mqtt.c-1.3.16/src/SSLSocketConfig.h` | 公开回调头文件（新增） |
| `three_part/mqtt/paho.mqtt.c-1.3.16/src/SSLSocket.c` | 补丁核心（回调 + else if） |
| `three_part/mqtt/paho.mqtt.c-1.3.16/src/SSLSocket.h` | 引用 SSLSocketConfig.h |
| `three_part/mqtt/paho.mqtt.c-1.3.16/src/CMakeLists.txt` | 头文件 install 规则 |
| `mqtts/ssl_config.c` | ENGINE 凭据注入实现 |
| `mqtts/ssl_config.h` | tbox_ssl_config_pub/sub 包装 |
| `mqtts/mqtts_pub.c` | 发布者（调用 SSLSocket_setExternalConfigCallback） |
| `mqtts/mqtts_sub.c` | 订阅者 |
| `mqtts/gen_csr.c` | CSR 生成器（ENGINE 签名） |
| `mqtts/test/mqtt_gen_certs.sh` | CA + 证书编排生成 |
| `qemu_v8.mk:492` | QEMU 端口转发 (`-net user,hostfwd=...`) |
