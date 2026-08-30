# MQTTS 双向认证 — TEE ENGINE + paho 客户端

## 概述

MQTTS 发布/订阅演示，通过 tbox_keystore ENGINE 使用 TA 内密钥与 EMQX Broker 完成 CA 链式 TLS 双向认证。paho.mqtt.c 经最小补丁后通过 `SSLSocket_setExternalConfigCallback` 回调注入 ENGINE 凭据。

## 架构

```
Root CA (root-ca.crt)
  ├── 签发 broker.crt  → EMQX Broker   (软件私钥)
  ├── 签发 pub.crt     → mqtts_pub      (pub-key, TA 内)
  └── 签发 sub.crt     → mqtts_sub      (sub-key, TA 内)
```

pub 和 sub 各自独立 TA 密钥，避开 OP-TEE 3.2 跨进程并发限制。

## 源文件清单

| 文件 | 说明 |
|------|------|
| `ssl_config.c` | ENGINE 凭据注入回调实现 |
| `ssl_config.h` | `tbox_ssl_config_pub()` / `tbox_ssl_config_sub()` 包装声明 |
| `mqtts_pub.c` | MQTT 发布者 |
| `mqtts_sub.c` | MQTT 订阅者 |
| `gen_csr.c` | CSR 生成器（ENGINE 签名，供 Root CA 签发） |
| `tcpprobe_mqtt.c` | paho TCP 探测工具（无 SSL，隔离网络问题） |

## 外部接口

### ssl_config — 凭据注入回调

```c
int tbox_ssl_config_ex(SSL_CTX *ctx, const char *key_label, const char *cert_file);

// 包装宏，匹配 SSLSocket_externalConfigCallback 签名
static inline int tbox_ssl_config_pub(SSL_CTX *ctx)
    → tbox_ssl_config_ex(ctx, "pub-key", "/tmp/pub.crt");

static inline int tbox_ssl_config_sub(SSL_CTX *ctx)
    → tbox_ssl_config_ex(ctx, "sub-key", "/tmp/sub.crt");
```

`tbox_ssl_config_ex` 执行：
1. `ENGINE_load_tbox_keystore()` — 注册 ENGINE（首次调用）
2. `ENGINE_load_private_key(key_label)` — 从 TA 加载私钥
3. `SSL_CTX_use_certificate_file(cert_file)` — 加载设备证书
4. `SSL_CTX_load_verify_locations("/tmp/root-ca.crt")` — 信任 Root CA
5. `SSL_CTX_set_verify(PEER | FAIL_IF_NO_PEER_CERT)` — 开启双向认证

### paho 补丁回调

```c
// 声明于 paho/SSLSocketConfig.h
typedef int (*SSLSocket_externalConfigCallback)(SSL_CTX *ctx);
void SSLSocket_setExternalConfigCallback(SSLSocket_externalConfigCallback cb);
```

### mqtts_pub / mqtts_sub — 命令行

```bash
mqtts_pub [broker_host] [port] [topic] [message]
# 默认: 127.0.0.1 8883 tbox/test "hello from TBox (TA-signed)"

mqtts_sub [broker_host] [port] [topic] [timeout_sec]
# 默认: 127.0.0.1 8883 tbox/test 30
```

### gen_csr — CSR 生成器

```bash
gen_csr <key-label> <CN> [out.csr]
# 例: gen_csr pub-key tbox-pub /tmp/pub.csr
#     → openssl x509 -req -in /tmp/pub.csr -CA root-ca.crt -CAkey root-ca.key -out pub.crt
```

## 脚本

| 脚本 | 说明 |
|------|------|
| `test/mqtt_ta_setup_keys.sh` | 灌装 TA 密钥（pub-key + sub-key）+ Lock |
| `test/mqtt_gen_root_ca.sh` | 生成 Root CA 密钥 + 自签名证书 |
| `test/mqtt_gen_broker_cert.sh` | 生成 Broker 软件密钥 + 自签名证书（本地测试） |
| `test/mqtt_gen_certs.sh` | CA 签发全部证书（broker + pub + sub） |
| `test/mqtt_run_test.sh` | 自动化：TCP 检查 → 启动 sub（后台） → pub → 检查消息 |

## 前置依赖

| 依赖 | 来源 | 说明 |
|------|------|------|
| `libe_tbox_keystore.so` | `../../engine/build/` | ENGINE 库 |
| `libpaho-mqtt3cs.so` | `three_part/mqtt/out/` | paho SSL 版（带补丁） |
| `libpaho-mqtt3c.so` | `three_part/mqtt/out/` | paho TCP 版（tcpprobe 用） |
| OpenSSL 1.1.x | `three_part/openssl/out/` | libssl + libcrypto |
| TA 密钥 (pub-key, sub-key) | TA 灌装 | 发布/订阅私钥 |
| paho 补丁（SSLSocket） | `paho_patch/` | paho 源码补丁说明 |

## 构建

```bash
cd examples/mqtts && mkdir -p build && cd build
cmake .. -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
    -DOPENSSL_ROOT_DIR=/home/test0923/workspace/OP-TEE/three_part/openssl/out \
    -DOPENSSL_INCLUDE_DIR=/home/test0923/workspace/OP-TEE/three_part/openssl/out/include \
    -DOPENSSL_SSL_LIBRARY=/home/test0923/workspace/OP-TEE/three_part/openssl/out/lib/libssl.so \
    -DOPENSSL_CRYPTO_LIBRARY=/home/test0923/workspace/OP-TEE/three_part/openssl/out/lib/libcrypto.so
make -j
```

产物：`mqtts_pub`、`mqtts_sub`、`gen_csr`、`tcpprobe_mqtt`。

## 设备端部署与验证

### 第一步：灌装 TA 密钥

```bash
rm -rf /data/tee/*
./test/mqtt_ta_setup_keys.sh
```

### 第二步：生成证书

```bash
./test/mqtt_gen_certs.sh
```

| 产物 | 部署位置 |
|------|----------|
| `/tmp/root-ca.crt` | 设备 + EMQX |
| `/tmp/broker.crt` | EMQX |
| `/tmp/broker.key` | EMQX |
| `/tmp/pub.crt` | 设备 |
| `/tmp/sub.crt` | 设备 |

### 第三步：配置 EMQX

修改 `emqx.conf`：

```
listeners.ssl.default = 8883
listeners.ssl.default.ssl_options.certfile  = /etc/emqx/certs/broker.crt
listeners.ssl.default.ssl_options.keyfile   = /etc/emqx/certs/broker.key
listeners.ssl.default.ssl_options.cacertfile = /etc/emqx/certs/root-ca.crt
listeners.ssl.default.ssl_options.verify     = verify_peer
listeners.ssl.default.ssl_options.fail_if_no_peer_cert = true
```

### 第四步：运行测试

```bash
./test/mqtt_run_test.sh
```

## 故障排查

| 现象 | 检查 |
|------|------|
| ENGINE init 失败 | `tbox_keystore --info pub-key` |
| TLS 握手失败 | 证书是否同一 Root CA 签发，时钟同步 |
| connect 拒绝 | `telnet broker 8883`，QEMU 需 hostfwd |
| paho 回调不触发 | `privateKey` 必须为 `"__EXTERNAL_CONFIG__"`，不能设 `keyStore` |
| 跨进程冲突 | pub/sub 串行运行 |

## 相关文档

- [engine/README.md](../../engine/README.md) — ENGINE 实现
- [18-mqtt-mutual-auth-demo.md](../../docs/18-mqtt-mutual-auth-demo.md) — MQTT 双向认证方案
- [19-hsm-chip-reference-architecture.md](../../docs/19-hsm-chip-reference-architecture.md) — 参考架构
- [20-mqtts-debug-issues.md](../../docs/20-mqtts-debug-issues.md) — MQTTS 调试记录
- [paho_patch/SSLSocket_setExternalConfigCallback.patch](paho_patch/SSLSocket_setExternalConfigCallback.patch) — paho 补丁说明
