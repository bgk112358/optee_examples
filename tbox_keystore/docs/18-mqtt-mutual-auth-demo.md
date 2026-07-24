# MQTT 双向认证 Demo — EMQX Broker + TEE ENGINE 客户端

> **目标**：TBox 设备通过 tbox_keystore ENGINE 使用 TA 内密钥与公网 EMQX Broker 完成 MQTT over TLS 双向认证通信。
>
> **Broker 侧**：EMQX v5，软件密钥 + 自签名证书
> **客户端侧**：独立 C 程序，ENGINE 加载 TA 密钥，TLS 握手后收发 MQTT 报文

---

## 一、整体架构

```
┌─────────────────────────────────────┐     ┌───────────────────────────────────┐
│ EMQX Broker  111.230.16.196 :8883   │     │ TBox Device                        │
│                                     │     │                                   │
│ 证书: broker.crt  (自签名)           │ TLS │ mqtt_pub / mqtt_sub                │
│ 私钥: broker.key  (软件 PEM)         │◄───►│                                   │
│ 信任: client.crt  (验证设备)         │     │ 证书:   client.crt  (自签名)       │
│                                     │     │ 私钥:   client-key  (TA 内)       │
│                                     │     │ 信任:   broker.crt  (验证 Broker)  │
│                                     │     │                                   │
│                                     │     │ TLS 层  → 自控 SSL (ENGINE + TA)   │
│                                     │     │ MQTT 层 → 手动实现 v3.1.1 协议     │
└─────────────────────────────────────┘     └───────────────────────────────────┘
```

### 1.1 信任链

```
Broker 验证 Client:
  Broker 收到 ClientHello → 要求客户端证书
  Client 发送 client.crt + CertificateVerify (签名=ENGINE→TA)
  Broker 用 client.crt 中的公钥验签 → 通过
  Broker 用 client.crt (作为信任锚) 验证证书链 → 通过

Client 验证 Broker:
  Client 收到 Broker 证书 broker.crt
  Client 用 broker.crt (作为信任锚) 验证 → 通过
```

两个方向的信任锚是**各自独立的自签名证书**，不是一个"根 CA"。

---

## 二、MQTT 实现选择

### 2.1 paho 不直接支持 ENGINE

paho.mqtt.c 的 `MQTTClient_SSLOptions` 只有文件路径接口：

```c
struct {
    const char *trustStore;    // CA cert PEM path
    const char *keyStore;      // client cert PEM path
    const char *privateKey;    // client private key PEM path ← 只支持文件
    // 无 ENGINE key identifier 接口
};
```

如果传 PEM 文件路径，OpenSSL 内部会走软件 RSA，私钥离开 TEE 失去安全意义。

### 2.2 方案：自控 TLS + 手动 MQTT 协议

```
┌─────────────────────────────┐
│ MQTT 协议层 (手写, ~150 行)  │  CONNECT / PUBLISH / SUBSCRIBE / PINGREQ
├─────────────────────────────┤
│ TLS 层 (ENGINE + TA)        │  SSL_connect → CertificateVerify 走 TA
├─────────────────────────────┤
│ TCP socket                  │  连接 broker:8883
└─────────────────────────────┘
```

不依赖 paho 做 TLS。MQTT v3.1.1 协议报文简单，手写比集成 paho 更可控。

**优点**：
- TLS 层完全由 ENGINE 控制，私钥操作路由到 TA
- 代码完全自包含，无外部依赖
- 不触发 paho 内部 SSL 路径的任何冲突

**缺点**：
- 需要手写 MQTT 报文编解码（~150 行，v3.1.1 协议很简洁）
- 不支持 paho 的异步/回调功能（demo 够用）

---

## 三、OP-TEE 3.2 并发限制应对

### 3.1 限制回顾

| 限制 | 现象 |
|------|------|
| 同 session 内 reopen 同一持久化对象 | TEE_ERROR_ACCESS_CONFLICT |
| 不同 TEEC 会话同时访问同一持久化对象 | TEE_ERROR_ITEM_NOT_FOUND |

mqtt_pub 和 mqtt_sub 是两个独立进程，各自持有不同的 TEEC 会话。如果同时运行，会触发交叉访问冲突。

### 3.2 Demo 策略：串行单工

```
mqtt_test.sh 流程:
  1. mqtt_pub --message "topic/qos/data"   ← 独立进程，CONNECT → PUBLISH → DISCONNECT → 退出
  2. 此时没有并发 session
  3. mqtt_sub --topic "topic/qos"          ← 独立进程，CONNECT → SUBSCRIBE → 等待 → 收到消息 → 退出
```

pub 和 sub 在**不同时间窗口**运行，TA 会话在每次进程退出时关闭，不存在并发冲突。

如果 pub 和 sub 需要同时在线（真实场景），生产部署走 [16-multi-process-concurrency-analysis.md](16-multi-process-concurrency-analysis.md) 中方案 B（tbox_keyd 守护进程）。

---

## 四、证书生成

### 4.1 Broker 证书

EMQX 需要自身证书 + 私钥。现有 `gen_sw_cert.sh` 的证书 SAN 只有 `127.0.0.1`，不适用于公网 IP。新建 `gen_broker_cert.sh`：

```bash
#!/bin/sh
KEY=/tmp/broker.key
CRT=/tmp/broker.crt

openssl genrsa -out "$KEY" 2048
openssl req -new -x509 -key "$KEY" -out "$CRT" -days 3650 \
    -subj "/CN=emqx-broker" \
    -addext "subjectAltName=IP:111.230.16.196"

echo "broker.key → $KEY"
echo "broker.crt → $CRT"
```

### 4.2 客户端证书

复用 `setup_keys.sh` 中 `tls_mutual_auth --gen-certs` 生成的 `/tmp/tbox-client.crt`。证书由 TA 签名，公钥匹配 TA 内的 `client-key`。

### 4.3 证书文件分布

| 文件 | 位置 | 用途 |
|------|------|------|
| `broker.crt` | EMQX + TBox 设备 | Broker 自签名证书 |
| `broker.key` | 仅 EMQX | Broker 软件私钥 |
| `tbox-client.crt` | EMQX + TBox 设备 | 设备自签名证书 |
| `client-key` | 仅 TBox (TA 内) | 设备私钥（永不出 TEE） |

---

## 五、MQTT 协议实现

### 5.1 最小可行集

v3.1.1 协议，支持以下控制报文：

| 报文 | 代码 | 用途 |
|------|:---:|------|
| CONNECT | 0x10 | 客户端连接 |
| CONNACK | 0x20 | Broker 确认连接 |
| PUBLISH | 0x30 | 发布消息 |
| PUBACK | 0x40 | QoS 1 确认 |
| SUBSCRIBE | 0x82 | 订阅主题 |
| SUBACK | 0x90 | 订阅确认 |
| PINGREQ | 0xC0 | 心跳 |
| PINGRESP | 0xD0 | 心跳响应 |
| DISCONNECT | 0xE0 | 断开连接 |

### 5.2 报文结构

```c
/* Fixed header: 1-5 bytes */
struct mqtt_fixed_header {
    uint8_t type : 4;
    uint8_t dup  : 1;
    uint8_t qos  : 2;
    uint8_t retain : 1;
    /* variable length encoding follows */
};

/* Remaining length: 1-4 bytes, 7-bit encoding */
int mqtt_encode_remaining(uint8_t *buf, uint32_t len);
int mqtt_decode_remaining(const uint8_t *buf, uint32_t *len, int *consumed);
```

### 5.3 CONNECT payload

```
[ProtocolName "MQTT", Ver4, ConnectFlags, KeepAlive, ClientID...+]
```

```c
int mqtt_send_connect(SSL *ssl, const char *client_id,
                       const char *username, const char *password);
int mqtt_recv_connack(SSL *ssl);
```

### 5.4 PUBLISH

```
FixedHeader(0x30 | QoS<<1) + TopicLen:2 + Topic + [PacketID:2] + Payload
```

```c
int mqtt_send_publish(SSL *ssl, const char *topic,
                       const uint8_t *payload, uint32_t len, int qos);
```

### 5.5 SUBSCRIBE

```
FixedHeader(0x82) + RemLen + PacketID:2 + TopicLen:2 + Topic + QoS:1 + ...
```

```c
int mqtt_send_subscribe(SSL *ssl, const char *topic, int qos);
int mqtt_recv_suback(SSL *ssl);
int mqtt_recv_publish(SSL *ssl, char *topic, int topic_len,
                       uint8_t *payload, int *payload_len);
```

### 5.6 消息循环

```c
/* Subscriber 主循环 */
while (running) {
    mqtt_send_pingreq(ssl);           // keep-alive 心跳
    mqtt_recv_pingresp(ssl);
    mqtt_recv_publish(ssl, topic, sizeof(topic), payload, &payload_len);
    printf("[SUB] %s: %.*s\n", topic, payload_len, payload);
    sleep(keepalive_seconds);
}
```

---

## 六、文件清单

```
optee_examples_AG519M/tbox_keystore/engine/
├── e_tbox_keystore.c             ← 已有
├── tls_mutual_auth.c             ← 已有
├── CMakeLists.txt                ← 修改（新增 3 个 target）
├── test/
│   ├── engine_test.c             ← 已有
│   ├── https_client.c            ← 已有
│   ├── setup_keys.sh             ← 已有
│   ├── run_test.sh               ← 已有
│   ├── https_test.sh             ← 已有
│   ├── gen_sw_cert.sh            ← 已有（本地测试用）
│   ├── gen_broker_cert.sh        ← 新增
│   ├── mqtt_pub.c                ← 新增 (~200 行)
│   ├── mqtt_sub.c                ← 新增 (~250 行)
│   ├── mqtt_common.c             ← 新增 (~300 行，MQTT 协议 + TLS 公共代码)
│   ├── mqtt_common.h             ← 新增
│   └── mqtt_test.sh              ← 新增
```

### 6.1 mqtt_common.c 职责

```c
// TLS 层
SSL_CTX *mqtt_create_tls_ctx(const char *key_label,
                              const char *cert_file,
                              const char *ca_file);
// MQTT 协议层
int mqtt_send_connect(SSL *ssl, const char *client_id);
int mqtt_recv_connack(SSL *ssl);
int mqtt_send_publish(SSL *ssl, const char *topic,
                       const uint8_t *payload, uint32_t len, int qos);
int mqtt_send_subscribe(SSL *ssl, const char *topic, int qos);
int mqtt_recv_suback(SSL *ssl);
int mqtt_recv_publish(SSL *ssl, char *topic, int topic_len,
                       uint8_t *payload, int *payload_len);
int mqtt_send_pingreq(SSL *ssl);
int mqtt_send_disconnect(SSL *ssl);
int mqtt_read_packet(SSL *ssl, uint8_t *buf, int len, int timeout_ms);
```

### 6.2 mqtt_pub.c 主流程

```c
int main(int argc, char *argv[])
{
    parse_args(argc, argv);   // --topic, --message, --broker, --port

    SSL_library_init();
    ENGINE_load_tbox_keystore();

    SSL_CTX *ctx = mqtt_create_tls_ctx("client-key",
                                       CLIENT_CERT, BROKER_CERT);
    SSL *ssl = tls_connect(ctx, broker_host, broker_port);
    print_peer_cert(ssl);

    mqtt_send_connect(ssl, "tbox-pub");
    mqtt_recv_connack(ssl);

    mqtt_send_publish(ssl, topic, (const uint8_t *)message, strlen(message), 1);
    mqtt_recv_puback(ssl);

    mqtt_send_disconnect(ssl);
    cleanup();
    return 0;
}
```

### 6.3 mqtt_sub.c 主流程

```c
int main(int argc, char *argv[])
{
    parse_args(argc, argv);   // --topic, --broker, --port, --timeout

    SSL_library_init();
    ENGINE_load_tbox_keystore();

    SSL_CTX *ctx = mqtt_create_tls_ctx("client-key",
                                       CLIENT_CERT, BROKER_CERT);
    SSL *ssl = tls_connect(ctx, broker_host, broker_port);
    print_peer_cert(ssl);

    mqtt_send_connect(ssl, "tbox-sub");
    mqtt_recv_connack(ssl);

    mqtt_send_subscribe(ssl, topic, 1);
    mqtt_recv_suback(ssl);

    /* Wait for messages */
    time_t start = time(NULL);
    while (time(NULL) - start < timeout) {
        uint8_t msg[4096];
        int len = sizeof(msg);
        char recv_topic[128];
        if (mqtt_recv_publish(ssl, recv_topic, sizeof(recv_topic),
                               msg, &len) > 0) {
            printf("[SUB] %s: %.*s\n", recv_topic, len, msg);
            break;
        }
        mqtt_send_pingreq(ssl);
        usleep(keepalive * 1000000);
    }

    mqtt_send_disconnect(ssl);
    cleanup();
    return 0;
}
```

---

## 七、测试脚本

### 7.1 mqtt_test.sh

```bash
#!/bin/sh
# 1. 确认 TA 已灌装 client-key + client.crt 已生成
# 2. 确认 broker.crt 已部署到设备
# 3. 确认 EMQX 已启动并配置好双向认证
# 4. 先启动 subscriber（后台，30s 超时）
# 5. 等 2s
# 6. 运行 publisher
# 7. sub 收到消息后打印 → TEST PASSED
```

### 7.2 EMQX 配置参考

```
# emqx.conf
listeners.ssl.default = 8883
listeners.ssl.default.ssl_options.certfile = /etc/emqx/certs/broker.crt
listeners.ssl.default.ssl_options.keyfile  = /etc/emqx/certs/broker.key
listeners.ssl.default.ssl_options.cacertfile = /etc/emqx/certs/client.crt
listeners.ssl.default.ssl_options.verify = verify_peer
listeners.ssl.default.ssl_options.fail_if_no_peer_cert = true
```

---

## 八、CMakeLists.txt 新增

```cmake
add_executable(mqtt_pub test/mqtt_pub.c test/mqtt_common.c)
target_link_libraries(mqtt_pub ${OPENSSL_LIBRARIES} e_tbox_keystore)

add_executable(mqtt_sub test/mqtt_sub.c test/mqtt_common.c)
target_link_libraries(mqtt_sub ${OPENSSL_LIBRARIES} e_tbox_keystore)
```

---

## 九、部署与运行

```bash
# 设备端
cd /path/to/tbox_keystore

# 1. 灌装密钥 + 生成客户端证书（一次性）
rm -rf /data/tee/*
./test/setup_keys.sh

# 2. 生成 broker 证书（一次性，在编译机生成后拷贝到 EMQX 和设备）
./test/gen_broker_cert.sh
scp /tmp/broker.crt root@<device>:/tmp/

# 3. 配置 EMQX（在 broker 上，手动操作）
#    将 broker.crt, broker.key, client.crt 上传到 EMQX 服务器
#    修改 emqx.conf 并重启

# 4. 编译
cd engine/build && cmake .. && make -j

# 5. 运行测试
./test/mqtt_test.sh
```

---

## 十、与已有测试的关系

```
测试金字塔:

         ┌──────────────────┐
         │ mqtt_test.sh     │  ← MQTT 双向认证 + EMQX 公网 （新）
         │ mqtt_pub + mqtt_sub │
         ├──────────────────┤
         │ https_test.sh    │  ← HTTPS GET s_server
         ├──────────────────┤
         │ run_test.sh      │  ← TLS 握手 (双方 TA)
         ├──────────────────┤
         │ engine_test      │  ← ENGINE 回调冒烟
         └──────────────────┘
```

`mqtt_test.sh` 是完整生产场景的缩影——真实 MQTT Broker + 真实网络 + TEE 密钥 + 双向 TLS。
