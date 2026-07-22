# MQTTS 双向认证 — TEE ENGINE + paho 客户端

## 架构

```
Root CA (root-ca.crt)
  ├── 签发 broker.crt  → EMQX Broker   (软件私钥)
  ├── 签发 pub.crt     → mqtts_pub      (pub-key, TA 内)
  └── 签发 sub.crt     → mqtts_sub      (sub-key, TA 内)
```

pub 和 sub 各自独立 TA 密钥，互不冲突，避开 OP-TEE 3.2 跨进程并发限制。

## 依赖

- 交叉编译工具链：`optee400/toolchains/aarch64/bin/aarch64-linux-gnu-gcc`
- OpenSSL 1.1.x（交叉编译）：`three_part/openssl/out`
- paho.mqtt.c 1.3.16（带 SSLSocket 外部配置回调补丁）：`three_part/mqtt/out`
- tbox_keystore ENGINE：`../engine/build/libe_tbox_keystore.so`

## 构建

```bash
cd optee_examples_AG519M/tbox_keystore/mqtts

# 设置交叉编译器
export PATH="/home/test0923/workspace/optee400/toolchains/aarch64/bin:$PATH"

mkdir -p build && cd build
cmake .. && make -j

# 产物
#   build/mqtts_pub     — 发布者
#   build/mqtts_sub     — 订阅者
#   build/gen_csr       — CSR 生成工具
```

## 设备端部署与验证

### 第一步：灌装 TA 密钥

```bash
rm -rf /data/tee/*
./test/mqtt_ta_setup_keys.sh
```

确认输出中 pub-key 和 sub-key 状态均为 RSA-2048。

### 第二步：生成证书

```bash
./test/mqtt_gen_certs.sh
```

证书产出：

| 文件 | 用途 | 部署位置 |
|------|------|----------|
| `/tmp/root-ca.crt` | 信任锚 | 设备 + EMQX |
| `/tmp/broker.crt` | Broker 证书 | EMQX |
| `/tmp/broker.key` | Broker 私钥 | EMQX |
| `/tmp/pub.crt` | 发布者证书 | 设备 |
| `/tmp/sub.crt` | 订阅者证书 | 设备 |

### 第三步：配置 EMQX Broker

将 `root-ca.crt`、`broker.crt`、`broker.key` 上传到 EMQX 服务器，修改 `emqx.conf`：

```
listeners.ssl.default = 8883
listeners.ssl.default.ssl_options.certfile  = /etc/emqx/certs/broker.crt
listeners.ssl.default.ssl_options.keyfile   = /etc/emqx/certs/broker.key
listeners.ssl.default.ssl_options.cacertfile = /etc/emqx/certs/root-ca.crt
listeners.ssl.default.ssl_options.verify     = verify_peer
listeners.ssl.default.ssl_options.fail_if_no_peer_cert = true
```

重启 EMQX。

### 第四步：运行端到端测试

```bash
./test/mqtt_run_test.sh
```

预期输出：

```
=========================================
 MQTTS CA-signed certs test
=========================================

[TEST] Starting subscriber (TEE key: sub-key)...
ssl_config: OK (key=sub-key, cert=/tmp/sub.crt, ca=/tmp/root-ca.crt)
[SUB] Connected — TLS mutual auth via TA
[SUB] Subscribed to 'tbox/test'

[TEST] Running publisher (TEE key: pub-key)...
ssl_config: OK (key=pub-key, cert=/tmp/pub.crt, ca=/tmp/root-ca.crt)
[PUB] Connected — TLS mutual auth via TA
[PUB] Published: 'hello from tbox (TA-signed)'
[SUB] topic=tbox/test payload=hello from tbox (TA-signed)

=========================================
 TEST PASSED
=========================================
```

### 故障排查

| 现象 | 检查 |
|------|------|
| ENGINE init 失败 | `tbox_keystore --info pub-key` 确认 TA 已灌装 |
| TLS 握手失败 | 检查 EMQX 证书配置，确认 root-ca.crt 一致 |
| connect 拒绝 | `ping <broker>` 确认网络可达，端口 8883 已开放 |
| 证书过期 | `openssl x509 -in /tmp/pub.crt -noout -dates` 检查有效期 |
| 跨进程冲突 | pub/sub 是串行测试，不应触发。如仍出现，`rm -rf /data/tee/*` 重来 |
