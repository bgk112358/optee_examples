# TBox Keystore — OP-TEE Example

## 概述

基于 OP-TEE 的 TBox 安全服务完整实现，包含 TA 密钥管理、OpenSSL ENGINE、TLS/HTTPS/MQTTS 双向认证示例。

- **TA** — TEE 内密钥生成/存储/密码学运算（RSA/AES）
- **ENGINE** — OpenSSL ENGINE 桥接，应用层标准 API 零改动
- **Examples** — ENGINE 冒烟测试、TLS 双向认证、HTTPS 客户端、MQTTS 发布/订阅

## 目录结构

```
tbox_keystore/
├── ta/                              ← Trusted Application 源码
│   ├── entry.c                      ←   TA 入口 + 命令分发
│   ├── pin_mgr.c                    ←   PIN 管理（自动认证 + Lock）
│   ├── keystore.c                   ←   密钥生命周期（生成/存储/加载/删除/导出）
│   ├── acl.c                        ←   访问控制（权限位校验）
│   ├── crypto_ops.c                 ←   密码学封装（sign/verify/encrypt/decrypt）
│   ├── user_ta_header_defines.h
│   └── include/
│       └── tbox_keystore_ta.h       ←   UUID + 命令 ID + 共享结构
│
├── host/                            ← Client Application（命令行工具）
│   └── keystore_client.c            ←   11 个管理命令
│
├── engine/                          ← 【公用 ENGINE 库】
│   ├── e_tbox_keystore.c            ←   OpenSSL ENGINE 实现
│   └── CMakeLists.txt               ←   构建 libe_tbox_keystore.so
│
├── examples/                        ← 【测试与演示样例】
│   ├── engine_test/                 ←   ENGINE 冒烟测试（6 步骤签名/验签）
│   ├── tls_mutual_auth/             ←   TLS 双向认证（双方 TA key）
│   ├── https_client/                ←   HTTPS 客户端（ENGINE + s_server）
│   └── mqtts/                       ←   MQTTS 发布/订阅（CA 链式证书）
│       ├── ssl_config.c / .h        ←     ENGINE 凭据注入回调
│       ├── mqtts_pub.c              ←     MQTT 发布者
│       ├── mqtts_sub.c              ←     MQTT 订阅者
│       ├── gen_csr.c                ←     CSR 生成器（ENGINE 签名）
│       ├── tcpprobe_mqtt.c          ←     paho TCP 探测工具
│       └── test/                    ←     测试脚本
│
└── scripts/
    └── provision.sh                 ← 产线灌装演示脚本
```

## 交叉编译环境

| 组件 | 路径 |
|------|------|
| 交叉编译器 | `optee400/toolchains/aarch64/bin/aarch64-linux-gnu-gcc` |
| OpenSSL (交叉编译) | `three_part/openssl/out` |
| paho.mqtt.c (带补丁) | `three_part/mqtt/out` |
| TEE Client API | `optee400/optee_client/export-ca_arm64` |

```bash
export PATH="/home/test0923/workspace/optee400/toolchains/aarch64/bin:$PATH"
export CC=aarch64-linux-gnu-gcc
export OPENSSL_DIR=/home/test0923/workspace/three_part/openssl/out
```

## 构建

### 1. ENGINE 库

```bash
cd engine && mkdir -p build && cd build
cmake .. -DCMAKE_C_COMPILER=$CC
make -j
# 产物: libe_tbox_keystore.so
```

### 2. TA（仅 Makefile）

```bash
cd ta
export TA_DEV_KIT_DIR=/opt/ql-ol-crosstool/.../export-user_ta
make CROSS_COMPILE=aarch64-linux-gnu-
# 产物: f8e9209a-*.ta
```

### 3. 示例程序

所有 example 共用相同的 CMake 配置模板：

```bash
cd examples/<name>
mkdir -p build && cd build
cmake .. \
    -DCMAKE_C_COMPILER=$CC \
    -DOPENSSL_ROOT_DIR=$OPENSSL_DIR \
    -DOPENSSL_INCLUDE_DIR=$OPENSSL_DIR/include \
    -DOPENSSL_SSL_LIBRARY=$OPENSSL_DIR/lib/libssl.so \
    -DOPENSSL_CRYPTO_LIBRARY=$OPENSSL_DIR/lib/libcrypto.so
make -j
```

| Example | 产物 | 说明 |
|---------|------|------|
| `engine_test` | `engine_test` | ENGINE 签名/验签 6 步冒烟测试 |
| `tls_mutual_auth` | `tls_mutual_auth` | TLS 1.2 双向认证（双方 TA key + 自签名证书） |
| `https_client` | `https_client` | HTTPS 客户端（ENGINE + openssl s_server） |
| `mqtts` | `mqtts_pub / mqtts_sub / gen_csr` | MQTTS 发布/订阅 + CSR 生成 |

## CA 命令行工具

```bash
cd host && mkdir -p build && cd build
cmake .. && make
# 产物: tbox_keystore
```

## 产线灌装流程

```bash
# 1. 初始化和生成密钥
./tbox_keystore --init-pin a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
./tbox_keystore --gen-rsa device-key --size 2048 --sign --decrypt
./tbox_keystore --gen-aes ota-key --size 256 --decrypt

# 2. 导出公钥发送给 CA 签发
./tbox_keystore --export-pub device-key --out device-key.pub

# 3. 锁定 TA（禁止后续写操作）
./tbox_keystore --lock
```

## 命令完整列表

| 命令 | 说明 |
|------|------|
| `--init-pin <hex>` | 写入 PIN（一次性） |
| `--lock` | 锁定 TA（禁用写操作） |
| `--gen-rsa <label>` | 生成 RSA 密钥对 |
| `--gen-aes <label>` | 生成 AES 密钥 |
| `--export-pub <label>` | 导出 RSA 公钥 |
| `--sign <label>` | RSA 签名 |
| `--verify <label>` | RSA 验签 |
| `--encrypt <label>` | AES 加密 |
| `--decrypt <label>` | AES 解密 |
| `--info <label>` | 查看密钥信息 |
| `--delete <label>` | 删除密钥 |

## 设备端部署

```bash
# TA
cp ta/*.ta /lib/optee_armtz/

# ENGINE
cp engine/build/libe_tbox_keystore.so /usr/lib/

# 示例程序（按需）
cp examples/engine_test/build/engine_test         /usr/bin/
cp examples/mqtts/build/mqtts_pub                 /usr/bin/
cp examples/mqtts/build/mqtts_sub                 /usr/bin/
cp examples/mqtts/build/gen_csr                   /usr/bin/

# paho（MQTTS 场景）
cp three_part/mqtt/out/lib/libpaho-mqtt3cs.so*    /usr/lib/
```

## 架构特点

- **自动 PIN** — PIN 只写一次到 TEE 安全存储，后续所有操作 TA 内部自动认证
- **密钥持久化** — 密钥存储为 TEE PersistObject，断电不丢失
- **权限控制** — 每个密钥独立权限位（SIGN/VERIFY/ENCRYPT/DECRYPT）
- **产线锁定** — 灌装完成后锁定 TA，防止运行时新增/删除密钥
- **ENGINE 桥接** — OpenSSL 标准 API 接入，应用层零改动
- **证书链** — 支持 Root CA → 设备证书的链式信任模型
- **多进程隔离** — pub/sub 各用独立 TA 密钥，避开 OP-TEE 3.2 并发限制

## 对应文档

| 文档 | 内容 |
|------|------|
| [13-openssl-engine-integration.md](./docs/13-openssl-engine-integration.md) | ENGINE 集成方案 |
| [15-engine-debug-issues.md](./docs/15-engine-debug-issues.md) | ENGINE 调试问题记录 |
| [17-https-client-demo.md](./docs/17-https-client-demo.md) | HTTPS 客户端方案 |
| [18-mqtt-mutual-auth-demo.md](./docs/18-mqtt-mutual-auth-demo.md) | MQTT 双向认证方案 |
| [20-mqtts-debug-issues.md](./docs/20-mqtts-debug-issues.md) | MQTTS 调试问题记录 |
| [21-product-manual.md](./docs/21-product-manual.md) | 产品说明书 |
