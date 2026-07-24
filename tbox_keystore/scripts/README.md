# scripts — 产线灌装脚本

## 概述

`provision.sh` 是一个示例脚本，模拟工厂产线 TBox 设备一机一密灌装流程。

**流程**：初始化 PIN → 生成设备身份密钥 → 生成 OTA 密钥 → 导出公钥 → 锁定 TA。

## 命令

```bash
./provision.sh <pin-hex>
```

| 参数 | 说明 | 示例 |
|------|------|------|
| `pin-hex` | 16 字节 hex 编码的灌装 PIN | `a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6` |

## 流程

```
[1/5] 初始化 PIN         → tbox_keystore --init-pin <PIN>
[2/5] 生成 RSA 设备密钥   → tbox_keystore --gen-rsa device-key --size 2048 --sign --decrypt
[3/5] 生成 AES OTA 密钥   → tbox_keystore --gen-aes ota-key --size 256 --decrypt
[4/5] 导出 RSA 公钥       → tbox_keystore --export-pub device-key --out device-key.pub
[5/5] 锁定 TA            → tbox_keystore --lock
```

## 依赖

| 依赖 | 路径 | 说明 |
|------|------|------|
| `tbox_keystore` CLI | `../host/build/tbox_keystore` | CA 命令行工具 |
| TA 已部署 | `/lib/optee_armtz/` | TEE 内密钥管理 |

## 使用

```bash
cd tbox_keystore
./scripts/provision.sh a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
```

## 预期输出

```
=========================================
 TBox Keystore Provisioning
=========================================

[1/5] Initializing PIN...
PIN initialized.
[2/5] Generating device identity key (RSA-2048)...
RSA-2048 key generated: 'device-key' (perms=0x13)
[3/5] Generating OTA decryption key (AES-256)...
AES-256 key generated: 'ota-key' (perms=0x8)
[4/5] Exporting device public key...
Public key written to device-key.pub
[5/5] Locking TA...
TA locked. Write operations disabled.

=========================================
 Provisioning complete!

 Public key: device-key.pub
   → Send this to your CA for signing.

 Next steps on the device:
   1. Verify: ./tbox_keystore --info device-key
   2. Verify: ./tbox_keystore --info ota-key
   3. Sign test: ./tbox_keystore --sign device-key --data $(echo -n test | xxd -p)
=========================================
```

## 与 CA 证书签发流程的关系

此脚本只完成 TEE 内密钥灌装。证书签发需要额外步骤：

```bash
# 4a. 导出的 device-key.pub → 发送给 Root CA
# 4b. Root CA: openssl x509 -req ... → device.crt
# 4c. device.crt 部署回设备: cp device.crt /etc/tbox/certs/

# 或者用 CSR 流程：
# 4a. gen_csr device-key tbox-device → device.csr (ENGINE 签名)
# 4b. Root CA: openssl x509 -req -in device.csr -CA root-ca.crt → device.crt
```

参见 [examples/mqtts/test/mqtt_gen_certs.sh](../examples/mqtts/test/mqtt_gen_certs.sh) 了解完整的 CA 证书链生成流程。

## 相关文档

- [host/README.md](../host/README.md) — CA 命令行工具
- [ta/README.md](../ta/README.md) — TA 实现
- [07-provisioning-procedure.md](../docs/07-provisioning-procedure.md) — 产线灌装详细流程
- [08-provisioning-security.md](../docs/08-provisioning-security.md) — 灌装安全约束
