# TBox Keystore — OP-TEE Example

## 概述

演示文档 `docs/11-industry-provisioning-solutions.md` 中推荐的组合方案代码实现：

- **模式 A** — TEE 内生 RSA/AES 密钥，私钥不出 TEE
- **模式 D** — 支持导出 RSA 公钥，用于产线 CA 签发设备证书
- **方案 B** — TA 内部自动 PIN 管理，应用层无需传 PIN

## 目录结构

```
tbox_keystore/
├── Makefile                          # 顶层构建
├── CMakeLists.txt
├── Android.mk
├── README.md
│
├── ta/                               # Trusted Application
│   ├── Makefile
│   ├── CMakeLists.txt
│   ├── sub.mk
│   ├── Android.mk
│   ├── user_ta_header_defines.h
│   ├── entry.c                       # TA 入口 + 命令分发
│   ├── pin_mgr.c                     # 自动 PIN 管理
│   ├── keystore.c                    # 密钥生命周期（生成/存储/加载/删除）
│   ├── acl.c                         # 密钥权限检查
│   ├── crypto_ops.c                  # 加解密/签名/验签封装
│   └── include/
│       └── tbox_keystore_ta.h        # UUID + 命令ID + 共享结构体
│
├── host/                             # Client Application
│   ├── Makefile
│   └── keystore_client.c             # 命令行工具
│
└── scripts/
    └── provision.sh                   # 产线灌装演示脚本
```

## 构建

```bash
# 设置环境
source /opt/ql-ol-crosstool/ql-ol-crosstool-env-in
export TA_DEV_KIT_DIR=<path-to-export-user_ta>

# 构建
make CROSS_COMPILE=arm-poky-linux-gnueabi-
```

**TA 用 64 位编译器时：**

```bash
make HOST_CROSS_COMPILE=arm-poky-linux-gnueabi- \
     TA_CROSS_COMPILE=aarch64-poky-linux-
```

## 产线灌装流程

```bash
# 1. 启动 TA（设备已上电，OP-TEE 已加载 TK#11 TA）

# 2. 初始化和生成密钥
./tbox_keystore --init-pin a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6

# 3. 生成设备身份密钥（RSA-2048, 签名 + 解密）
./tbox_keystore --gen-rsa device-key --size 2048 --sign --decrypt

# 4. 生成 OTA 解密密钥（AES-256, 仅解密）
./tbox_keystore --gen-aes ota-key --size 256 --decrypt

# 5. 导出公钥发送给 CA 签发
./tbox_keystore --export-pub device-key --out device-key.pub

# 6. 锁定 TA（禁止后续写操作）
./tbox_keystore --lock
```

## 正常运行示例

```bash
# 签名（TLS 客户端认证）
./tbox_keystore --sign device-key --data $(echo -n "hello" | xxd -p)

# 验签
./tbox_keystore --verify device-key \
    --data $(echo -n "hello" | xxd -p) \
    --sig <signature-hex>

# OTA 固件解密
./tbox_keystore --decrypt ota-key --data <encrypted-hex> --out firmware.bin

# 查询密钥信息
./tbox_keystore --info device-key
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

## 架构特点

- **自动 PIN** — PIN 只写一次到 TEE 安全存储，后续所有操作 TA 内部自动认证
- **密钥持久化** — 密钥存储为 TEE PersistObject，断电不丢失
- **权限控制** — 每个密钥独立权限位（SIGN/VERIFY/ENCRYPT/DECRYPT）
- **产线锁定** — 灌装完成后锁定 TA，防止运行时新增/删除密钥

## 对应文档

- [11-industry-provisioning-solutions.md](../../docs/11-industry-provisioning-solutions.md) — 行业灌装方案总览
- [07-provisioning-procedure.md](../../docs/07-provisioning-procedure.md) — 产线灌装详细流程
- [09-pin-management.md](../../docs/09-pin-management.md) — PIN 管理方案
- [10-multiple-keys-access-control.md](../../docs/10-multiple-keys-access-control.md) — 多密钥访问控制
