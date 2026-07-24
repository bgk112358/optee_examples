# 产线灌装详细流程

## 整体时序图

```
┌───── 产线工控机 ─────┐         ┌───── tbox 设备 ─────────────┐
│                        │         │                              │
│  ① 产线管理系统         │         │  BootROM 启动                 │
│  (MES / 密钥管理系统)   │         │  → 验签 uboot                │
│                        │         │  → uboot 验签 OP-TEE + Linux │
│  ② 下发灌装指令         │────────▶│  → Linux 启动 optee-supplicant│
│                        │  USB    │  → 启动灌装客户端              │
│  ③ 发送设备证书请求     │◀────────│  → 发送设备 UUID + HUK Hash  │
│                        │         │                              │
│  ④ 密钥管理系统签发:     │────────▶│                              │
│     - 设备证书           │  USB    │  ⑤ 接收密钥材料              │
│     - 设备私钥 (加密)    │         │                              │
│     - 对称密钥材料       │         │  ⑥ 调用 PKCS#11 API 注入:    │
│     - 自定义属性         │         │     - C_Login(SO PIN)       │
│                        │         │     - C_GenerateKeyPair(RSA) │
│  ⑦ 确认 + 记录 HUK Hash │◀────────│     - C_CreateObject(AES)   │
│                        │         │     - C_Unwrap(私钥)         │
│  ⑧ 序列号 → 密钥绑定    │         │     - C_Logout()            │
│     写入产线数据库       │         │                              │
└────────────────────────┘         └──────────────────────────────┘
```

---

## 阶段 A：设备上电 + 安全启动

```
Step 1: 设备上电
  └── BootROM 执行
       ├── 读取 eFuse 中的 HUK → 生成 SSK
       ├── 读取 eFuse 中的公钥 Hash → 验签 uboot
       └── 跳转 uboot

Step 2: uboot
  ├── 验签 OP-TEE OS image
  ├── 验签 Linux Kernel + initramfs（灌装环境）
  ├── 加载 OP-TEE 到 Secure RAM
  └── 跳转 OP-TEE + Linux

Step 3: OP-TEE 初始化
  ├── 从 eFuse 读取 HUK → 生成 SSK
  ├── 初始化 RPMB 驱动（第一次使用时需写入 RPMB 密钥）
  ├── tee-supplicant 在 REE 启动
  └── PKCS#11 TA 首次加载（执行 init_persistent_db）
```

### PKCS#11 TA 首次初始化（代码路径）

```c
/* pkcs11_token.c — TA 加载时的初始化 */

TEE_Result pkcs11_init(void)
{
    for (id = 0; id < TOKEN_COUNT; id++) {
        /* 从 RPMB 读取或创建持久化数据库 */
        struct ck_token *token = init_persistent_db(id);
        if (!token)
            return TEE_ERROR_SECURITY;

        if (token->state == PKCS11_TOKEN_RESET) {
            /* 首次运行: token 初始化为读写状态，等待产线 C_InitToken */
            token->state = PKCS11_TOKEN_READ_WRITE;
            token->session_count = 0;
            token->rw_session_count = 0;
        }
    }
    return TEE_SUCCESS;
}

/* 此时 token 的状态: */
// - state = PKCS11_TOKEN_READ_WRITE
// - db_main->flags = 0 (未初始化)
// - db_objs->count = 0 (无密钥)
// - 等待产线调用 C_InitToken + C_Login(SO) + 灌装密钥
```

---

## 阶段 B：主体灌装交互

### 产线工控机执行脚本

```bash
#!/bin/bash
# 文件: provision.sh — 产线工控机上执行的灌装脚本
# 依赖: optee_pkcs11_client (封装了 PKCS#11 C_* 调用的 CLI 工具)

set -e
DEVICE_SN=$(get_device_serial_from_usb)  # 读取设备序列号
echo "=== 开始灌装: ${DEVICE_SN} ==="

# ============================================================
# 步骤 1: 初始化 Token（仅在首次灌装时执行）
# ============================================================
# 对应 PKCS#11 C_InitToken:
#   - 清空 Token 中所有密钥
#   - 设置 SO (Security Officer) PIN
#   - 设置 Token Label
optee_pkcs11_client --init-token \
    --so-pin "12345678" \
    --label "TBOX-${DEVICE_SN}"

# 验证 Token 状态:
#   db_main->flags = PKCS11_CKFT_TOKEN_INITIALIZED
#   db_main->label = "TBOX-<SN>"
#   so_pin_hash = SHA512("12345678" || so_pin_salt)

# ============================================================
# 步骤 2: 设置 User PIN (用于正常运行时解锁密钥)
# ============================================================
# 对应 PKCS#11 C_InitPIN:
#   - 使用 SO PIN 登录后设置 User PIN
#   - User PIN = 序列号（操作员只需扫码，无需手动输入）
optee_pkcs11_client --init-pin \
    --so-pin "12345678" \
    --user-pin "${DEVICE_SN}"

# 验证:
#   db_main->flags |= PKCS11_CKFT_USER_PIN_INITIALIZED
#   user_pin_hash = SHA512(DEVICE_SN || user_pin_salt)

# ============================================================
# 步骤 3: 生成 RSA 2048 设备私钥（TEE 内生成，永不出 TEE）
# ============================================================
# 对应 PKCS#11 C_GenerateKeyPair:
#   - 算法: CKM_RSA_PKCS_KEY_PAIR_GEN
#   - 密钥由 TEE 内部安全随机数产生
#   - 私钥直接写入持久化存储，不经过 REE 内存
KEY_ID=$(optee_pkcs11_client --generate-key-pair \
    --key-type RSA \
    --key-size 2048 \
    --id "device-key" \
    --label "TBOX-${DEVICE_SN}-rsa" \
    --pin "${DEVICE_SN}")

# TEE 内部流程:
#   TEE_GenerateKey(TEE_ALG_RSA_NOPAD, 2048, ...)
#   → 生成: n, e, d, p, q, dp, dq, qp
#   → 序列化到 obj_attrs[ CKA_MODULUS, CKA_PUBLIC_EXPONENT,
#                        CKA_PRIVATE_EXPONENT, ... ]
#   → TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE_RPMB, uuid, ...)
#   → RPMB 写入（FEK 加密）
#   → 返回对象句柄 KEY_ID

# ============================================================
# 步骤 4: 导出公钥 → 请求 CA 签署设备证书
# ============================================================
# 导出公钥材料（n, e），通过 USB 发回工控机
# 工控机的 KMS 使用 CA 私钥签发 X.509 证书
echo "PUBKEY_REQUEST" > /dev/usb-gadget/ep0
sleep 0.1
PUBKEY_N=$(optee_pkcs11_client --get-attribute \
    --object $KEY_ID \
    --attribute CKA_MODULUS)
PUBKEY_E=$(optee_pkcs11_client --get-attribute \
    --object $KEY_ID \
    --attribute CKA_PUBLIC_EXPONENT)

# USB 传输到工控机
echo "${PUBKEY_N}|${PUBKEY_E}" > /dev/usb-gadget/ep0

# 工控机侧:
# kms-agent recv pubkey → openssl ca -sign → device.cert.pem
# → echo device.cert.pem > /dev/usb-gadget/ep1

# ============================================================
# 步骤 5: 接收并写入设备证书
# ============================================================
CERT=$(cat /dev/usb-gadget/ep1)   # 从工控机接收 PEM 格式证书
optee_pkcs11_client --import-cert \
    --cert-type x509 \
    --object-id "device-cert" \
    --label "TBOX-${DEVICE_SN}-cert" \
    --value "$CERT" \
    --pin "${DEVICE_SN}"

# 写入 TEE 后:
# → obj_attrs: CKA_CLASS=CKO_CERTIFICATE, CKA_CERTIFICATE_TYPE=CKC_X_509
# → TEE_CreatePersistentObject(RPMB, ...)

# ============================================================
# 步骤 6: 注入预置对称密钥
# ============================================================
# 用于: OTA 更新加密、安全日志、远程诊断
# 方式 A（推荐）: TEE 内生成
optee_pkcs11_client --generate-key \
    --key-type AES \
    --key-size 256 \
    --id "ota-key" \
    --label "TBOX-${DEVICE_SN}-ota" \
    --encrypt true \
    --decrypt true \
    --pin "${DEVICE_SN}"

# 方式 B（备选）: 从 KMS 远程注入
# KMS 生成 AES-256 → 用设备公钥 RSA-OAEP 加密 → 传输
# tbox 用 C_Unwrap 解密后注入
# optee_pkcs11_client --unwrap-key \
#     --wrapping-key $KEY_ID \
#     --mechanism CKM_RSA_PKCS_OAEP \
#     --key-type AES --key-size 256 \
#     --id "ota-key" \
#     --pin "${DEVICE_SN}"

# ============================================================
# 步骤 7: 注入额外的应用密钥（按需）
# ============================================================
# 产线可根据产品型号选择性注入:
# - 云平台对接密钥 (HMAC-SHA256)
# - TSP (Telematics Service Provider) 证书
# - 国密 SM2/SM4 密钥对
# - 第二 RSA 密钥（用于 TLS 客户端认证）

optee_pkcs11_client --import-key \
    --key-type GENERIC_SECRET \
    --key-size 256 \
    --id "cloud-hmac-key" \
    --label "TBOX-${DEVICE_SN}-hmac" \
    --sign true --verify true \
    --pin "${DEVICE_SN}" \
    --value $(kms generate-hmac-key --serial ${DEVICE_SN})

# ============================================================
# 步骤 8: 锁定 Token（防止后续非法写入）
# ============================================================
# 对应 PKCS#11 C_InitToken 在已初始化 token 上执行 → 拒绝
# 设置 User PIN 修改锁定 → 只能由 SO 修改
# Token 设置为只读状态

optee_pkcs11_client --set-token-flags \
    --read-only true \
    --so-pin "12345678"

# 验证: db_main->state = PKCS11_TOKEN_READ_ONLY
# 此后所有写操作返回 CKR_TOKEN_WRITE_PROTECTED

# ============================================================
# 步骤 9: 灌装结果验证
# ============================================================
echo "=== 验证开始 ==="

# 验证 Token Label
TOKEN_INFO=$(optee_pkcs11_client --token-info)
echo "$TOKEN_INFO" | grep -q "TBOX-${DEVICE_SN}" || exit 1

# 验证密钥存在
optee_pkcs11_client --find-objects \
    --class PRIVATE_KEY | grep -q "device-key" || exit 1

# 验证签功能可用
SIG=$(optee_pkcs11_client --sign \
    --mechanism CKM_RSA_PKCS \
    --object "device-key" \
    --data "provision verification" \
    --pin "${DEVICE_SN}")

# 工控机侧用设备证书公钥验证签名
echo "${SIG}" > /dev/usb-gadget/ep0
sleep 0.1
VERIFY_RESULT=$(cat /dev/usb-gadget/ep1)
if [ "$VERIFY_RESULT" != "OK" ]; then
    echo "签名验证失败！"
    exit 1
fi

# 验证断电持久化
# 通知 tbox 准备掉电测试
echo "POWER_CYCLE_TEST" > /dev/usb-gadget/ep0
sleep 2  # tbox 断电再重启...

# 重启后再次连接，验证密钥仍在
optee_pkcs11_client --find-objects \
    --class PRIVATE_KEY | grep -q "device-key" || exit 1

echo "=== 灌装完成: ${DEVICE_SN} ==="
exit 0
```

---

## 阶段 C：密钥在 TEE 内的落地路径

```
产线执行 C_GenerateKeyPair(RSA-2048)
  │
  ├─ PKCS#11 TA 内部:
  │   └─ TEE_GenerateKey(TEE_ALG_RSA_NOPAD, 2048, ...)
  │       └─ LibTomCrypt / Crypto Cell → 生成 RSA 密钥对
  │           ├─ 私钥: d, p, q, dp, dq, qp
  │           └─ 公钥: n, e
  │
  ├─ 判断 CKA_TOKEN = true
  │   └─ TEE_CreatePersistentObject(
  │         TEE_STORAGE_PRIVATE_RPMB,   # 直接写入 RPMB
  │         uuid, sizeof(uuid),
  │         ...,
  │         serialized_attrs, size, ...)
  │
  └─ TEE 加密流程（自动，不可见）:
      ├─ 生成 FEK (File Encryption Key)
      ├─ enc_fek = AES-GCM-Encrypt(TSK, FEK)
      │   TSK = HMAC-SHA256(SSK, PKCS11_TA_UUID)
      │   SSK = HMAC-SHA256(HUK, ChipID || "static string")
      ├─ 用 FEK 加密密钥明文
      └─ 写入 RPMB（硬件认证写，防回滚）
```

### PKCS#11 Token 产线初始化后的状态

```c
/* 灌装完成后，Token 内部状态：*/

// Token 主数据库
struct token_persistent_main {
    .version = 1,
    .label = "TBOX-ABCD1234",             // 序列号
    .flags = PKCS11_CKFT_TOKEN_INITIALIZED |
             PKCS11_CKFT_USER_PIN_INITIALIZED |
             PKCS11_CKFT_LOGIN_REQUIRED |
             PKCS11_CKFT_READ_ONLY,       // 已锁定
    .so_pin_hash = <SHA512("12345678" || salt)>,
    .user_pin_hash = <SHA512("ABCD1234" || salt)>,
};

// Token 对象注册表
struct token_persistent_objs {
    .count = 4,  // 4 个持久化对象
    .uuids = {
        { 0x... },  // RSA 私钥 (device-key)
        { 0x... },  // AES 对称密钥 (ota-key)
        { 0x... },  // X.509 证书 (device-cert)
        { 0x... },  // HMAC 密钥 (cloud-hmac-key)
    },
};

// RPMB 中的物理文件
// /data/tee/ 目录不存在（因为 CFG_REE_FS=n）
// 所有数据在 eMMC RPMB 分区中，块地址由 FAT 表管理
```

---

## 灌装模式退出

```bash
# 灌装成功后的退出逻辑

# provision-client 完成后的操作:
if [ "$VERIFY_RESULT" = "OK" ]; then
    # 标记 RPMB 写计数器（防止回滚到未灌装状态）
    # 清除 kernel cmdline 中的 provision=1 标志
    # 如果是双分区系统，切换到正常系统分区
    # 执行 reboot

    # ov 产线反馈结果给工控机
    echo "PROVISION_SUCCESS" > /dev/usb-gadget/ep0
    reboot
fi
```
