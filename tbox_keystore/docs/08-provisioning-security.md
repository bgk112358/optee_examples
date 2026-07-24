# 安全设计约束与验证清单

## 一、产线环境安全性

### 风险分析

```
风险: 产线工控机被攻击 → 所有设备密钥泄露
影响: 整个批次设备失去安全信任，需要召回重灌
```

### 缓解措施

```
├── 工控机与 KMS 之间的通信使用双向 TLS 证书认证
│   └── 工控机本身不存储任何私钥，只做签名请求的转发
│
├── 密钥材料不允许明文保存在工控机本地
│   ├── 对称密钥 → 由 KMS 加密后通过安全通道下发
│   │                tbox 内用 C_Unwrap 解密再注入
│   └── 设备私钥 → 在 TEE 内用 C_GenerateKeyPair 生成
│                   私钥从不离开 TEE，工控机只知道公钥
│
├── 产线网络与办公网络物理隔离
│   └── 工控机不应同时连接互联网
│
└── 灌装完成后工控机必须清除本地缓存
    └── 每台设备灌装结束后立即清除临时文件
```

### KMS 安全通道建立流程

```
产线工控机                          KMS (密钥管理系统)
    │                                    │
    │  ─── 建立 TLS 1.3 双向认证 ──────▶ │
    │  ◀── 证书验证通过 ──────────────── │
    │                                    │
    │  ─── 请求设备证书签发 ────────────▶ │
    │      { SN, pubkey_n, pubkey_e }    │
    │                                    │  openssl ca -sign
    │  ◀── 返回设备证书 ──────────────── │      device.crt
    │      { cert_pem }                  │
    │                                    │
    │  ─── 请求 OTA 对称密钥 ───────────▶ │
    │      { SN }                        │
    │                                    │  AES-256-Gen
    │  ◀── 返回 { encrypted_key } ────── │  RSA-OAEP(device_pubkey)
    │                                    │
```

---

## 二、产线退出锁定

### 不可逆操作清单

```bash
# 灌装成功后，tbox 必须锁定以下能力:

# 1. 关闭 Token 重新初始化
# C_InitToken(PIN, label) → 在已初始化的 Token 上返回:
#   CKR_TOKEN_ALREADY_INITIALIZED

# 2. 关闭 SO 登录（正常运行时只能 User PIN 登录）
# 正常情况下不应暴露 SO PIN:
# C_Login(SO) → CKR_USER_TYPE_INVALID
# （仅产线模式允许 SO 登录）

# 3. Token 状态锁定为只读
# 所有写操作:
# C_CreateObject       → CKR_TOKEN_WRITE_PROTECTED
# C_DestroyObject      → CKR_TOKEN_WRITE_PROTECTED
# C_GenerateKeyPair    → CKR_TOKEN_WRITE_PROTECTED

# 4. 内核 cmdline 移除 provision=1 标志
# 下次启动进入正常系统，不再启用灌装客户端

# 5. RPMB 不可回滚验证
# 尝试用旧版本的 RPMB Key 访问 → 失败
# 说明 RPMB 写计数器已增加，无法回滚到未灌装状态
```

### 产线模式判定代码

```c
/* provision-client 中的产线模式判定 */

static bool is_provision_mode(void)
{
    /* 方法 A: kernel cmdline */
    if (strstr(bootargs, "optee.provision=1"))
        return true;

    /* 方法 B: GPIO 电平（产线工装拉低某个识别 GPIO）*/
    if (gpio_get_value(PROVISION_GPIO) == 0)
        return true;

    /* 方法 C: RPMB 特定标记位 */
    /* 如果 Token 已初始化并且锁定了 → 不可再进入产线模式 */
    struct ck_token *token = get_token(0);
    if (token->db_main->flags & PKCS11_CKFT_READ_ONLY) {
        return false;  /* 已灌装完成，禁止二次灌装 */
    }

    return false;
}
```

---

## 三、产线验证清单

### 灌装后即时验证

```bash
# 由 provision-client 在断电前执行

echo "=== 产线验证开始 ==="
errors=0

# 验证 1: Token 状态
TOKEN_INFO=$(optee_pkcs11_client --token-info)
if echo "$TOKEN_INFO" | grep -q "TBOX-"; then
    echo "[PASS] Token label 正确"
else
    echo "[FAIL] Token label 错误"
    errors=$((errors+1))
fi

# 验证 2: 密钥数量
KEY_COUNT=$(optee_pkcs11_client --find-objects --class PRIVATE_KEY | wc -l)
if [ "$KEY_COUNT" -ge 1 ]; then
    echo "[PASS] 私钥对象存在: ${KEY_COUNT} 个"
else
    echo "[FAIL] 私钥对象缺失"
    errors=$((errors+1))
fi

# 验证 3: 密钥可正常使用
DATA="Provision verification at $(date)"
SIG=$(optee_pkcs11_client --sign \
    --mechanism CKM_RSA_PKCS \
    --object "device-key" \
    --data "${DATA}" \
    --pin "${DEVICE_SN}")
if [ -n "$SIG" ]; then
    echo "[PASS] 签名操作成功"
else
    echo "[FAIL] 签名操作失败"
    errors=$((errors+1))
fi

# 验证 4: 工控机侧用证书公钥验证签名
echo "$SIG" | openssl pkeyutl -verify \
    -pubin -inkey device_pubkey.pem \
    -in <(echo "${DATA}") \
    -siglen 256
if [ $? -eq 0 ]; then
    echo "[PASS] 签名验证通过（工控机侧）"
else
    echo "[FAIL] 签名验证失败"
    errors=$((errors+1))
fi

# 验证 5: Token 已锁定，禁止写入
optee_pkcs11_client --generate-key \
    --key-type AES --key-size 128 --pin "${DEVICE_SN}" \
    2>&1 | grep -q "CKR_TOKEN_WRITE_PROTECTED"
if [ $? -eq 0 ]; then
    echo "[PASS] Token 已锁定，写操作已禁用"
else
    echo "[FAIL] Token 未锁定"
    errors=$((errors+1))
fi

# 验证 6: 设备证书存在
optee_pkcs11_client --find-objects --class CERTIFICATE \
    | grep -q "device-cert"
if [ $? -eq 0 ]; then
    echo "[PASS] 设备证书存在"
else
    echo "[FAIL] 设备证书缺失"
    errors=$((errors+1))
fi

echo "=== 验证结果: ${errors} 个错误 ==="
if [ "$errors" -gt 0 ]; then
    exit 1
fi
exit 0
```

### 出厂抽检验证

```bash
# 产线 QA 抽检（每批次抽检 5%）

# 测试 1: 断电持久化
# 断开电源 → 等待 10 秒 → 重新上电
# → provision-client 不应启动（已退出产线模式）
# → 读取 Token 状态，确认所有密钥仍在

# 测试 2: 密钥操作功能完整
optee_pkcs11_client --encrypt \
    --mechanism CKM_AES_CBC \
    --object "ota-key" \
    --iv "0123456789abcdef" \
    --data "128 bytes plaintext data..." \
    --pin "${DEVICE_SN}"

optee_pkcs11_client --decrypt \
    --mechanism CKM_AES_CBC \
    --object "ota-key" \
    --iv "0123456789abcdef" \
    --data "<encrypted data>" \
    --pin "${DEVICE_SN}"

# 测试 3: 安全属性不可变
# 尝试修改密钥属性 → 应拒绝
C_GetAttributeValue → 可读
C_SetAttributeValue → CKR_ACTION_PROHIBITED

# 测试 4: RPMB 防回滚
# 用 dd 命令直接写入 eMMC RPMB 旧数据 → 不通过认证
# TEE 启动时发现写计数器不匹配 → 拒绝使用旧数据
```

---

## 四、异常处理

### 产线异常分类

| 异常类型 | 现象 | 处理方式 |
|----------|------|----------|
| 通信中断 | USB 断开 | provision-client 等待超时后自动关机，重试 |
| 密钥生成失败 | C_GenerateKeyPair 返回 CKR_DEVICE_MEMORY | 记录错误码到 RPMB 错误日志，上报工控机 |
| RPMB 写失败 | 物理 eMMC 损坏 | 标记为不良品，维修或报废 |
| Token 已初始化 | C_InitToken 返回 CKR_TOKEN_ALREADY_INITIALIZED | 设备已灌装过，核对序列号是否一致 |
| PIN 验证失败 | C_Login 返回 CKR_PIN_INCORRECT | 确认 User PIN 策略，检查序列号 |
| 证书签名不匹配 | openssl verify 失败 | 重新请求 KMS 签发，或标记为异常设备 |
| 掉电 | 灌装过程中断电 | 下次开机重新执行灌装（RPMB 保证原子性） |

### 异常恢复流程

```
灌装过程中断电
  │
  ├─ 重新上电
  │
  ├─ PKCS#11 TA 加载
  │   ├─ RPMB 读 token_persistent_main
  │   │   ├─ 如果未初始化 (flags=0) → 从头开始灌装
  │   │   └─ 如果已初始化 (flags & TOKEN_INITIALIZED)
  │   │       └─ 读取 token_persistent_objs
  │   │           ├─ 如果无密钥对象 → 重新灌装
  │   │           └─ 如果有密钥对象 → 跳过已完成的步骤
  │
  └─ RPMB 的原子性保证:
      ├─ 每个写操作是原子的（eMMC 规范保证）
      ├─ FAT 表最后更新
      └─ 不存在"半写"的密钥文件
```

---

## 五、固件防回滚

### RPMB 写计数器机制

```
RPMB 写计数器内置在 eMMC 控制器中:
├─ 初始值 = 0
├─ 每次认证写操作 → 计数器 +1
├─ 不可重置（除非 Erase RPMB Key，但 Key 只能写一次）
└─ 读请求时返回当前计数值 → TEE 校验

产线灌装时:
  step1: RPMB 写计数器 0 → 1（写入 RPMB Key）
  step2: RPMB 写计数器 1 → 2（创建 Token DB 文件）
  step3: RPMB 写计数器 2 → 3（写入密钥文件 1）
  ...

回滚攻击:
  攻击者写入旧 RPMB 数据 → eMMC 要求 HMAC 认证
  → HMAC 中包含写计数器值
  → 旧数据的 HMAC 使用旧计数器值
  → eMMC 拒绝（计数器不匹配）
  → 攻击失败
```

### 双分区升级防回滚

```
正常系统分区 (A)    灌装系统分区 (B)
┌──────────────┐    ┌──────────────┐
│ 正常 Linux    │    │ initramfs    │
│ + OP-TEE     │    │ + 灌装客户端  │
│ + 服务应用    │    │ + 最小内核   │
└──────────────┘    └──────────────┘

产线启动流程:
  1. BootROM 读 eFuse → 确定启动分区
  2. 产线工装 GPIO 拉低 → BootROM 选择 B 分区
  3. 灌装完成后覆写 A 分区标记位
  4. 下次启动 GPIO 恢复 → BootROM 选择 A 分区

安全约束:
  - B 分区不包含设备私钥和持久化能力
  - 只有 B 分区的内核 cmdline 启用 optee.provision=1
  - 正常 A 分区的内核永远不会启用产线模式
```

---

## 六、密钥生命周期管理

### 产线阶段

```
阶段 1: SoC 封测
  ├── HUK 写入 eFuse（128位，每芯片唯一）
  ├── Root CA 公钥写入 eFuse
  └── Debug 接口熔丝锁定

阶段 2: SMT 贴片
  └── eMMC 烧录（未灌装，不含任何密钥）

阶段 3: 产线灌装（本文档核心）
  ├── TEE 内生成设备 RSA 私钥
  ├── 注入对称密钥材料
  ├── 写入设备证书
  └── Token 锁定为只读

阶段 4: 出厂
  └── 所有密钥在 TEE RPMB 中，与 SoC HUK 绑定
```

### 设备运行阶段

```
阶段 5: 首次联网
  ├── 用设备私钥签名 CSR
  ├── 发送证书签名请求到云平台 CA
  └── 云平台返回 TLS 客户端证书

阶段 6: 正常运行
  ├── TLS 连接使用设备证书
  ├── OTA 解密使用 OTA 密钥
  ├── 安全日志使用 HMAC 密钥
  └── 所有密钥操作在 TEE 内完成

阶段 7: 密钥轮换
  ├── PKCS#11 C_GenerateKeyPair → 新密钥
  ├── 旧密钥标记为 CKA_DESTROYABLE
  ├── C_DestroyObject → 删除旧密钥
  └── 私钥永远不出 TEE

阶段 8: 设备退役
  ├── C_Login(SO)（正常不可用，仅工厂模式）
  ├── C_InitToken → 清空 Token
  └── RPMB 写计数器 +1 → 防回滚重利用
```

---

## 七、安全能力总结矩阵

| 安全需求 | 实现方式 | 覆盖率 |
|----------|----------|--------|
| 每设备唯一密钥 | HUK (eFuse) + SSK 派生 | 出厂已锁定 |
| 密钥不可提取 | TEE 内存隔离 + RPMB 加密 | RPMB 加密存储 |
| 密钥不可回滚 | RPMB 写计数器 | 硬件保证 |
| 防重灌 | Token 只读锁 + RPMB 状态 | Token 不可逆 |
| 防调试器泄露 | JTAG 熔丝 | 封测已锁 |
| 防固件降级 | 安全启动链签名验证 | 每级验签 |
| 防物理拆解 | RPMB 认证 + HUK 绑定 SoC | 芯片级绑定 |
| 防侧信道 | TEE 隔离环境 | OP-TEE 沙箱 |
| 产线数据不可恢复 | 使用后清除临时文件 | 工控机策略 |
| 产线数据机密传输 | TLS 双向认证 | KMS → 工控机 |
