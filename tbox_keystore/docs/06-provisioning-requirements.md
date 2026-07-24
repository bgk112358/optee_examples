# 系统内置能力要求

产线一机一密灌装需要从硬件层到应用层的完整能力支撑。本文档按层次列出所有必须的能力。

---

## 一、硬件信任根（硬件层必须）

```
SoC 必须提供:
├── eFuse / OTP (One-Time Programmable)
│   ├── HUK (Hardware Unique Key) — 每颗芯片唯一，出厂烧录
│   ├── 安全启动公钥 Hash — 验证 BootROM → 引导程序签名
│   ├── Debug 授权控制 — 锁定 JTAG/SWD 调试接口
│   └── TEE 使能位 — 标记该芯片启用 TEE
│
├── RPMB (Replay Protected Memory Block) 分区
│   └── eMMC 上的防回滚安全分区
│
└── 真随机数发生器 (TRNG/HRNG)
```

### HUK 产前准备

```c
/* 芯片出厂阶段（半导体封测厂）*/
// SoC 在封测阶段就要完成:
// 1. 烧录 HUK 到 eFuse（128位随机数，每颗芯片不同）
// 2. 烧录 Root CA 公钥 Hash（用于验签 uboot）
// 3. 锁定 Debug 接口（JTAG熔丝）
// 4. 在 HUK 数据库中记录 {ChipID → HUK Hash} 映射

// SoC 厂商提供 HUK 的读取接口（仅 Secure World 可调用）:
struct tee_hw_unique_key {
    uint8_t data[HUK_SIZE];
};

// 平台实现（plat-xxx/main.c）:
void tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
    // 从 eFuse 控制器读取，示例伪代码:
    efuse_read(EFUSE_HUK_OFFSET, hwkey->data, HUK_SIZE);
    // 如果是模拟环境/开发板:
    // hwkey->data = { 0x00 };  // 开发用固定值，量产绝对不能
}
```

---

## 二、安全启动链（固件层）

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ BootROM     │──▶  │ 引导程序    │──▶  │ OP-TEE OS   │──▶  │ Linux 内核   │
│ (片上ROM)   │     │ (SPL/uboot) │     │ (tee-pager) │     │ + initramfs │
│ 验签下一级  │     │ 验签 OP-TEE │     │ 验签 TA     │     │ 验签应用    │
│            │     │ + Linux     │     │ 加载 PKCS   │     │ 启动灌装    │
│            │     │             │     │ #11 TA      │     │ 客户端     │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
      ▲                    ▲                   ▲                   ▲
      │                    │                   │                   │
      └────────── 每级签名验证，信任链从 BootROM ────────────────┘
```

### 信任链要求

| 层级 | 镜像 | 签名方式 | 验签公钥来源 |
|------|------|----------|-------------|
| BootROM | 自身（片上ROM） | 不可更改（Mask ROM） | 硬件固定 |
| SPL / 引导程序 | uboot-spl.bin | RSA-2048 PKCS#1.5 | eFuse 中 Root CA Hash |
| OP-TEE OS | tee-pager.bin | 同上 | uboot 传递的 Key |
| Linux 内核 | Image + dtb | 同上 | OP-TEE 验证 |
| PKCS#11 TA | ta-pkcs11.ta | TA 签名证书 | OP-TEE 内置 TA 公钥 |
| 灌装客户端 | provision-client | initramfs 整体验签 | 内核验签 |

---

## 三、OP-TEE 配置要求

### 量产 Makefile 配置

```makefile
# optee_os 量产配置
CFG_PKCS11_TA = y                # PKCS#11 TA（核心依赖）
CFG_RPMB_FS = y                  # RPMB 安全存储
CFG_RPMB_WRITE_KEY = y           # 允许烧录 RPMB 密钥（产线专用）
CFG_RPMB_TESTKEY = n             # ❌ 不能使用测试密钥！
CFG_REE_FS = n                   # 量产禁用 REE FS 存储
CFG_TA_PKI = y                   # TA 签名验证
CFG_SECURE_DATA_PATH = y         # 安全数据路径
CFG_CORE_DYN_SHM = y             # 动态共享内存

# PKCS#11 配置
CFG_PKCS11_TA_TOKEN_COUNT = 1    # 单 Token 模式
CFG_PKCS11_TA_ALLOW_DIGEST = y   # 允许 HASH
CFG_PKCS11_TA_AUTH_TEE_IDENTITY = n  # 产线使用 PIN 认证

# 算法支持
CFG_CRYPTO_SIZE_OPTIMIZATION = n  # 不优化尺寸，开启全部算法
CFG_CRYPTO_WITH_CE = y            # 启用 Crypto Extension 硬件加速
```

### HUK 回调函数要求

```c
/* 平台必须实现以下两个函数，量产不能是空壳 */

// 1. 读取硬件唯一密钥（来自 eFuse 或其他 OTP）
void tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
    // 从安全硬件模块读取
    // 返回值永不为零，每台设备唯一
    hsm_read_otp(HUK_SLOT, hwkey->data, sizeof(hwkey->data));
}

// 2. 读取芯片 Die ID
int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
    // 作为 SSK 派生时的 ChipID 输入
    return hsm_read_otp(DIE_ID_SLOT, buffer, len);
}
```

---

## 四、产线灌装软件栈

### 产线工控机侧

```
工控机软件栈:
┌────────────────────────────────────────────────────────────┐
│  密钥管理系统 (KMS / Key Management Server)                 │
│  ├── 安全随机数生成器                                        │
│  ├── 证书签发模块 (CA)                                       │
│  ├── 密钥数据库（记录 序列号 ↔ 公钥 Hash ↔ 设备证书）          │
│  └── 审计日志                                                │
├────────────────────────────────────────────────────────────┤
│  产线管理中间件                                              │
│  ├── USB-Gadget 通信驱动 (识别 tbox RNDIS / CDC-ECM)        │
│  ├── 序列号读取器 (扫码枪 / RFID)                            │
│  ├── 灌装脚本引擎                                            │
│  │   ├── 产线流程控制（上电→灌装→验证→下电）                 │
│  │   ├── 超时/重试/异常处理                                  │
│  │   └── 结果上报 MES                                       │
│  └── 安全通道 (与 tbox 通信加密，设备证书双向认证)              │
└────────────────────────────────────────────────────────────┘

启动的进程:
  # 工控机上需要运行:
  kms-daemon          # 密钥管理系统
  provision-agent     # 灌装代理（USB 通信 + 脚本执行）
  mes-client          # 与工厂 MES 系统对接
```

### tbox 设备侧（灌装模式）

```
设备 kernel cmdline 新增:
  optee.provision=1     # 标记当前为灌装模式
  quiet                 # 可选的静默启动

启动后自动运行的进程:
  1. optee-supplicant (must)      # OP-TEE 用户态守护进程
  2. tee-supplicant (must)        # REE 侧 supplicant（处理 RPMB 请求）
  3. provision-client (auto)      # 灌装客户端（in initramfs）
      ├── 初始化 USB Gadget（RNDIS / CDC-ECM）
      ├── 等待工控机连接
      ├── 执行 PKCS#11 灌装命令
      └── 完成后停止 / 重启到正常系统

initramfs 结构:
  /init              # 灌装模式入口
  /usr/bin/provision-client  # 灌装客户端（静态链接）
  /usr/lib/liboptee_pkcs11.so
  /usr/lib/libteec.so.2
  /etc/ssl/openssl.cnf  # 预先配置好 pkcs11 engine
```

### 产线操作视角

```
┌───────────────────────────────────────────────────────────────┐
│  产线岗位操作步骤                                               │
│                                                               │
│  Step 1: 操作员将 tbox 放置在工装上，连接 USB 线                │
│  Step 2: 扫码枪扫描 tbox 外壳上的序列号条码                     │
│  Step 3: 工装上的继电器使能 tbox 供电                          │
│  Step 4: tbox 自动进入灌装模式（由 BootROM GPIO 电平识别）     │
│  Step 5: 工控机检测到 USB 设备，开始灌装                       │
│          ├─ 5a. 核对序列号 ↔ 产品型号                          │
│          ├─ 5b. 获取设备 HUK Hash 验证硬件身份                  │
│          ├─ 5c. 批量注入并固化密钥（~3-10秒）                   │
│          └─ 5d. 验证密钥可正常使用                              │
│  Step 6: 结果 OK → 绿灯 → 断电 → 取走 tbox                    │
│          NG → 红灯 → 记录到 MES → 维修工位                     │
│                                                               │
│  单台总耗时: ~8-15秒（含上电和通信握手）                        │
└───────────────────────────────────────────────────────────────┘
```
