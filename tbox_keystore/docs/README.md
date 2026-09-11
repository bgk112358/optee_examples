# tbox 产线一机一密灌装方案

> 本文档描述在 tbox 产线上，如何将唯一密钥安全地灌装到每台设备的 OP-TEE PKCS#11 Token 中。

## 文档目录

| 文件 | 内容 |
|------|------|
| [01-architecture-overview.md](01-architecture-overview.md) | 五种实现方案的对比与选型建议 |
| [02-pkcs11-route.md](02-pkcs11-route.md) | PKCS#11 + OP-TEE PKCS#11 TA 路线（推荐） |
| [03-engine-route.md](03-engine-route.md) | OpenSSL ENGINE 路线（OpenSSL 1.x 兼容） |
| [04-provider-route.md](04-provider-route.md) | OpenSSL Provider 路线（OpenSSL 3.x 原生） |
| [05-key-storage.md](05-key-storage.md) | 密钥在 TEE 内的存储机制详解 |
| [06-provisioning-requirements.md](06-provisioning-requirements.md) | 系统内置能力要求（硬件/固件/软件） |
| [07-provisioning-procedure.md](07-provisioning-procedure.md) | 产线灌装详细流程与步骤分解 |
| [08-provisioning-security.md](08-provisioning-security.md) | 安全设计约束与验证清单 |
| [09-pin-management.md](09-pin-management.md) | HTTPS 应用中 PIN 码管理与无感调用方案 |
| [10-multiple-keys-access-control.md](10-multiple-keys-access-control.md) | 多业务密钥的访问控制与区分方案 |
| [11-industry-provisioning-solutions.md](11-industry-provisioning-solutions.md) | 行业通用工厂密钥灌装方案（角色分工/模式对比/开发量估算） |
| [12-platform-api-replacement-analysis.md](12-platform-api-replacement-analysis.md) | 平台黑盒 ql_km/ql_ss API 替换可行性分析与重构方案 |
| [13-openssl-engine-integration.md](13-openssl-engine-integration.md) | tbox_keystore TA → OpenSSL ENGINE 集成方案（TLS 双向认证） |
| [14-brick-recovery-and-best-practices.md](14-brick-recovery-and-best-practices.md) | TEE 设备变砖场景与救砖方案大全（安全存储/RPMB/行业实践） |
| [15-engine-debug-issues.md](15-engine-debug-issues.md) | tbox_keystore ENGINE 调试问题全记录（15 个问题的现象/原因/方案/结果） |
| [16-multi-process-concurrency-analysis.md](16-multi-process-concurrency-analysis.md) | 多进程并发访问 TEE 安全存储的方案分析（keyd 守护进程/缓存/RPMB） |
| [17-https-client-demo.md](17-https-client-demo.md) | HTTPS 客户端 Demo — openssl s_server + TEE ENGINE 客户端 |
| [18-mqtt-mutual-auth-demo.md](18-mqtt-mutual-auth-demo.md) | MQTT 双向认证 Demo — EMQX Broker + TEE ENGINE 客户端 |
| [19-hsm-chip-reference-architecture.md](19-hsm-chip-reference-architecture.md) | 他人架构参考：HSM 安全芯片支撑 MQTTS 方案（含与 OP-TEE 架构对比分析） |
| [20-mqtts-debug-issues.md](20-mqtts-debug-issues.md) | MQTTS 双向认证调试问题全记录（方案/实现/部署/7 个问题） |
| [21-product-manual.md](21-product-manual.md) | **产品说明书** — TBox 安全服务产品定义/架构/场景/灌装/运维/合规 |
| [24-so-pin-yubikey-unlock.md](24-so-pin-yubikey-unlock.md) | SO-PIN + YubiKey 双因子解锁设计（ECDSA P-256 版历史） |
| [25-yubikey-guide.md](25-yubikey-guide.md) | YubiKey 4/5 代对比、PIV 功能详解与操作指南 |
| [26-sgx-provisioning-attestation.md](26-sgx-provisioning-attestation.md) | SGX 远程证明四层次方案（本地/离线签名/云端 SGX） |
| [27-yubikey-provisioning-trusted-server.md](27-yubikey-provisioning-trusted-server.md) | 可信服务器替代 SGX 的产线灌装方案 |
| [28-yubikey-full-lifecycle.md](28-yubikey-full-lifecycle.md) | SO 解锁完整闭环 + 安全缺口分析 |
| [29-rsa-yubikey-provisioning.md](29-rsa-yubikey-provisioning.md) | **最终方案**：RSA-2048 产线灌装与 SO 解锁完整设计 |
| [30-ecc-p256-ta-unsupported-debug-log.md](30-ecc-p256-ta-unsupported-debug-log.md) | TA 不支持 ECC P-256 验签的调试记录（ECDSA transient panic → RSA） |
