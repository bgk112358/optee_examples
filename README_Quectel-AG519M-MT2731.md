# OP-TEE Sample Applications

This git contains source code for sample host and Trusted Application that can
be used directly in the OP-TEE project.

All official OP-TEE documentation has moved to <http://optee.readthedocs.io>. The
information that used to be here in this git can be found under
[optee_examples].

> // OP-TEE core maintainers

[optee_examples]: https://optee.readthedocs.io/en/latest/building/gits/optee_examples/optee_examples.html


## 设置环境变量

```bash
unset LD_LIBRARY_PATH
source /opt/ql-ol-crosstool/ql-ol-crosstool-env-in
```


## 构建 CA

```bash
cd /home/ubuntu/Documents/Charger/optee_examples_ag519m-mt2731/build
cmake ..
make
```


## 构建 TA

```bash
export ARCH=arm

# 二选一: 根据工具链架构选择路径
export PATH=/opt/ql-ol-crosstool/sysroots/x86_64-oesdk-linux/usr/bin:$PATH
# export PATH=/opt/ql-ol-crosstool/sysroots/x86_64-oesdk-linux/usr/bin/aarch64-poky-linux:$PATH

export PLATFORM=（没有则不用导入环境变量）
export CROSS_COMPILE=aarch64-poky-linux-
export TA_DEV_KIT_DIR=/opt/ql-ol-crosstool/sysroots/cortexa7hf-neon-vfpv4-poky-linux-gnueabi/usr/include/optee/export-user_ta
```


## 修改权限

```bash
sudo chmod 755 /home/ubuntu/Documents/Charger/optee/export-user_ta/scripts/sign.py
```


## 安装 Crypto 模块

### 在线安装

```bash
sudo apt-get download python3-pycryptodome
```

### 离线安装

```bash
uname -m
手动去官网下下载对应的版本（https://pypi.org/project/pycryptodome/#files）
pip3 install pycryptodome-3.23.0-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
```

### 链接模块名路径

```bash
sudo ln -s Cryptodome Crypto
```

### 验证安装

```bash
# 获取 Python 信息
python3 -c "import sys; print(sys.path)"
python3 -c "from Crypto.Signature import PKCS1_v1_5; print('Success')"

# 根据上步获得路径后设置 PYTHONPATH
PYTHONPATH="/home/ubuntu/.local/lib/python3.10/site-packages" python3 -c "from Crypto.Signature import PKCS1_v1_5; print('Success')"
```

### 设置环境变量（重启失效）

```bash
export PYTHONPATH="$HOME/.local/lib/python3.10/site-packages:$PYTHONPATH"
python3 -c "from Crypto.Signature import PKCS1_v1_5; print('Success')"
```


## 编译报错处理

如果编译的时候报错：

```
aarch64-poky-linux-ld.bfd: unrecognized option '-Wl,-O1'
```

执行:

```bash
make LDFLAGS="-O1"
  CC      cus_test_001_ta.o
  CC      user_ta_header.o
  CPP     ta.lds
  LD      7347f239-0373-4295-b0c9-f49d9d5f30cf.elf
  OBJDUMP 7347f239-0373-4295-b0c9-f49d9d5f30cf.dmp
  OBJCOPY 7347f239-0373-4295-b0c9-f49d9d5f30cf.strip
  SIGN    7347f239-0373-4295-b0c9-f49d9d5f30cf.ta
  optee/export-user_ta/scripts/sign.py --key /home/ubuntu/Documents/Charger/optee/export-user_ta/keys/default_ta.pem --uuid 7347f239-0373-4295-b0c9-f49d9d5f30cf --ta-version 0 --in 7347f239-0373-4295-b0c9-f49d9d5f30cf.stripped.elf --out 7347f239-0373-4295-b0c9-f49d9d5f30cf.ta
```


## 开发板部署与测试

开发板默认挂载点 `/lib/optee_armtz` 启用 `adb_verify` 分区保护，无法重新挂载。

```bash
# 查看目录内容
oem# ls
7347f239-0373-4295-b0c9-f49d9d5f30cf.ta    optee_example_cus_test_001

# 直接运行（会失败）
oem# ./optee_example_cus_test_001
optee_example_cus_test_001: TEEC_Opensession failed with code 0xffff0008 origin 0x3
```

### 覆盖一个读写分区来完成

```bash
oem# ls
7347f239-0373-4295-b0c9-f49d9d5f30cf.ta   optee_example_cus_test_001

oem# mount --bind /oem/optee_armtz /lib/optee_arm

oem# ls /lib/optee_armtz/
7347f239-0373-4295-b0c9-f49d9d5f30cf.ta

oem# ./optee_example_cus_test_001
Invoking TA to increment 42
TA incremented value to 43
```