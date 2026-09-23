#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tbox-dongle-sign 自测 —— P1 验证

验证内容：
  1. genkey 能生成 RSA-2048 密钥，权限 0600，且拒绝覆盖
  2. ping / getpub / info 正常
  3. sign 对 32B SHA-256 摘要产出 **256 字节**签名，且能被公钥验证通过
  4. 签名格式与 TA 期望一致（RSA PKCS#1 v1.5 + SHA-256 DigestInfo）
  5. 篡改摘要后验签必须失败
  6. 参数校验：错误长度 / 非 hex 摘要应被拒绝
  7. serve 模式（SSH_ORIGINAL_COMMAND）可用
  8. 公钥 DER 长度符合预期（RSA-2048 SubjectPublicKeyInfo ≈ 294B）

用法：python3 selftest.py [被测程序路径]
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "tbox-dongle-sign")

PASS, FAIL = 0, 0


def check(cond, label):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  PASS  %s" % label)
    else:
        FAIL += 1
        print("  FAIL  %s" % label)


def run(args, home, expect_rc=0, ssh_cmd=None, stdin=None):
    """调用被测程序；返回 (rc, stdout, stderr)。"""
    env = dict(os.environ)
    env["TBOX_DONGLE_SIGN_HOME"] = home
    if ssh_cmd is not None:
        env["SSH_ORIGINAL_COMMAND"] = ssh_cmd

    proc = subprocess.run([BIN] + args, env=env, capture_output=True, input=stdin)
    return proc.returncode, proc.stdout.decode().strip(), proc.stderr.decode().strip()


def main():
    if not os.path.exists(BIN):
        print("找不到被测程序: %s" % BIN, file=sys.stderr)
        return 1

    home = tempfile.mkdtemp(prefix="tbsign-selftest-")
    key_path = os.path.join(home, "keys", "dongle.pem")
    print("临时 HOME: %s\n" % home)

    try:
        # ---- 1. genkey ----
        print("[1] genkey")
        rc, _, err = run(["genkey"], home)
        check(rc == 0, "genkey 返回 0")
        check(os.path.exists(key_path), "私钥文件已创建")
        mode = os.stat(key_path).st_mode & 0o777
        check(mode == 0o600, "私钥权限为 0600（实际 %04o）" % mode)
        rc, _, err = run(["genkey"], home, expect_rc=3)
        check(rc == 3, "重复 genkey 被拒绝（退出码 3）")

        # ---- 2. ping / info ----
        print("\n[2] ping / info")
        rc, out, _ = run(["ping"], home)
        check(rc == 0 and out == "OK", "ping → OK")

        rc, out, _ = run(["info"], home)
        fields = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
        check(rc == 0 and fields.get("key_type") == "RSA-2048", "info 报告 RSA-2048")
        check(int(fields.get("pubkey_der_len", 0)) > 256,
              "公钥 DER 长度 %s > 256B（这正是 §8.6 要放宽上限的原因）"
              % fields.get("pubkey_der_len"))

        # ---- 3. getpub ----
        print("\n[3] getpub")
        rc, out, _ = run(["getpub"], home)
        check(rc == 0, "getpub 返回 0")
        try:
            pub_der = bytes.fromhex(out)
            check(True, "getpub 输出是合法 hex")
        except ValueError:
            pub_der = b""
            check(False, "getpub 输出是合法 hex")
        check(len(pub_der) > 256, "公钥 DER %d 字节" % len(pub_der))

        pubkey = serialization.load_der_public_key(pub_der)

        # ---- 4. sign + 验签 ----
        print("\n[4] sign（核心）")
        digest = hashlib.sha256(b"tbox dongle selftest challenge").digest()
        rc, out, _ = run(["sign", digest.hex()], home)
        check(rc == 0, "sign 返回 0")

        sig = bytes.fromhex(out)
        check(len(sig) == 256, "签名长度 256 字节（RSA-2048），实际 %d" % len(sig))

        # 用公钥验证：Prehashed(SHA256) —— 与 TA 的
        # TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 语义一致
        try:
            pubkey.verify(sig, digest, padding.PKCS1v15(),
                          utils.Prehashed(hashes.SHA256()))
            check(True, "签名可被公钥验证通过（格式与 TA 期望一致）")
        except Exception as exc:  # noqa: BLE001
            check(False, "签名验证失败: %s" % exc)

        # 公钥哈希应与 info 里报的一致（TA 白名单存的就是这个）
        check(hashlib.sha256(pub_der).hexdigest() == fields.get("pubkey_sha256"),
              "info 的 pubkey_sha256 与实取公钥一致")

        # ---- 5. 篡改检测 ----
        print("\n[5] 篡改检测")
        bad_digest = hashlib.sha256(b"tampered").digest()
        try:
            pubkey.verify(sig, bad_digest, padding.PKCS1v15(),
                          utils.Prehashed(hashes.SHA256()))
            check(False, "篡改摘要后验签应失败，但通过了")
        except Exception:  # noqa: BLE001
            check(True, "篡改摘要后验签失败（符合预期）")

        # ---- 6. 参数校验 ----
        print("\n[6] 参数校验")
        rc, _, _ = run(["sign", "ab" * 16], home)   # 16 字节，非 32
        check(rc == 2, "16 字节摘要被拒绝（退出码 2）")
        rc, _, _ = run(["sign", "zzzz"], home)      # 非 hex
        check(rc == 2, "非 hex 摘要被拒绝（退出码 2）")
        rc, _, _ = run(["sign"], home)              # 缺参数
        check(rc == 1, "缺参数被拒绝（退出码 1）")
        rc, _, _ = run(["bogus"], home)             # 未知子命令
        check(rc == 1, "未知子命令被拒绝（退出码 1）")

        # ---- 7. serve 模式（SSH 强制命令）----
        print("\n[7] serve 模式")
        rc, out, _ = run(["serve"], home, ssh_cmd="ping")
        check(rc == 0 and out == "OK", "serve + SSH_ORIGINAL_COMMAND='ping' → OK")

        rc, out, _ = run(["serve"], home, ssh_cmd="sign " + digest.hex())
        check(rc == 0 and len(bytes.fromhex(out)) == 256,
              "serve + 'sign <digest>' → 256B 签名")

        rc, _, _ = run(["serve"], home, ssh_cmd="rm -rf /")   # 企图越权
        check(rc == 1, "serve 拒绝非协议命令（无法获得 shell）")

    finally:
        shutil.rmtree(home, ignore_errors=True)

    print("\n=== 结果: %d passed, %d failed ===" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
