#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
neo_pcrypt.py  -  Neo Geo PVC系カートリッジ P-ROM 再暗号化＆分割ツール

復号済みP-ROM(8MB/9MB)を、MAME用の暗号化済み p1/p2(/p3) に変換します。
対象: KOF2003, SVC CHAOS, METAL SLUG 5  (P-ROMのみ)

暗号化テーブル・ビット置換・ブロック並べ替えの定義は MAME の
src/devices/bus/neogeo/pvc_prot.cpp (BSD-3-Clause,
copyright-holders: S. Smith, David Haywood) の復号処理を逆変換したものです。

使い方:
  python neo_pcrypt.py kof2003  decrypted.bin
  python neo_pcrypt.py kof2003h decrypted.bin -o out
  python neo_pcrypt.py svc      decrypted.bin
  python neo_pcrypt.py mslug5   decrypted.bin

入力ファイル:
  MAMEが復号した後のメインCPUメモリ内容そのもの
    kof2003 / kof2003h : 9MB (0x900000)
    svc / mslug5       : 8MB (0x800000)
  バイト順は 68000ネイティブ(ビッグエンディアン: 先頭 00 10 F3 00) か、
  16bitワードスワップ(先頭 10 00 00 F3) を自動判別します。
"""
import argparse
import os
import sys
import hashlib
import zlib

MB = 0x100000

# ---------------------------------------------------------------- 定義 ----
GAMES = {
    "mslug5": dict(
        desc="Metal Slug 5 (MVS)", size=0x800000, ext=False,
        xor1=bytes([0xc2, 0x4b, 0x74, 0xfd, 0x0b, 0x34, 0xeb, 0xd7, 0x10, 0x6d, 0xf9, 0xce, 0x5d, 0xd5, 0x61, 0x29,
                    0xf5, 0xbe, 0x0d, 0x82, 0x72, 0x45, 0x0f, 0x24, 0xb3, 0x34, 0x1b, 0x99, 0xea, 0x09, 0xf3, 0x03]),
        xor2=bytes([0x36, 0x09, 0xb0, 0x64, 0x95, 0x0f, 0x90, 0x42, 0x6e, 0x0f, 0x30, 0xf6, 0xe5, 0x08, 0x30, 0x64,
                    0x08, 0x04, 0x00, 0x2f, 0x72, 0x09, 0xa0, 0x13, 0xc9, 0x0b, 0xa0, 0x3e, 0xc2, 0x00, 0x40, 0x2b]),
        p16=(15, 14, 13, 12, 10, 11, 8, 9, 6, 7, 4, 5, 3, 2, 1, 0),
        sw_a=(7, 6, 5, 4, 1, 0, 3, 2), xor_b=0x700, sw_b=(5, 4, 7, 6, 1, 0, 3, 2),
        files=("268-p1cr.p1", "268-p2cr.p2", None)),
    "svc": dict(
        desc="SVC CHAOS (MVS/AES)", size=0x800000, ext=False,
        xor1=bytes([0x3b, 0x6a, 0xf7, 0xb7, 0xe8, 0xa9, 0x20, 0x99, 0x9f, 0x39, 0x34, 0x0c, 0xc3, 0x9a, 0xa5, 0xc8,
                    0xb8, 0x18, 0xce, 0x56, 0x94, 0x44, 0xe3, 0x7a, 0xf7, 0xdd, 0x42, 0xf0, 0x18, 0x60, 0x92, 0x9f]),
        xor2=bytes([0x69, 0x0b, 0x60, 0xd6, 0x4f, 0x01, 0x40, 0x1a, 0x9f, 0x0b, 0xf0, 0x75, 0x58, 0x0e, 0x60, 0xb4,
                    0x14, 0x04, 0x20, 0xe4, 0xb9, 0x0d, 0x10, 0x89, 0xeb, 0x07, 0x30, 0x90, 0x50, 0x0e, 0x20, 0x26]),
        p16=(15, 14, 13, 12, 10, 11, 8, 9, 6, 7, 4, 5, 3, 2, 1, 0),
        sw_a=(7, 6, 5, 4, 2, 3, 0, 1), xor_b=0xa00, sw_b=(4, 5, 6, 7, 1, 0, 3, 2),
        files=("269-p1.p1", "269-p2.p2", None)),
    "mslug5h": dict(    # 暗号化ルーチンは mslug5 と同一 (ファイル名のみ家庭用)
        desc="Metal Slug 5 (AES)", base="mslug5",
        files=("268-p1c.p1", "268-p2c.p2", None)),
    "svcpcba": dict(    # 暗号化ルーチンは svc と同一 (ファイル名のみ JAMMA PCB set 2)
        desc="SVC CHAOS (JAMMA PCB set 2 / svcpcba)", base="svc",
        files=("269-p1a.p1", "269-p2a.p2", None)),
    "kof2003": dict(
        desc="KOF2003 (MVS)", size=0x900000, ext=True,
        xor1=bytes([0x3b, 0x6a, 0xf7, 0xb7, 0xe8, 0xa9, 0x20, 0x99, 0x9f, 0x39, 0x34, 0x0c, 0xc3, 0x9a, 0xa5, 0xc8,
                    0xb8, 0x18, 0xce, 0x56, 0x94, 0x44, 0xe3, 0x7a, 0xf7, 0xdd, 0x42, 0xf0, 0x18, 0x60, 0x92, 0x9f]),
        xor2=bytes([0x2f, 0x02, 0x60, 0xbb, 0x77, 0x01, 0x30, 0x08, 0xd8, 0x01, 0xa0, 0xdf, 0x37, 0x0a, 0xf0, 0x65,
                    0x28, 0x03, 0xd0, 0x23, 0xd3, 0x03, 0x70, 0x42, 0xbb, 0x06, 0xf0, 0x28, 0xba, 0x0f, 0xf0, 0x7a]),
        p16=(15, 14, 13, 12, 5, 4, 7, 6, 9, 8, 11, 10, 3, 2, 1, 0),
        sw_a=(7, 6, 5, 4, 0, 1, 2, 3), xor_b=0x800, sw_b=(4, 5, 6, 7, 1, 0, 3, 2),
        files=("271-p1c.p1", "271-p2c.p2", "271-p3c.p3")),
    "kof2003h": dict(
        desc="KOF2003 (AES)", size=0x900000, ext=True,
        xor1=bytes([0xc2, 0x4b, 0x74, 0xfd, 0x0b, 0x34, 0xeb, 0xd7, 0x10, 0x6d, 0xf9, 0xce, 0x5d, 0xd5, 0x61, 0x29,
                    0xf5, 0xbe, 0x0d, 0x82, 0x72, 0x45, 0x0f, 0x24, 0xb3, 0x34, 0x1b, 0x99, 0xea, 0x09, 0xf3, 0x03]),
        xor2=bytes([0x2b, 0x09, 0xd0, 0x7f, 0x51, 0x0b, 0x10, 0x4c, 0x5b, 0x07, 0x70, 0x9d, 0x3e, 0x0b, 0xb0, 0xb6,
                    0x54, 0x09, 0xe0, 0xcc, 0x3d, 0x0d, 0x80, 0x99, 0x87, 0x03, 0x90, 0x82, 0xfe, 0x04, 0x20, 0x18]),
        p16=(15, 14, 13, 12, 10, 11, 8, 9, 6, 7, 4, 5, 3, 2, 1, 0),
        sw_a=(7, 6, 5, 4, 1, 0, 3, 2), xor_b=0x400, sw_b=(6, 7, 4, 5, 0, 1, 2, 3),
        files=("271-p1k.p1", "271-p2k.p2", "271-p3k.p3")),
}


for _k, _g in list(GAMES.items()):
    if "base" in _g:
        _b = dict(GAMES[_g["base"]])
        _b.update(_g)
        GAMES[_k] = _b

# 正規ROMの (CRC32, SHA1)  p1, p2, p3 の順 / None は未登録
# MAME形式 (出力直前の2バイトスワップ適用後) のファイルに対する値
KNOWN_HASH = {
    "kof2003": (
        (0x530ecc14, "812cf7e9902af3f5e9e330b7c05c2171b139ad2b"),
        (0xfd568da9, "46364906a1e81dc251117e91a1a7b43af1373ada"),
        (0xaec5b4a9, "74087f785590eda5898ce146029818f86ced42b6")),
    "kof2003h": (
        (0xd0d0ae3e, "538d054ac50c91694fbbfefcce548b063713e14e"),
        (0xfb3f79d9, "f253d10e732d6e23ae82d74ac9269d21f69ddb4d"),
        (0x232702ad, "6045046027dac1cbd4cbd14b5c1ece522bc6197f")),
    "svc": (
        (0x38e2005e, "1b902905916a30969282f1399a756e32ff069097"),
        (0x6d13797c, "3cb71a95cea6b006b44cac0f547df88aec0007b7"),
        None),
    "mslug5": (
        (0xd0466792, "880819933d997fab398f91061e9dbccb959ae8a1"),
        (0xfbf6b61e, "9ec743d5988b5e3183f37f8edf45c72a8c0c893e"),
        None),
    "mslug5h": (
        (0x3636690a, "e0da714b4bdc6efffe1250ded02ebddb3ab6d7b3"),
        (0x8dfc47a2, "27d618cfbd0107a4d2a836797e967b39d2eb4851"),
        None),
}
KNOWN_HASH["svcpcba"] = KNOWN_HASH["svc"]    # svcpcba は svc と同じ内容


# ------------------------------------------------------------- 部品 ----
def bitswap(val, args):
    """MAME の BITSWAPn と同じ: args は出力の MSB から順に、元のビット番号を並べたもの"""
    n = len(args)
    out = 0
    for k, src in enumerate(args):
        out |= ((val >> src) & 1) << (n - 1 - k)
    return out


def make_tables(args16):
    """16bit置換の順変換/逆変換テーブル"""
    lo = [bitswap(v, args16) for v in range(256)]
    hi = [bitswap(v << 8, args16) for v in range(256)]
    fwd = [lo[v & 0xff] | hi[v >> 8] for v in range(65536)]
    inv = [0] * 65536
    for v, w in enumerate(fwd):
        inv[w] = v
    return fwd, inv


def xor_range(M, start, end, key):
    n = end - start
    k = (key * (n // len(key) + 1))[:n]          # start は 0x20 の倍数
    v = int.from_bytes(M[start:end], "little") ^ int.from_bytes(k, "little")
    M[start:end] = v.to_bytes(n, "little")


def xor_p3(M):
    # for i<1MB: M[0x800000+i] ^= M[0x100002 | i]   (自己逆変換)
    src = M[0x100000:0x200000]
    for i in range(0, MB, 4):
        a, b = src[i + 2], src[i + 3]
        M[0x800000 + i] ^= a
        M[0x800000 + i + 1] ^= b
        M[0x800000 + i + 2] ^= a
        M[0x800000 + i + 3] ^= b


def swap_units(M, start, end, tbl):
    """[start,end) の4バイト毎に M[i+1] | M[i+2]<<8 を表で置換"""
    lo = M[start + 1:end:4]
    hi = M[start + 2:end:4]
    new = [tbl[a | (b << 8)] for a, b in zip(lo, hi)]
    M[start + 1:end:4] = bytes(v & 0xff for v in new)
    M[start + 2:end:4] = bytes(v >> 8 for v in new)


def ofst_a(j, g):
    return (j & 0xf0) + bitswap(j & 0x0f, g["sw_a"])


def ofst_b(i, g):
    return (i & 0xf000ff) + ((i & 0x000f00) ^ g["xor_b"]) + \
           (bitswap((i & 0x0ff000) >> 12, g["sw_b"]) << 12)


# ------------------------------------------------- 復号(検証用)/暗号化 ----
def mame_decrypt(M, g):
    """MAME の復号処理(検証用)。M は暗号化メモリ。復号結果を返す"""
    size, tail = g["size"], g["size"] - MB
    fwd, _ = make_tables(g["p16"])
    M = bytearray(M)
    if g["ext"]:
        xor_p3(M)
    xor_range(M, 0, MB, g["xor1"])
    xor_range(M, MB, 0x800000, g["xor2"])
    swap_units(M, MB, 0x800000, fwd)
    new = bytearray(size)
    for j in range(16):
        o = ofst_a(j, g)
        new[j * 0x10000:(j + 1) * 0x10000] = M[o * 0x10000:(o + 1) * 0x10000]
    for i in range(MB, size, 0x100):
        o = ofst_b(i, g)
        new[i:i + 0x100] = M[o:o + 0x100]
    return bytearray(new[0:MB] + new[tail:size] + new[MB:tail])


def mame_encrypt(D, g):
    """mame_decrypt の逆変換。D は復号済みメモリ。暗号化メモリを返す"""
    size, tail = g["size"], g["size"] - MB
    _, inv = make_tables(g["p16"])
    D = bytearray(D)
    new = bytearray(size)                       # 最終並べ替えの逆
    new[0:MB] = D[0:MB]
    new[tail:size] = D[MB:2 * MB]
    new[MB:tail] = D[2 * MB:size]
    M = bytearray(size)
    for j in range(16):                         # ブロック並べ替えの逆
        o = ofst_a(j, g)
        M[o * 0x10000:(o + 1) * 0x10000] = new[j * 0x10000:(j + 1) * 0x10000]
    for i in range(MB, size, 0x100):
        o = ofst_b(i, g)
        M[o:o + 0x100] = new[i:i + 0x100]
    swap_units(M, MB, 0x800000, inv)            # ビット置換の逆
    xor_range(M, 0, MB, g["xor1"])
    xor_range(M, MB, 0x800000, g["xor2"])
    if g["ext"]:
        xor_p3(M)
    return M


# ----------------------------------------------------- 入出力の並び ----
def swap16(b):
    o = bytearray(len(b))
    o[0::2] = b[1::2]
    o[1::2] = b[0::2]
    return o


def split_files(M, g):
    """メモリ(M) -> MAMEの p1/p2/(p3) ファイル内容 (ファイルは68000ビッグエンディアン)"""
    B = swap16(M)
    b8 = B[:0x800000]
    p1 = bytearray(0x400000)
    p2 = bytearray(0x400000)
    p1[0::2], p1[1::2] = b8[0::4], b8[1::4]
    p2[0::2], p2[1::2] = b8[2::4], b8[3::4]
    out = [p1, p2]
    if g["ext"]:
        out.append(bytearray(B[0x800000:0x900000]))
    return out


def join_files(blobs, g):
    """p1/p2(/p3) ファイル内容(68000ビッグエンディアン) -> メモリ(M)   (split_files の逆)"""
    p1, p2 = blobs[0], blobs[1]
    b8 = bytearray(0x800000)
    b8[0::4], b8[1::4] = p1[0::2], p1[1::2]
    b8[2::4], b8[3::4] = p2[0::2], p2[1::2]
    B = bytearray(g["size"])
    B[:0x800000] = b8
    if g["ext"]:
        B[0x800000:0x900000] = blobs[2]
    return swap16(B)


def known_hash_check(game, blobs):
    """入力ファイルを内蔵の正規ハッシュと照合し [(crc, sha1, 判定), ...] を返す"""
    known = KNOWN_HASH.get(game, (None, None, None))
    out = []
    for k, blob in enumerate(blobs):
        blob = bytes(blob)
        crc = zlib.crc32(blob) & 0xffffffff
        sha = hashlib.sha1(blob).hexdigest()
        if known[k] is None:
            verdict = None
        else:
            verdict = "OK" if (crc == known[k][0] and sha == known[k][1]) else "NG"
        out.append((crc, sha, verdict))
    return out


def decrypt_files(game, blobs, swap_in=True, out_order="be", layout="mame", log=print):
    """
    暗号化済み p1/p2(/p3) -> 復号済みP-ROM (convert の逆変換)
    swap_in : 入力ファイルが2バイトスワップ済み(MAME形式, 既定)か
    out_order: 出力のバイト順 be=00 10 F3 00 / le=ワードスワップ
    layout  : mame=MAME復号後メモリ / complete=268-p1d.bin形式(mslug5専用)
    """
    g = GAMES[game]
    if layout == "complete" and game != "mslug5":
        raise ValueError("completeレイアウトは mslug5 (MVS版) 専用です。")
    need = [0x400000, 0x400000] + ([0x100000] if g["ext"] else [])
    if len(blobs) != len(need):
        raise ValueError("%s には %d 個のファイル(p1/p2%s)が必要です。"
                         % (game, len(need), "/p3" if g["ext"] else ""))
    for k, (b, n) in enumerate(zip(blobs, need)):
        if len(b) != n:
            raise ValueError("p%d のサイズが %d バイトです。%d バイトが必要です。" % (k + 1, len(b), n))

    for k, (crc, sha, verdict) in enumerate(known_hash_check(game, blobs)):
        tag = {"OK": "正規ROMと一致", "NG": "正規ROMと不一致", None: "照合先なし"}[verdict]
        log("入力 p%d: CRC32=%08x  SHA1=%s  [%s]" % (k + 1, crc, sha, tag))

    blobs = [bytearray(b) for b in blobs]
    if swap_in:
        blobs = [swap16(b) for b in blobs]
        log("入力の2バイトスワップを戻しました")
    D = mame_decrypt(join_files(blobs, g), g)     # MAMEメモリ(復号後)

    if layout == "complete":
        C = bytearray(0x800000)
        C[0:MB] = D[0:MB]
        C[MB:0x700000] = D[2 * MB:0x800000]
        C[0x700000:0x800000] = D[MB:2 * MB]
        D = C
        log("出力レイアウト: complete (268-p1d.bin形式)")
    out = swap16(D) if out_order == "be" else D
    log("出力バイト順: %s" % ("68000ネイティブ(BE)" if out_order == "be" else "ワードスワップ"))
    return bytes(out)


def parse_crc_list(text):
    """'aabbccdd,11223344,' -> (0xaabbccdd, 0x11223344, None)"""
    out = []
    for s in (text or "").split(","):
        s = s.strip().lower().replace("0x", "")
        out.append(int(s, 16) if s else None)
    return tuple((out + [None, None, None])[:3])


def convert(game, data, order="auto", swap_out=True, names=None,
            expect_crc=None, verify=True, log=print, layout="mame",
            ms5_aesfix=False, ms5_fillff=False, ms5_autofix=False):
    """
    変換本体 (CLI/GUI共通)。戻り値: [(ファイル名, bytes, crc32, sha1, 判定), ...]
    判定: "OK" / "NG" / None(照合先なし)
    """
    g = GAMES[game]
    data = bytearray(data)
    if (layout == "complete" or ms5_aesfix or ms5_fillff or ms5_autofix) and game != "mslug5":
        raise ValueError("completeレイアウトとIQ互換オプションは mslug5 (MVS版) 専用です。")
    if (ms5_fillff or ms5_autofix) and layout != "complete":
        raise ValueError("0xFF埋めと入力自動補正は --layout complete のときだけ使えます。")
    if layout == "complete":
        # メタスラコンプリート用 268-p1d.bin 形式 (IQ_132氏のms5hpcnv.c と同じ並び):
        #   0-1MB=固定, 1MB以降=バンクデータ (MAMEメモリでは2MB以降に来る分)
        if not 0x500000 <= len(data) <= 0x800000:
            raise ValueError("completeレイアウトの入力は 5MB〜8MB が必要です (現在 %d バイト)。" % len(data))
        data += b"\xff" * (0x800000 - len(data))
        log("入力レイアウト: complete (268-p1d.bin形式, 不足分は0xFFで補完)")
    elif len(data) != g["size"]:
        raise ValueError("サイズが %d バイトです。%s は %d バイト(%dMB)が必要です。"
                         % (len(data), game, g["size"], g["size"] // MB))

    if order == "auto":
        head4 = bytes(data[:4])
        if head4 == b"\x00\x10\xf3\x00":
            order = "be"
        elif head4 == b"\x10\x00\x00\xf3":
            order = "le"
        else:
            raise ValueError("先頭4バイトが %s で、バイト順を自動判別できません。"
                             "バイト順を手動で指定してください。" % head4.hex(" "))
    log("入力バイト順: %s" % ("68000ネイティブ(BE)" if order == "be" else "ワードスワップ"))
    D = swap16(data) if order == "be" else data      # 内部表現(MAMEメモリ)へ
    if layout == "complete":                         # MAME復号後の並びへ変換
        C = D
        if ms5_autofix:                              # IQ_132氏のコードと同じ自動判別
            if C[0x300007] == 0x57:
                log("入力の並び判定: 正常 (補正なし)")
            elif C[0x400007] == 0x57:
                log("入力の並び判定: エミュレータのRAM保存と判断し補正")
                C[0x100000:0x700000] = C[0x200000:0x800000]
            elif C[0x200007] == 0x57:
                log('入力の並び判定: "bootleg" Pと判断し補正')
                C[0x200000:0x300000], C[0x300000:0x400000] = \
                    C[0x300000:0x400000], C[0x200000:0x300000]
            else:
                log("入力の並び判定: 該当なし (補正なし)")
        if ms5_fillff:
            C[0x500000:0x800000] = b"\xff" * 0x300000
            log("0x500000-0x7FFFFF を 0xFF で埋めました")
        D = bytearray(0x800000)
        D[0:MB] = C[0:MB]
        D[MB:2 * MB] = C[0x700000:0x800000]
        D[2 * MB:0x800000] = C[MB:0x700000]

    if ms5_aesfix:                                   # 内部表現(MAMEメモリ)上の 67 00 00 34
        D[0x122A:0x122E] = b"\x00\x67\x34\x00"
        log("AES Fix を除去 (0x122A: beq パッチ) を適用")
    if ms5_aesfix or ms5_fillff or ms5_autofix:
        log("注意: データを書き換えるため、正規ROMとのCRC/SHA1は一致しません")
    M = mame_encrypt(D, g)
    if verify:
        if mame_decrypt(M, g) != D:
            raise RuntimeError("内部エラー: 往復検証に失敗しました。")
        log("往復検証: OK (MAMEの復号処理で元に戻ることを確認)")

    blobs = split_files(M, g)
    if swap_out:                                     # 出力直前の2バイトスワップ
        blobs = [swap16(b) for b in blobs]
        log("出力直前の2バイトスワップ: 適用")

    fnames = list(g["files"])
    for k, n in enumerate(names or []):
        if n:
            fnames[k] = n

    # 期待値: 内蔵の正規ハッシュ表、CRCは手動指定で上書き可
    known = KNOWN_HASH.get(game, (None, None, None))
    exp_crc = [k[0] if k else None for k in known]
    exp_sha = [k[1] if k else None for k in known]
    for k, v in enumerate(expect_crc or ()):
        if v is not None:
            exp_crc[k] = v

    results = []
    for k, blob in enumerate(blobs):
        blob = bytes(blob)
        crc = zlib.crc32(blob) & 0xffffffff
        sha = hashlib.sha1(blob).hexdigest()
        checks = []
        if exp_crc[k] is not None:
            checks.append(crc == exp_crc[k])
        if exp_sha[k] is not None:
            checks.append(sha == exp_sha[k])
        verdict = None if not checks else ("OK" if all(checks) else "NG")
        results.append((fnames[k], blob, crc, sha, verdict))
    return results


def write_results(results, outdir, log=print):
    os.makedirs(outdir, exist_ok=True)
    for name, blob, crc, sha, verdict in results:
        path = os.path.join(outdir, name)
        with open(path, "wb") as f:
            f.write(blob)
        tag = {"OK": "正規ROMと一致", "NG": "正規ROMと不一致", None: "照合先なし"}[verdict]
        log("出力: %s (%d bytes)" % (path, len(blob)))
        log("  CRC32=%08x  SHA1=%s  [%s]" % (crc, sha, tag))


# ----------------------------------------------------------------- CLI ----
def run_cli():
    ap = argparse.ArgumentParser(description="復号済みP-ROMをMAME用の暗号化p1/p2(/p3)に変換")
    ap.add_argument("game", choices=GAMES.keys(),
                    help="kof2003=MVS / kof2003h=AES / svc / svcpcba=JAMMA set2 / "
                         "mslug5=MVS / mslug5h=AES")
    ap.add_argument("input", nargs="+",
                    help="暗号化時: 復号済みP-ROM 1個 (KOF2003:9MB, SVC/MSLUG5:8MB) / "
                         "復号時(-d): p1 p2 [p3] の順にファイルを指定")
    ap.add_argument("-d", "--decrypt", action="store_true",
                    help="復号モード: 暗号化済みp1/p2(/p3) から復号済みP-ROMを作る")
    ap.add_argument("--no-swap-in", dest="swap_in", action="store_false",
                    help="[復号時] 入力が2バイトスワップ済みでない場合に指定 (既定: スワップ済み=MAME形式)")
    ap.add_argument("--out-order", choices=["be", "le"], default="be",
                    help="[復号時] 出力のバイト順 be=00 10 F3 00 / le=ワードスワップ (既定: be)")
    ap.add_argument("--outname", help="[復号時] 出力ファイル名 (既定: <セット名>_decrypted.bin)")
    ap.add_argument("-o", "--outdir", default=".", help="出力先フォルダ")
    ap.add_argument("--order", choices=["auto", "be", "le"], default="auto",
                    help="入力のバイト順 be=00 10 F3 00 / le=ワードスワップ (既定: 自動)")
    ap.add_argument("--no-swap-out", dest="swap_out", action="store_false",
                    help="出力直前の2バイトスワップを行わない (既定: 行う)")
    ap.add_argument("--names", help="出力ファイル名を p1,p2[,p3] の順にカンマ区切りで指定")
    ap.add_argument("--crc", help="内蔵値の代わりに使う期待CRC32を p1,p2[,p3] の順に16進で指定")
    ap.add_argument("--layout", choices=["mame", "complete"], default="mame",
                    help="暗号化時は入力、復号時は出力の並び mame=MAME復号後メモリ / complete=メタスラコンプリートの"
                         "268-p1d.bin形式(5〜8MB, mslug5(MVS)専用)")
    ap.add_argument("--ms5-aesfix", action="store_true",
                    help="[mslug5専用] 0x122AのAES Fixを除去するパッチを当てる")
    ap.add_argument("--ms5-fillff", action="store_true",
                    help="[mslug5専用/complete限定] 0x500000-0x7FFFFFを0xFFで埋める")
    ap.add_argument("--ms5-autofix", action="store_true",
                    help="[mslug5専用/complete限定] RAM保存・bootleg形式の並びを自動補正")
    ap.add_argument("--iq-compat", action="store_true",
                    help="[mslug5専用] --layout complete と上記3つをすべて有効にする")
    ap.add_argument("--no-verify", action="store_true", help="往復検証を省略")
    a = ap.parse_args()
    if a.iq_compat:
        a.layout = "complete"
        if not a.decrypt:
            a.ms5_aesfix, a.ms5_fillff, a.ms5_autofix = True, True, True
    if a.decrypt:
        if a.ms5_aesfix or a.ms5_fillff or a.ms5_autofix:
            sys.exit("エラー: パッチ系オプションは復号時には使えません。")
        try:
            blobs = [open(p, "rb").read() for p in a.input]
            out = decrypt_files(a.game, blobs, a.swap_in, a.out_order, a.layout)
        except (ValueError, RuntimeError, OSError) as e:
            sys.exit("エラー: %s" % e)
        os.makedirs(a.outdir, exist_ok=True)
        path = os.path.join(a.outdir, a.outname or "%s_decrypted.bin" % a.game)
        with open(path, "wb") as f:
            f.write(out)
        print("出力: %s (%d bytes)" % (path, len(out)))
        return
    if len(a.input) != 1:
        sys.exit("エラー: 暗号化時の入力ファイルは1個です (復号するなら -d を付けてください)。")
    try:
        res = convert(a.game, open(a.input[0], "rb").read(), a.order, a.swap_out,
                      a.names.split(",") if a.names else None,
                      parse_crc_list(a.crc) if a.crc else None, not a.no_verify,
                      layout=a.layout, ms5_aesfix=a.ms5_aesfix,
                      ms5_fillff=a.ms5_fillff, ms5_autofix=a.ms5_autofix)
    except (ValueError, RuntimeError, OSError) as e:
        sys.exit("エラー: %s" % e)
    write_results(res, a.outdir)
    if any(r[4] == "NG" for r in res):
        sys.exit(2)


# ----------------------------------------------------------------- GUI ----
def run_gui():
    import queue
    import threading
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk

    root = tk.Tk()
    root.title("Neo Geo PVC P-ROM 暗号化・分割ツール")
    root.columnconfigure(1, weight=1)

    keys = list(GAMES.keys())
    labels = ["%s  -  %s" % (k, GAMES[k]["desc"]) for k in keys]
    v_set = tk.StringVar(value=labels[0])
    v_in = tk.StringVar()
    v_out = tk.StringVar()
    v_order = tk.StringVar(value="auto")
    v_layout = tk.StringVar(value="mame")
    v_aes = tk.BooleanVar(value=False)
    v_ff = tk.BooleanVar(value=False)
    v_auto = tk.BooleanVar(value=False)
    v_verify = tk.BooleanVar(value=True)
    v_dec = tk.BooleanVar(value=False)
    v_p2 = tk.StringVar()
    v_p3 = tk.StringVar()
    v_decname = tk.StringVar()
    v_outorder = tk.StringVar(value="be")
    v_names = [tk.StringVar() for _ in range(3)]
    v_crcs = [tk.StringVar() for _ in range(3)]
    pad = dict(padx=6, pady=3)

    def cur_key():
        return keys[labels.index(v_set.get())]

    def on_set(*_):
        g = GAMES[cur_key()]
        is_ms5 = cur_key() == "mslug5"
        if not is_ms5:                       # MVS版メタスラ5以外では選べない
            v_layout.set("mame")
            v_aes.set(False)
            v_ff.set(False)
            v_auto.set(False)
        cb_layout.config(values=["mame", "complete"] if is_ms5 else ["mame"])
        decm = v_dec.get()
        for c in chk_ms5:
            c.config(state="normal" if (is_ms5 and not decm) else "disabled")
        for w in ent_dec[:-1]:
            w.config(state="normal" if decm else "disabled")
        ent_dec[-1].config(state="readonly" if decm else "disabled")
        if decm and not g["ext"]:
            ent_dec[2].config(state="disabled")      # p3 入力欄 (p3なしのセット)
            ent_dec[3].config(state="disabled")
        lbl_layout.config(text="出力レイアウト" if decm else "入力レイアウト")
        btn.config(text="復号開始" if decm else "変換開始")
        if decm and not v_decname.get():
            v_decname.set("%s_decrypted.bin" % cur_key())
        for k in range(3):
            v_names[k].set(g["files"][k] or "")
            ent_n[k].config(state="normal" if g["files"][k] else "disabled")
            ent_c[k].config(state="normal" if g["files"][k] else "disabled")
        lbl_size.config(text="入力サイズ: %d MB (%d バイト)%s" % (
            g["size"] // MB, g["size"], " / complete形式は5〜8MB" if is_ms5 else ""))

    ttk.Label(root, text="対象セット").grid(row=0, column=0, sticky="e", **pad)
    cb = ttk.Combobox(root, textvariable=v_set, values=labels, state="readonly", width=52)
    cb.grid(row=0, column=1, columnspan=2, sticky="we", **pad)
    cb.bind("<<ComboboxSelected>>", on_set)
    lbl_size = ttk.Label(root, text="")
    lbl_size.grid(row=1, column=1, sticky="w", **pad)

    def pick_in():
        p = filedialog.askopenfilename(title="復号済みP-ROMを選択")
        if p:
            v_in.set(p)
            if not v_out.get():
                v_out.set(os.path.dirname(p))

    def pick_out():
        p = filedialog.askdirectory(title="出力先フォルダ")
        if p:
            v_out.set(p)

    ttk.Label(root, text="入力ファイル").grid(row=2, column=0, sticky="e", **pad)
    ttk.Entry(root, textvariable=v_in).grid(row=2, column=1, sticky="we", **pad)
    ttk.Button(root, text="参照...", command=pick_in).grid(row=2, column=2, **pad)
    ttk.Label(root, text="出力先").grid(row=3, column=0, sticky="e", **pad)
    ttk.Entry(root, textvariable=v_out).grid(row=3, column=1, sticky="we", **pad)
    ttk.Button(root, text="参照...", command=pick_out).grid(row=3, column=2, **pad)

    ttk.Label(root, text="入力バイト順").grid(row=4, column=0, sticky="e", **pad)
    ttk.Combobox(root, textvariable=v_order, values=["auto", "be", "le"], state="readonly",
                 width=8).grid(row=4, column=1, sticky="w", **pad)
    lbl_layout = ttk.Label(root, text="入力レイアウト")
    lbl_layout.grid(row=5, column=0, sticky="e", **pad)
    cb_layout = ttk.Combobox(root, textvariable=v_layout, values=["mame", "complete"],
                             state="readonly", width=10)
    cb_layout.grid(row=5, column=1, sticky="w", **pad)
    ttk.Label(root, text="※出力は常に2バイトスワップ").grid(row=5, column=2, sticky="e", **pad)
    ms5 = ttk.LabelFrame(root, text="メタルスラッグ5 (MVS) 専用: IQ_132氏ツール互換")
    ms5.grid(row=10, column=0, columnspan=3, sticky="we", **pad)
    chk_ms5 = [
        ttk.Checkbutton(ms5, text="AES Fix除去パッチ (0x122A)", variable=v_aes),
        ttk.Checkbutton(ms5, text="0x500000-0x7FFFFF を 0xFF で埋める (completeのみ)", variable=v_ff),
        ttk.Checkbutton(ms5, text="RAM保存/bootleg形式を自動補正 (completeのみ)", variable=v_auto),
    ]
    for k, c in enumerate(chk_ms5):
        c.grid(row=k, column=0, sticky="w", **pad)
    ttk.Checkbutton(root, text="往復検証を行う", variable=v_verify
                    ).grid(row=6, column=1, columnspan=2, sticky="w", **pad)

    frm = ttk.LabelFrame(root, text="出力ファイル名 / 期待CRC32(空欄=内蔵値)")
    frm.grid(row=7, column=0, columnspan=3, sticky="we", **pad)
    frm.columnconfigure(1, weight=1)
    ent_n, ent_c = [], []
    for k, t in enumerate(("p1", "p2", "p3")):
        ttk.Label(frm, text=t).grid(row=k, column=0, **pad)
        e1 = ttk.Entry(frm, textvariable=v_names[k])
        e1.grid(row=k, column=1, sticky="we", **pad)
        e2 = ttk.Entry(frm, textvariable=v_crcs[k], width=12)
        e2.grid(row=k, column=2, **pad)
        ent_n.append(e1)
        ent_c.append(e2)

    dec = ttk.LabelFrame(root, text="復号モード (暗号化済み p1/p2/p3 → 復号済みP-ROM)")
    dec.grid(row=9, column=0, columnspan=3, sticky="we", **pad)
    dec.columnconfigure(1, weight=1)

    def pick_file(var):
        p = filedialog.askopenfilename(title="暗号化済みファイルを選択")
        if p:
            var.set(p)

    ttk.Checkbutton(dec, text="復号モードにする (上の「入力ファイル」= p1)", variable=v_dec,
                    command=lambda: on_set()).grid(row=0, column=0, columnspan=3, sticky="w", **pad)
    ent_dec = []
    for r, (t, var) in enumerate((("入力 p2", v_p2), ("入力 p3", v_p3)), start=1):
        ttk.Label(dec, text=t).grid(row=r, column=0, sticky="e", **pad)
        e = ttk.Entry(dec, textvariable=var)
        e.grid(row=r, column=1, sticky="we", **pad)
        b = ttk.Button(dec, text="参照...", command=lambda v=var: pick_file(v))
        b.grid(row=r, column=2, **pad)
        ent_dec += [e, b]
    ttk.Label(dec, text="出力ファイル名").grid(row=3, column=0, sticky="e", **pad)
    e = ttk.Entry(dec, textvariable=v_decname)
    e.grid(row=3, column=1, sticky="we", **pad)
    ent_dec.append(e)
    ttk.Label(dec, text="出力バイト順").grid(row=4, column=0, sticky="e", **pad)
    c = ttk.Combobox(dec, textvariable=v_outorder, values=["be", "le"], state="readonly", width=6)
    c.grid(row=4, column=1, sticky="w", **pad)
    ent_dec.append(c)

    logbox = scrolledtext.ScrolledText(root, height=12, width=80, state="disabled")
    logbox.grid(row=11, column=0, columnspan=3, sticky="nsew", **pad)
    root.rowconfigure(11, weight=1)
    q = queue.Queue()

    def log(msg):
        q.put(msg)

    def work_dec(key, paths, outdir):
        try:
            out = decrypt_files(key, [open(p, "rb").read() for p in paths], True,
                                v_outorder.get(), v_layout.get(), log)
            os.makedirs(outdir, exist_ok=True)
            path = os.path.join(outdir, v_decname.get() or "%s_decrypted.bin" % key)
            with open(path, "wb") as f:
                f.write(out)
            log("出力: %s (%d bytes)" % (path, len(out)))
            log("完了")
        except Exception as e:                       # noqa
            log("エラー: %s" % e)
        finally:
            q.put("__done__")

    def work(key, path, outdir):
        try:
            crcs = parse_crc_list(",".join(v.get() for v in v_crcs))
            res = convert(key, open(path, "rb").read(), v_order.get(), True,
                          [v.get() for v in v_names], crcs, v_verify.get(), log,
                          layout=v_layout.get(), ms5_aesfix=v_aes.get(),
                          ms5_fillff=v_ff.get(), ms5_autofix=v_auto.get())
            write_results(res, outdir, log)
            bad = [r[0] for r in res if r[4] == "NG"]
            log("完了" if not bad else "完了 (正規ROMと不一致: %s)" % ", ".join(bad))
        except Exception as e:                       # noqa
            log("エラー: %s" % e)
        finally:
            q.put("__done__")

    def start():
        if not v_in.get() or not os.path.isfile(v_in.get()):
            messagebox.showerror("エラー", "入力ファイルを選択してください。")
            return
        outdir = v_out.get() or os.path.dirname(v_in.get())
        if v_dec.get():
            paths = [v_in.get(), v_p2.get()] + ([v_p3.get()] if GAMES[cur_key()]["ext"] else [])
            if not all(p and os.path.isfile(p) for p in paths):
                messagebox.showerror("エラー", "p1/p2%sのファイルをすべて選択してください。"
                                     % ("/p3" if GAMES[cur_key()]["ext"] else ""))
                return
            btn.config(state="disabled")
            log("---- %s (復号) ----" % cur_key())
            threading.Thread(target=work_dec, args=(cur_key(), paths, outdir), daemon=True).start()
            return
        btn.config(state="disabled")
        log("---- %s ----" % cur_key())
        threading.Thread(target=work, args=(cur_key(), v_in.get(), outdir), daemon=True).start()

    btn = ttk.Button(root, text="変換開始", command=start)
    btn.grid(row=8, column=1, **pad)

    def poll():
        try:
            while True:
                m = q.get_nowait()
                if m == "__done__":
                    btn.config(state="normal")
                    continue
                logbox.config(state="normal")
                logbox.insert("end", m + "\n")
                logbox.see("end")
                logbox.config(state="disabled")
        except queue.Empty:
            pass
        root.after(100, poll)

    on_set()
    poll()
    root.mainloop()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_cli()
    else:
        run_gui()
