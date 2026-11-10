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

MB = 0x100000

# ---------------------------------------------------------------- 定義 ----
GAMES = {
    "mslug5": dict(
        desc="Metal Slug 5 (MVS/AES)", size=0x800000, ext=False,
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
        desc="KOF2003 (AES / 'h' set)", size=0x900000, ext=True,
        xor1=bytes([0xc2, 0x4b, 0x74, 0xfd, 0x0b, 0x34, 0xeb, 0xd7, 0x10, 0x6d, 0xf9, 0xce, 0x5d, 0xd5, 0x61, 0x29,
                    0xf5, 0xbe, 0x0d, 0x82, 0x72, 0x45, 0x0f, 0x24, 0xb3, 0x34, 0x1b, 0x99, 0xea, 0x09, 0xf3, 0x03]),
        xor2=bytes([0x2b, 0x09, 0xd0, 0x7f, 0x51, 0x0b, 0x10, 0x4c, 0x5b, 0x07, 0x70, 0x9d, 0x3e, 0x0b, 0xb0, 0xb6,
                    0x54, 0x09, 0xe0, 0xcc, 0x3d, 0x0d, 0x80, 0x99, 0x87, 0x03, 0x90, 0x82, 0xfe, 0x04, 0x20, 0x18]),
        p16=(15, 14, 13, 12, 10, 11, 8, 9, 6, 7, 4, 5, 3, 2, 1, 0),
        sw_a=(7, 6, 5, 4, 1, 0, 3, 2), xor_b=0x400, sw_b=(6, 7, 4, 5, 0, 1, 2, 3),
        files=("271-p1.p1", "271-p2.p2", "271-p3.p3")),
}


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


def main():
    ap = argparse.ArgumentParser(description="復号済みP-ROMをMAME用の暗号化p1/p2(/p3)に変換")
    ap.add_argument("game", choices=GAMES.keys(),
                    help="kof2003=MVS版 / kof2003h=AES版 / svc / mslug5")
    ap.add_argument("input", help="復号済みP-ROM (KOF2003:9MB, SVC/MSLUG5:8MB)")
    ap.add_argument("-o", "--outdir", default=".", help="出力先フォルダ")
    ap.add_argument("--order", choices=["auto", "be", "le"], default="auto",
                    help="入力のバイト順 be=00 10 F3 00 / le=ワードスワップ (既定: 自動)")
    ap.add_argument("--names", help="出力ファイル名を p1,p2[,p3] の順にカンマ区切りで指定")
    ap.add_argument("--no-verify", action="store_true", help="往復検証を省略")
    a = ap.parse_args()

    g = GAMES[a.game]
    data = bytearray(open(a.input, "rb").read())
    if len(data) != g["size"]:
        sys.exit("エラー: サイズが %d バイトです。%s は %d バイト(%dMB)が必要です。"
                 % (len(data), a.game, g["size"], g["size"] // MB))

    order = a.order
    if order == "auto":
        head = bytes(data[:4])
        if head == b"\x00\x10\xf3\x00":
            order = "be"
        elif head == b"\x10\x00\x00\xf3":
            order = "le"
        else:
            sys.exit("エラー: 先頭4バイトが %s で、バイト順を自動判別できません。--order be|le を指定してください。"
                     % head.hex(" "))
    print("入力バイト順: %s" % ("68000ネイティブ(BE)" if order == "be" else "ワードスワップ"))
    D = swap16(data) if order == "be" else data   # 内部表現(MAMEメモリ)へ

    M = mame_encrypt(D, g)
    if not a.no_verify:
        if mame_decrypt(M, g) != D:
            sys.exit("内部エラー: 往復検証に失敗しました。")
        print("往復検証: OK (MAMEの復号処理で元に戻ることを確認)")

    names = list(g["files"])
    if a.names:
        given = a.names.split(",")
        for k, n in enumerate(given[:3]):
            names[k] = n
    os.makedirs(a.outdir, exist_ok=True)
    for name, blob in zip(names, split_files(M, g)):
        path = os.path.join(a.outdir, name)
        with open(path, "wb") as f:
            f.write(blob)
        print("出力: %s (%d bytes)" % (path, len(blob)))


if __name__ == "__main__":
    main()
