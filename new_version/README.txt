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

GUIでやるほうが楽です
neo_pcrypt_GUI.bat
を実行してください

入力ファイル:
  MAMEが復号した後のメインCPUメモリ内容そのもの
    kof2003 / kof2003h : 9MB (0x900000)
    svc / mslug5       : 8MB (0x800000)
  バイト順は 68000ネイティブ(ビッグエンディアン: 先頭 00 10 F3 00) か、
  16bitワードスワップ(先頭 10 00 00 F3) を自動判別します。

その他
(おっさん(人間)より)

メタスラコンプリート分のPROMはMVS復号版と思ってましたが
やっぱり海賊版のようです。
IQさんのはパッチを当てて正規化してたのかと思います。

MVSのメタルスラッグ5だけなにやら動作がおかしいです。
真の復号PROMがよく分からなくなってきましたが
一応選択できるようにしています(どうもうまく暗号化できません)
最終的にメタルスラッグ5MVS版はIQさんの参考に
メタスラコンプリート分での対応とさせることにします
(現状は動作おかしいのですいません)

IQさんのベースではなくMAMEのやつベースになるので  
ライセンス等はそちらになります
