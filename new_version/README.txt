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

その他
(おっさん(人間)より)

現状色々とミスっております
一応CodeMysticsさん分やACA NG分やメタスラコンプリート分を
放り込むだけで変換されるはずでしたが
暗号化後のファイルのバイトスワップ処理忘れてしまったので
現状はご面倒ですが吐き出された暗号化されたファイルを
2byteごと別プログラム等でバイトスワップしてください、申し訳ないです
2byteごとバイトスワップできるプログラムなら何でもいいです
というか入力ファイルのとこ見たら分かると思います
出力ファイルでやるの忘れてました

メタルスラッグ5はプログラム的に一応AES,MVSに
対応しているはずですがAES,MVSのオプションとか忘れました
ルーチンは同じもののROMセットのファイル名も違ってくるので
mslug5hのオプション指定も追加しておきます
SVCも必要ならばJAMMAセット2も追加しておきますが
コレは中身は同じでファイル名が違うのみです

ファイルのCRCチェックとかも行っておりません

できる人はすぐできる修正です
上に書いた不具合を追加すれば終わりです

また修正しておきます
というか不具合修正とCRCチェック機能つけたら終わりです
(AI無料枠なのでAIにやらせます

自分で修正できますがめんどくさいのでやりません
