<!-- source: 6f6b765c5fc1 -->

# テストとスコア

メッセージは5点でスパム、15点で拒否になります。以下の各テストが点数を加算または減算し、結果には該当したテストが示されます。

しきい値は`threshold`と`rejectThreshold`で変更します。点数は`scores`で変更します。設定キーで指定する方法（`scores: {deceptiveLink: 4}`）と、テスト名で指定してそのテストの点数を固定する方法（`scores: {FROM_NAME_BRAND: 4}`）があります。


## 分類器

| テスト                    | 点数         | 意味                                                                                                                                                                                                    |
| ---------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BAYES_00`〜`BAYES_999` | -2.5〜+6.25 | 分類器のスパム確率を対数オッズの尺度で表したもの。90%で2.4点、99%で5点、99.9%で6.25点のため、分類器単独でスパムとするのは99%以上の確信がある場合だけです。名前が区間を示します。`BAYES_999`は99.9%以上、`BAYES_99`は99%〜99.9%、`BAYES_50`は40%〜60%です。設定キー`bayesHam`と`bayesSpam`で両端を設定します。 |


## フィッシングとリンク

| テスト                         |  点数 | 設定キー                | 意味                                         |
| --------------------------- | --: | ------------------- | ------------------------------------------ |
| `PHISHING_LOOKALIKE_DOMAIN` |   5 | `homograph`         | リンクのドメインが、紛らわしい文字や入れ替えた文字でブランドを模倣している      |
| `MIXED_SCRIPT_DOMAIN`       |   3 | `mixedScriptDomain` | ドメインのラベルに複数の文字体系が混在している                    |
| `BRAND_IN_DOMAIN`           | 1.5 | `brandInDomain`     | 他人のドメインにブランド名が含まれている                       |
| `TYPO_DOMAIN`               |   1 | `typoDomain`        | ブランドのドメインと1文字違い                            |
| `DECEPTIVE_LINK`            |   3 | `deceptiveLink`     | リンクの表示と宛先が別のアドレスになっている                     |
| `MALICIOUS_DOMAIN`          |   6 | `maliciousDomain`   | Cloudflareのマルウェア対策リゾルバーがリンク先のドメインをブロックしている |
| `ADULT_DOMAIN`              |   2 | `adultDomain`       | Cloudflareのファミリー向けリゾルバーがリンク先のドメインをブロックしている |
| `URIBL_<LIST>`              |   5 | `uriblListed`       | リンク先のドメインがドメインブロックリストに載っている（例：`URIBL_DBL`） |


## 添付ファイル

| テスト                     |    点数 | 設定キー                                    | 意味                                |
| ----------------------- | ----: | --------------------------------------- | --------------------------------- |
| `EXECUTABLE_ATTACHMENT` |    10 | `executable`                            | プログラムまたはスクリプト                     |
| `DISGUISED_EXECUTABLE`  |    12 | `disguisedExecutable`                   | 文書や画像のような名前のプログラム                 |
| `DOUBLE_EXTENSION`      |     6 | `doubleExtension`                       | `invoice.pdf.exe`のような名前           |
| `RTL_OVERRIDE_FILENAME` |     6 | `rtlOverride`                           | 右から左への書字方向の上書きで本当の拡張子を隠している       |
| `EXECUTABLE_IN_ARCHIVE` |     8 | `executableInArchive`                   | ZIPファイル内のプログラム                    |
| `ENCRYPTED_ARCHIVE`     |     2 | `encryptedArchive`                      | スキャナーが開けないアーカイブ                   |
| `MACRO_ATTACHMENT`      |     4 | `macro`                                 | マクロ付きのOfficeファイル                  |
| `PDF_ACTIVE_CONTENT`    |     3 | `pdfActive`                             | JavaScript、起動アクション、埋め込みファイルを含むPDF |
| `RTF_EMBEDDED_OBJECT`   |     4 | `rtfObject`                             | 埋め込みオブジェクトを含むRTFファイル              |
| `HTML_ATTACHMENT`       | 1または3 | `htmlAttachment`、`activeHtmlAttachment` | HTMLファイル。スクリプトやフォームを含む場合は3        |
| `VIRUS`                 |   100 | `virus`                                 | ClamAVがウイルスを検出した                  |


## ルール

| テスト                       |   点数 | 意味                                                       |
| ------------------------- | ---: | -------------------------------------------------------- |
| `GTUBE`                   | 1000 | GTUBEのテスト文字列                                             |
| `SEXTORTION_SUBJECT`      |    6 | セクストーション詐欺やアカウント乗っ取り詐欺で使われる件名                            |
| `PAYPAL_INVOICE`          |    6 | PayPalの請求書または送金リクエスト（詐欺に悪用される経路）                         |
| `MICROSOFT_SPAM_VERDICT`  |    5 | Microsoftが中継する前にメッセージをスパムと判定した（Microsoftのサーバーから来た場合だけ信頼） |
| `MICROSOFT_HIGH_SCL`      |    3 | Microsoftが高いスパム信頼度レベル（SCL）を付けた（同上）                       |
| `PROMPT_INJECTION`        |    3 | AIフィルターに宛てたテキスト                                          |
| `SELF_SPOOF`              |    3 | 受信者自身のドメインから来たと称しているが、認証に通らない                            |
| `FROM_NAME_OTHER_ADDRESS` |  2.5 | 表示名に別のメールアドレスが含まれている                                     |
| `FROM_NAME_BRAND`         |    2 | アドレスが属さないブランドを表示名が名乗っている                                 |
| `DATE_IN_FUTURE`          |    1 | 日付が1日以上先になっている                                           |
| `MISSING_DATE`            |  0.5 | Dateヘッダーがない                                              |
| `MISSING_MESSAGE_ID`      |  0.5 | Message-IDヘッダーがない                                        |

スパムのしきい値以上の点数を持つルールは、以前のバージョンと同じく`results.arbitrary`にも示されます。


## 難読化と言語

| テスト                    |  点数 | 設定キー                  | 意味                        |
| ---------------------- | --: | --------------------- | ------------------------- |
| `INVISIBLE_CHARACTERS` |   2 | `invisibleCharacters` | テキスト内に3つ以上の不可視文字がある       |
| `MIXED_SCRIPT_WORDS`   | 2.5 | `mixedScriptWords`    | 2つ以上の単語で異なる文字体系の文字が混在している |
| `STYLED_LETTERS`       | 1.5 | `styledLetters`       | 通常のテキストに見せかけた数学用文字や囲み文字   |
| `LANGUAGE_NOT_ALLOWED` |   3 | `languageNotAllowed`  | `allowedLanguages`に含まれない  |


## 認証

クライアントのIPアドレスと`authentication: true`が必要です。

| テスト            |   点数 | 設定キー（`authentication.weights`内） |
| -------------- | ---: | ------------------------------- |
| `SPF_PASS`     | -0.5 | `spfPass`                       |
| `SPF_FAIL`     |    2 | `spfFail`                       |
| `SPF_SOFTFAIL` |    1 | `spfSoftfail`                   |
| `DKIM_PASS`    | -0.5 | `dkimPass`                      |
| `DKIM_FAIL`    |    1 | `dkimFail`                      |
| `DMARC_PASS`   | -1.5 | `dmarcPass`                     |
| `DMARC_FAIL`   |  3.5 | `dmarcFail`                     |
| `ARC_PASS`     | -0.5 | `arcPass`                       |
| `ARC_FAIL`     |    1 | `arcFail`                       |


## レピュテーションとブロックリスト

| テスト            |  点数 | 設定キー          | 意味                                       |
| -------------- | --: | ------------- | ---------------------------------------- |
| `DENYLISTED`   | 100 | `denylisted`  | 送信者のIPアドレス、ドメイン、アドレスのいずれかが拒否リストに載っている    |
| `ALLOWLISTED`  | -20 | `allowlisted` | 許可リストに載っている                              |
| `TRUTH_SOURCE` |  -5 | `truthSource` | レピュテーションサービスが送信者を信頼できるとしている              |
| `RBL_<LIST>`   |   4 | `rblListed`   | クライアントのIPアドレスがブロックリストに載っている（例：`RBL_ZEN`） |


## 言語モデルとオプションのモデル

| テスト                                                | 点数   | 設定キー       | 意味                         |
| -------------------------------------------------- | ---- | ---------- | -------------------------- |
| `LLM_SPAM`、`LLM_PHISHING`、`LLM_SCAM`、`LLM_MALWARE` | 最大+6 | `llmSpam`  | モデルの判定に確信度を掛けたもの           |
| `LLM_HAM`                                          | 最小-3 | `llmHam`   | 同上                         |
| `TOXIC_CONTENT`                                    | 3    | `toxicity` | 利用者が用意した有害性判定モデルがテキストを検出した |
| `NSFW_IMAGE`                                       | 3    | `nsfw`     | 利用者が用意した画像モデルが画像を検出した      |
