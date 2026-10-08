<!-- source: c061da9312ad -->

# บรรทัดคำสั่ง

```text
spamscanner <command> [options]
```

| คำสั่ง                                     | สิ่งที่ทำ                                                              |
| ------------------------------------------ | ---------------------------------------------------------------------- |
| `scan [file\|-]`                           | สแกนข้อความจากไฟล์หรือ standard input                                  |
| `filter -f <sender> -- <recipients...>`    | ตัวกรองเนื้อหาของ Postfix: สแกน standard input เพิ่มส่วนหัว แล้วส่งต่อ |
| `milter`                                   | milter สำหรับ Postfix และ Sendmail พอร์ต 7831                          |
| `http`                                     | HTTP API พอร์ต 7832                                                    |
| `server`                                   | เซิร์ฟเวอร์ TCP แบบธรรมดา พอร์ต 7830                                   |
| `spamd`                                    | เซิร์ฟเวอร์ spamd ที่เข้ากันได้กับ SpamAssassin พอร์ต 783              |
| `train`                                    | ฝึกโมเดลจากไฟล์ mbox, Maildir, โฟลเดอร์ หรือชุดข้อมูล                  |
| `eval`                                     | วัดผลโมเดลกับอีเมลที่ติดป้ายกำกับแล้ว                                  |
| `learn spam\|ham [file\|-] --model <file>` | สอนโมเดลด้วยข้อความหนึ่งข้อความ                                        |
| `llm-test`                                 | ตรวจการตั้งค่าโมเดลภาษาด้วยข้อความตัวอย่างสามข้อความ                   |
| `models`                                   | แสดงรายการโมเดลแบบเปิดที่แนะนำ                                         |
| `version`, `help`                          |                                                                        |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| ตัวเลือก                   | ความหมาย                                            |
| -------------------------- | --------------------------------------------------- |
| `--json`                   | พิมพ์ผลลัพธ์ฉบับเต็มเป็น JSON                       |
| `--headers`                | พิมพ์ข้อความพร้อมส่วนหัว `X-Spam-*` ที่เพิ่มเข้าไป  |
| `--subject-tag <tag>`      | เติมคำนำหน้าหัวเรื่องของสแปมด้วย                    |
| `--verbose`                | แสดงทุกการทดสอบ และเบาะแสที่แรงที่สุดของตัวจำแนก    |
| `--threshold <n>`          | คะแนนที่อีเมลถือเป็นสแปม (ค่าเริ่มต้น 5)            |
| `--reject-threshold <n>`   | คะแนนที่อีเมลถูกปฏิเสธ (ค่าเริ่มต้น 15)             |
| `--model <file>`           | ไฟล์โมเดลที่ใช้แทนโมเดลที่มาพร้อมแพ็กเกจ            |
| `--no-classifier`          | ไม่ใช้ตัวจำแนก                                      |
| `--config <file>`          | ไฟล์ JSON ที่มี[ตัวเลือกของไลบรารี](api.md#options) |
| `--allow-language <codes>` | ภาษาที่ยอมรับ เช่น `en,de,fr`                       |

รหัสออก: 0 คือ ham, 1 คือสแปม, 2 คือข้อผิดพลาด

### เซสชัน SMTP

| ตัวเลือก            | ความหมาย                                  |
| ------------------- | ----------------------------------------- |
| `--ip <address>`    | ที่อยู่ IP ของไคลเอนต์ที่ส่งข้อความ       |
| `--hostname <name>` | ชื่อ reverse DNS ของไคลเอนต์ที่ยืนยันแล้ว |
| `--helo <name>`     | ชื่อที่ไคลเอนต์ให้ไว้ใน HELO หรือ EHLO    |
| `--from <address>`  | ผู้ส่งใน envelope (MAIL FROM)             |
| `--to <address>`    | ผู้รับใน envelope ระบุซ้ำได้หากมีหลายราย  |

### การตรวจ

| ตัวเลือก              | ความหมาย                                                        |
| --------------------- | --------------------------------------------------------------- |
| `--auth`              | ตรวจ SPF, DKIM, DMARC และ ARC (ต้องใช้ `--ip`)                  |
| `--dnsbl <zone>`      | IP blocklist เช่น `zen.spamhaus.org` ระบุซ้ำได้                 |
| `--uribl <zone>`      | Domain blocklist สำหรับลิงก์ เช่น `dbl.spamhaus.org` ระบุซ้ำได้ |
| `--dns-server <ip>`   | name server สำหรับการตรวจทาง DNS ระบุซ้ำได้                     |
| `--no-cloudflare`     | ไม่ถาม resolver แบบกรองของ Cloudflare เกี่ยวกับลิงก์            |
| `--clamav [socket]`   | สแกนไฟล์แนบด้วย clamd ที่ซ็อกเก็ตค่าเริ่มต้นหรือซ็อกเก็ตที่ระบุ |
| `--allowlist <value>` | รับที่อยู่ IP โดเมน หรือที่อยู่อีเมลนี้เสมอ ระบุซ้ำได้          |
| `--denylist <value>`  | ปฏิเสธที่อยู่ IP โดเมน หรือที่อยู่อีเมลนี้เสมอ ระบุซ้ำได้       |

### โมเดลภาษา

| ตัวเลือก                                                   | ความหมาย                                                                                                                                          |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--llm <provider>`                                         | `ollama`, `clef-flash`, `jev`, `openai`, `anthropic` และอื่น ๆ ([รายการ](llm.md#providers))                                                       |
| `--llm-model <name>`                                       | โมเดล เช่น `qwen3.5:4b` หรือ `claude-haiku-4-5`                                                                                                   |
| `--llm-method <method>`                                    | `decision` (ความน่าจะเป็นของผลตัดสินแต่ละแบบในขั้นตอนเดียว เป็นค่าเริ่มต้นเมื่อรองรับ) หรือ `generate` ([วิธีการ](llm.md#decision-or-generation)) |
| `--llm-account <id>`                                       | ID บัญชี Cloudflare สำหรับ `clef` และ `clef-flash`                                                                                                |
| `--llm-url <url>`                                          | URL ฐาน เช่น `http://10.0.0.5:11434`                                                                                                              |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | เปลี่ยนส่วนใดส่วนหนึ่งของ URL ของผู้ให้บริการ                                                                                                     |
| `--llm-api-key <key>`                                      | API key ดูตัวแปรสภาพแวดล้อมด้านล่างด้วย                                                                                                           |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header` หรือ `none`                                                                                   |
| `--llm-auth-header <name>`                                 | ส่วนหัวสำหรับ key ใช้กับ `--llm-auth header`                                                                                                      |
| `--llm-username`, `--llm-password`                         | สำหรับ `--llm-auth basic`                                                                                                                         |
| `--llm-header "Name: value"`                               | ส่วนหัวคำขอเพิ่มเติม ระบุซ้ำได้                                                                                                                   |
| `--llm-mode <mode>`                                        | `auto` (เฉพาะกรณีที่ตัดสินยาก เป็นค่าเริ่มต้น) หรือ `always`                                                                                      |
| `--llm-timeout <ms>`                                       | ค่าเริ่มต้น 30000                                                                                                                                 |
| `--llm-policy <text>`                                      | กฎเพิ่มเติมสำหรับโมเดล เช่น "We never send invoices"                                                                                              |
| `--llm-redact`, `--no-llm-redact`                          | ลบข้อมูลส่วนบุคคลออกก่อน เปิดไว้โดยค่าเริ่มต้นสำหรับผู้ให้บริการระยะไกล                                                                           |


## filter

[ตัวกรองเนื้อหาของ Postfix](postfix.md#content-filter) อ่านข้อความจาก standard input เพิ่มส่วนหัว `X-Spam-*` แล้วส่งต่อให้ sendmail ด้วย envelope เดิม

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| ตัวเลือก              | ความหมาย                                 |
| --------------------- | ---------------------------------------- |
| `--sendmail <path>`   | ค่าเริ่มต้น `/usr/sbin/sendmail`         |
| `--subject-tag <tag>` | เติมคำนำหน้าหัวเรื่องของสแปม             |
| `--reject`            | ตีกลับอีเมลที่ถึงเกณฑ์ปฏิเสธแทนการส่งต่อ |
| `--discard`           | ทิ้งอีเมลที่ถึงเกณฑ์ปฏิเสธแทนการส่งต่อ   |

รหัสออกเป็นไปตามข้อตกลงของ sendmail ซึ่ง Postfix อ่าน: 0 ส่งแล้ว (หรือทิ้งแล้ว), 64 ไม่ได้ระบุผู้รับ, 69 ถูกปฏิเสธเพราะเป็นสแปม (Postfix จะตีกลับ), 75 ความล้มเหลวใด ๆ ซึ่ง Postfix จะเก็บข้อความไว้และลองใหม่ภายหลัง


## milter, http, server และ spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

พอร์ต 783 คือพอร์ตที่ไคลเอนต์ของ SpamAssassin ใช้โดยค่าเริ่มต้น พอร์ตที่ต่ำกว่า 1024 ต้องใช้ root หรือ capability `CAP_NET_BIND_SERVICE` หรือใช้พอร์ตอื่น เช่น `--port 7833` แล้วแจ้งไคลเอนต์

| ตัวเลือก              | ความหมาย                                                                    |
| --------------------- | --------------------------------------------------------------------------- |
| `--port <n>`          | พอร์ต TCP                                                                   |
| `--host <ip>`         | ที่อยู่ที่รอรับการเชื่อมต่อ (ค่าเริ่มต้น 127.0.0.1)                         |
| `--socket <path>`     | รอรับบน Unix socket แทน                                                     |
| `--reject`            | Milter: ปฏิเสธอีเมลที่ถึงเกณฑ์ปฏิเสธ                                        |
| `--reject-code <n>`   | Milter: 451 ให้ลองใหม่ภายหลัง (ค่าเริ่มต้น) หรือ 550                        |
| `--quarantine`        | Milter: กักสแปมไว้ในพื้นที่กักกันของเซิร์ฟเวอร์อีเมล                        |
| `--name <hostname>`   | Milter: ชื่อของเซิร์ฟเวอร์นี้ใน Authentication-Results                      |
| `--token <secret>`    | HTTP: กำหนดให้ต้องมี `Authorization: Bearer <secret>` จำเป็นสำหรับ `/learn` |
| `--allow-tell`        | spamd: รับคำขอ TELL (`spamc -L spam`) เพื่อเรียนรู้                         |
| `--out <file>`        | HTTP และ spamd: บันทึกสิ่งที่เรียนรู้ลงไฟล์โมเดลนี้                         |
| `--subject-tag <tag>` | Milter และ spamd: เติมคำนำหน้าหัวเรื่องของสแปม                              |
| `--verbose`           | Milter: บันทึกล็อกทุกการสแกน เซิร์ฟเวอร์ TCP: ตอบเป็นข้อความบรรทัดเดียว     |

ตัวเลือกการสแกนด้านบนใช้กับเซิร์ฟเวอร์ได้ด้วย [milter](postfix.md#milter), [HTTP API, เซิร์ฟเวอร์ TCP และ spamd](http-api.md)


## train, eval และ learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| ตัวเลือก                                        | ความหมาย                                                            |
| ----------------------------------------------- | ------------------------------------------------------------------- |
| `--spam <path>`                                 | สแปม: ไฟล์ mbox, Maildir หรือโฟลเดอร์ของไฟล์ `.eml` ระบุซ้ำได้      |
| `--ham <path>`                                  | Ham เช่นเดียวกัน ระบุซ้ำได้                                         |
| `--dataset <file>`                              | ไฟล์ CSV หรือ JSON Lines ที่มีคอลัมน์ข้อความและป้ายกำกับ ระบุซ้ำได้ |
| `--text-column <name>`, `--label-column <name>` | ชื่อคอลัมน์ เมื่อตรวจหาเองไม่พบ                                     |
| `--out <file>`                                  | ตำแหน่งที่จะเขียนโมเดล (ค่าเริ่มต้น `spamscanner-model.json`)       |
| `--merge`                                       | เริ่มจากโมเดลที่มาพร้อมแพ็กเกจ (หรือ `--model`) แทนโมเดลว่าง        |

`learn` อัปเดตไฟล์โมเดลในที่เดิม และสร้างจากโมเดลที่มาพร้อมแพ็กเกจในครั้งแรก [การฝึกโมเดล](training.md)


## llm-test และ models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test` ส่งข้อความทั่วไปหนึ่งข้อความและข้อความหลอกลวงสองข้อความ เป็นภาษาอังกฤษและภาษาอิตาลี ไปให้โมเดล พิมพ์ผลตัดสิน เวลาที่ใช้ในแต่ละข้อความ วิธีการที่ใช้ และฮาร์ดแวร์ แล้วออกด้วยรหัส 0 เฉพาะเมื่อตอบถูกทั้งสามข้อความ


## ไฟล์การตั้งค่า

`--config file.json` (หรือตัวแปรสภาพแวดล้อม `SPAMSCANNER_CONFIG`) โหลด[ตัวเลือกของไลบรารี](api.md#options) ตัวเลือกบรรทัดคำสั่งมีผลเหนือค่าในไฟล์

```json
{
  "threshold": 6,
  "authentication": true,
  "dnsbl": {"ip": ["zen.spamhaus.org"], "domain": ["dbl.spamhaus.org"]},
  "dns": {"servers": ["127.0.0.1"]},
  "clamav": {"socket": "/var/run/clamav/clamd.ctl"},
  "llm": {"provider": "ollama", "model": "qwen3.5:4b"},
  "scores": {"deceptiveLink": 4, "FROM_NAME_BRAND": 3}
}
```


## ตัวแปรสภาพแวดล้อม

| ตัวแปร                                                                                                                                                                                                                                                                                                                       | ความหมาย                                   |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                                                                                         | ไฟล์การตั้งค่า                             |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                                                                                          | ไฟล์โมเดลที่ใช้แทนโมเดลที่มาพร้อมแพ็กเกจ   |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                                                                                          | โทเค็นสำหรับ HTTP API                      |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                                                                                                    | API key สำหรับผู้ให้บริการโมเดลภาษาใดก็ได้ |
| `CLOUDFLARE_API_TOKEN` และ `CLOUDFLARE_ACCOUNT_ID`, `TYPESAFE_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | key ของผู้ให้บริการแต่ละราย                |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                                                                                                    | ล็อกสำหรับดีบัก                            |
