<!-- source: 599bd320e55a -->

<!--
label: เกี่ยวกับ
title: เกี่ยวกับ Spam Scanner สัญญาอนุญาต และความเป็นส่วนตัว
description: ใครพัฒนา Spam Scanner วิธีแจ้งบั๊กหรือช่องโหว่ สัญญาอนุญาตของมัน และเว็บไซต์นี้เก็บข้อมูลอะไร: ไม่มีคุกกี้และไม่มีระบบวิเคราะห์
keywords: เกี่ยวกับ Spam Scanner, Forward Email, สัญญาอนุญาต Spam Scanner, BUSL-1.1, ติดต่อ Spam Scanner, ความเป็นส่วนตัว Spam Scanner
-->

# เกี่ยวกับ Spam Scanner

Spam Scanner คือตัวกรองสแปมอีเมลที่ [Forward Email](https://forwardemail.net) บริการอีเมลที่เน้นความเป็นส่วนตัว สร้างขึ้นสำหรับเซิร์ฟเวอร์อีเมลของตนเอง ซอร์สโค้ด รายการปัญหา และรุ่นต่าง ๆ อยู่บน [GitHub](https://github.com/spamscanner/spamscanner) ส่วนแพ็กเกจอยู่บน [npm](https://www.npmjs.com/package/spamscanner)


## ใครพัฒนา

ทีม Forward Email เขียนและดูแล Spam Scanner Forward Email ไม่เก็บบันทึกเนื้อหาข้อความ จึงไม่สามารถส่งอีเมลไปยังบริการกรองภายนอกได้ ตัวกรองต้องทำงานบนเซิร์ฟเวอร์ของตนเองและอธิบายทุกการตัดสินโดยไม่มีคนอ่านอีเมล [Forward Email ใช้งานอย่างไร](../../docs/forward-email.md)

Forward Email ก็เป็นโอเพนซอร์สเช่นกัน ที่ [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net) ผู้ก่อตั้งเคยเป็นหนึ่งในพนักงานรุ่นแรกของ DuckDuckGo


## ติดต่อ

* **คำถาม บั๊ก และคำขอฟีเจอร์:** เปิดรายการปัญหาบน [GitHub](https://github.com/spamscanner/spamscanner/issues)
* **ช่องโหว่ด้านความปลอดภัย:** แจ้งแบบส่วนตัวผ่าน [ระบบรายงานช่องโหว่ของ GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new) ไม่ใช่ในรายการปัญหาสาธารณะ ที่อยู่เดียวกันนี้อยู่ใน [security.txt](https://spamscanner.net/.well-known/security.txt)
* **สัญญาอนุญาตแบบอื่น:** ติดต่อ [Forward Email](https://forwardemail.net)


## เงื่อนไขสัญญาอนุญาต

[สัญญาอนุญาต](https://github.com/spamscanner/spamscanner/blob/master/LICENSE)ของ Spam Scanner คือ Business Source License 1.1 โดยมี Apache License 2.0 เป็น Change License วันที่ Change Date ที่ระบุในสัญญาอนุญาตได้ผ่านไปแล้ว และตั้งแต่วันนั้น สัญญาอนุญาตให้สิทธิ์แก่คุณตาม Apache License 2.0


## ความเป็นส่วนตัว

เว็บไซต์นี้ไม่ตั้งคุกกี้ และไม่โหลดระบบวิเคราะห์ ตัวติดตาม โฆษณา ฟอนต์ หรือสคริปต์จากเว็บไซต์อื่น ทุกไฟล์มาจาก spamscanner.net

* ธีม ภาษาที่คุณเลือก และเซิร์ฟเวอร์ Mastodon ที่คุณแชร์ไป จะถูกบันทึกในพื้นที่เก็บข้อมูลภายในของเบราว์เซอร์ และไม่ถูกส่งไปที่ใด
* วิดีโอจะโหลดเมื่อคุณเล่นเท่านั้น
* ลิงก์แชร์เป็นลิงก์ธรรมดา จึงไม่มีอะไรจากเครือข่ายเหล่านั้นโหลดจนกว่าคุณจะเปิดลิงก์
* เว็บไซต์โฮสต์อยู่บน GitHub Pages และ GitHub บันทึกที่อยู่ IP ของผู้เยี่ยมชมทุกคนเพื่อความปลอดภัย ดู [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) และ [คำชี้แจงความเป็นส่วนตัวของ GitHub](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement)


## ซอฟต์แวร์ส่งอะไรออกไป

Spam Scanner ไม่ส่งข้อมูลการใช้งานและไม่ตรวจหาอัปเดต โดยค่าเริ่มต้นจะค้นหาชื่อโฮสต์ของลิงก์ในข้อความบนตัวแปลงชื่อ DNS แบบกรองของ Cloudflare และไม่มีสิ่งอื่นออกจากเครื่อง การตรวจผ่านเครือข่ายอื่น ๆ จะปิดอยู่จนกว่าคุณจะเปิด [ความปลอดภัยและความเป็นส่วนตัว](../../docs/security.md)


## รุ่นที่เผยแพร่

GitHub Actions สร้างไบนารีแบบสแตนด์อโลนจากรีโพสิทอรีสาธารณะ แต่ละรุ่นแสดงค่าแฮชของไบนารีไว้ในไฟล์ `SHA256SUMS` ซึ่งสคริปต์ติดตั้งใช้ตรวจสอบ และไบนารีทุกตัวมีการรับรองแหล่งที่มาของบิลด์แบบลงนาม รุ่นต่าง ๆ และบันทึกประจำรุ่นอยู่บน [GitHub](https://github.com/spamscanner/spamscanner/releases)
