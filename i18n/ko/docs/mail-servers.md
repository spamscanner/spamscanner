<!-- source: 1151282f29d3 -->

# 기타 메일 서버

Spam Scanner는 네 가지 프로토콜을 지원하므로, 대부분의 메일 소프트웨어는 전용 플러그인 없이 사용할 수 있습니다.

| 프로토콜   | 명령                                       | 사용하는 소프트웨어                                        |
| ------ | ---------------------------------------- | ------------------------------------------------- |
| Milter | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD(filter-milter 사용)    |
| spamd  | `spamscanner spamd`                      | spamc, Exim, Haraka, 그리고 SpamAssassin용으로 작성된 모든 것 |
| HTTP   | `spamscanner http`                       | 스크립트, 웹훅, 자체 개발 MTA와 서비스                          |
| 파이프    | `spamscanner scan`, `spamscanner filter` | Postfix 파이프, procmail, maildrop, cron 작업          |

[Postfix와 Sendmail](postfix.md)은 별도 페이지에서 다룹니다.


## SpamAssassin의 spamd를 그대로 대체

`spamscanner spamd`는 SpamAssassin의 spamd 프로토콜에 응답합니다. `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING`, 그리고 `--allow-tell`을 사용하면 `TELL`도 지원합니다. SpamAssassin용으로 작성된 소프트웨어는 수정 없이 동작합니다. `spamd`를 중지하고 같은 포트에서 Spam Scanner를 시작하면 됩니다.

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

spamc 사용 예:

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

저장소의 엔드투엔드 테스트에서는 SpamAssassin의 spamc로 직접 Spam Scanner를 테스트합니다.


## Exim

Exim의 `spam` ACL 조건은 spamd와 통신합니다. 메인 설정에 다음을 추가합니다.

```text
spamd_address = 127.0.0.1 783
```

DATA ACL(Debian exim4의 `acl_check_data`)에는 다음을 추가합니다.

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer`는 일시적 4xx 오류로 응답하므로, 발신 서버가 다시 시도하고 잘못된 판정은 바로잡을 수 있습니다. 결과가 적절해 보이면 영구 거부를 위해 `deny`로 바꾸십시오.


## Haraka

Haraka의 `spamassassin` 플러그인은 spamd와 통신합니다. `config/plugins`에서 플러그인을 활성화하고 `config/spamassassin.ini`에 다음을 설정합니다.

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: Junk 폴더와 학습

Sieve 규칙으로 표시된 메일을 Junk 폴더에 넣습니다.

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

IMAPSieve를 사용하면 메시지를 Junk 폴더로 옮기거나 Junk 폴더에서 꺼낼 때 모델을 학습시킬 수 있습니다. 토큰과 모델 파일을 지정해 HTTP API를 시작합니다.

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

그리고 milter나 spamd 서버가 `--model /var/lib/spamscanner/model.json`(또는 `SPAMSCANNER_MODEL`)으로 같은 모델을 사용하도록 지정합니다. 학습한 내용을 반영하려면 가끔 서버를 재시작하십시오. `sieve_pipe`가 실행하는 스크립트가 메시지를 전송합니다.

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

나머지 설정은 Dovecot의 [스팸 신고 가이드](https://doc.dovecot.org/main/core/config/spam_reporting.html)에 나와 있으며, 스크립트로 학습하는 모든 스팸 필터에 똑같이 적용됩니다.


## procmail과 maildrop

```text
# ~/.procmailrc
:0fw
| spamscanner scan - --headers

:0:
* ^X-Spam-Flag: YES
Junk/
```

maildrop:

```text
xfilter "spamscanner scan - --headers"
if (/^X-Spam-Flag: YES/)
{
  to "$HOME/Maildir/.Junk/"
}
```

`scan --headers`는 스팸이면 1로 종료합니다. 위 규칙에서 procmail과 maildrop은 종료 코드가 아니라 출력을 사용합니다.


## HTTP API

HTTP 요청을 보낼 수 있는 프로그램이라면 무엇이든 메일을 검사할 수 있습니다.

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

모든 엔드포인트는 [HTTP API](http-api.md)에 나와 있습니다.


## Node.js 메일 서버 안에서 사용

[smtp-server](https://nodemailer.com/extras/smtp-server/), Haraka 플러그인, 그 밖의 Node.js 서버에서는 라이브러리를 직접 호출합니다.

```js
import SpamScanner from 'spamscanner';

const scanner = new SpamScanner({authentication: true});

// smtp-server's onData handler
async function onData(stream, session, callback) {
  const result = await scanner.scan(stream, {
    session: {
      remoteAddress: session.remoteAddress,
      resolvedClientHostname: session.clientHostname,
      helo: session.hostNameAppearsAs,
      envelope: session.envelope,
    },
  });

  if (result.action === 'reject') {
    const error = new Error('Message rejected as spam');
    error.responseCode = 451;
    return callback(error);
  }

  // Deliver, with result.isSpam deciding the folder.
  callback();
}
```

smtp-server의 `session.envelope`는 이미 Spam Scanner가 읽는 `mailFrom`과 `rcptTo` 구조로 되어 있습니다.
