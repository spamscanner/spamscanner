<!-- source: f1043eb5fc58 -->

# Postfix와 Sendmail

Spam Scanner는 두 가지 방식으로 Postfix와 연동합니다.

* **milter로 연동**(권장). Postfix는 SMTP 세션 중, 메시지를 수락하기 전에 각 메시지에 대해 Spam Scanner에 묻습니다. 스팸은 4xx 또는 5xx 응답으로 거부할 수 있으므로, 처리 책임은 수신 서버가 아니라 발신 서버가 집니다. Sendmail도 같은 프로토콜을 사용합니다.
* **콘텐츠 필터로 연동.** Postfix가 메시지를 수락한 뒤 `spamscanner filter`로 파이프하면, 필터가 헤더를 추가하고 sendmail로 다시 넘겨줍니다. SMTP 세션 중에 거부되는 메일은 없습니다.

두 방식 모두 모든 메시지에 다음 헤더를 추가합니다.

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0
X-Spam-Action: tag
```

메시지에 이미 있는 `X-Spam-*` 헤더는 먼저 제거하므로, 발신자가 자기 메일을 정상으로 표시할 수 없습니다.


## milter

### 1. milter 실행

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

`--reject`를 사용하면 거부 임계값(15점)에 이른 메시지를 `451 4.7.1 Message rejected as spam`으로 거부합니다. 451은 일시적 오류이므로 발신 서버가 나중에 다시 시도하며, 잘못된 판정은 설정을 바꿔 바로잡을 수 있습니다. 결과가 적절해 보이면 `--reject-code 550`으로 영구 거부를 사용하십시오. `--quarantine`을 사용하면 스팸은 거부하는 대신 Postfix의 보류(hold) 큐로 보냅니다.

systemd 서비스로 실행하려면 `/etc/systemd/system/spamscanner-milter.service`에 다음을 작성합니다.

```ini
[Unit]
Description=Spam Scanner milter
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin spamscanner
sudo systemctl daemon-reload
sudo systemctl enable --now spamscanner-milter
```

### 2. Postfix에 milter 지정

`/etc/postfix/main.cf`에 다음을 추가합니다.

```ini
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
# If the milter is down: accept mail unfiltered (accept) or ask senders to retry (tempfail).
milter_default_action = accept
# Long enough for a language model, if one is configured.
milter_content_timeout = 120s
```

```sh
sudo postfix reload
```

`smtpd_milters`는 SMTP로 도착하는 메일에 적용됩니다. `sendmail` 명령으로 제출한 메일도 검사해야 하는 경우가 아니라면 `non_smtpd_milters`는 비워 두십시오.

### 3. 테스트

[swaks](https://www.jetmore.org/john/code/swaks/)로 테스트 메시지를 보냅니다. GTUBE는 모든 스팸 필터가 스팸으로 처리하는 테스트 문자열입니다.

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

`--reject` 없이 실행하면 메시지는 `X-Spam-Flag: YES`와 표시가 붙은 제목으로 전달됩니다. `--reject`를 사용하면 swaks에 451 또는 550 응답이 표시됩니다.


## 콘텐츠 필터

SMTP 세션 중에 메일을 절대 거부하면 안 되는 경우나, milter를 사용할 수 없는 서버에서 이 방식을 사용합니다.

`/etc/postfix/master.cf`에 필터 서비스를 추가하고 SMTP 리스너에서 사용하도록 설정합니다.

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] -f ${sender} -- ${recipient}
```

Postfix는 거의 비어 있는 환경으로 필터를 실행하므로, `argv`에는 Node.js와 스크립트를 전체 경로로 지정합니다(`command -v node`와 `npm root --global`로 경로를 확인할 수 있습니다). 그다음 다음을 실행합니다.

```sh
sudo postfix reload
```

필터는 `sendmail -G -i`로 메시지를 다시 넘겨줍니다. 이렇게 제출한 메일은 `smtp` 리스너를 다시 거치지 않으므로 두 번 필터링되지 않습니다.

종료 코드로 Postfix에 결과를 알립니다. 0은 전달, 69는 거부(`--reject` 사용 시 Postfix가 발신자에게 반송), 75는 일시적 실패(Postfix가 메시지를 보관하고 다시 시도)입니다. 검사나 전달에 실패하면 항상 75이므로, 설정이 잘못되어도 메일이 사라지거나 반송되지 않습니다.


## Sendmail

`sendmail.mc`에 다음을 추가합니다.

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T`를 지정하면 milter를 사용할 수 없는 동안 Sendmail이 일시적 실패로 응답합니다. 대신 필터링 없이 메일을 수락하려면 이 값을 빼십시오. `sendmail.cf`를 다시 빌드하고 Sendmail을 재시작합니다.


## 스팸을 Junk 폴더로 분류

표시만 하면 스팸은 받은편지함으로 전달됩니다. Dovecot에서는 Sieve 규칙으로 스팸을 옮깁니다.

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[기타 메일 서버](mail-servers.md)에서는 Dovecot, Exim, Haraka, procmail을 다루며, [학습](training.md#learning-from-reports)에서는 사용자가 Junk 폴더로 옮기거나 Junk 폴더에서 꺼낸 메일로 학습하는 방법을 설명합니다.


## 테스트 현황

저장소의 엔드투엔드 테스트는 실제 Postfix를 실행합니다. ham은 헤더와 함께 전달되고, 위조된 `X-Spam-Flag`는 제거되고, 스팸은 표시되고, GTUBE는 SMTP 세션 중에 550으로 거부되며, 콘텐츠 필터는 두 번째 포트에서 메일에 표시를 붙입니다. `scripts/e2e-postfix.sh`가 그 Postfix를 설정하고 `test/e2e/postfix.test.js`가 메일을 보냅니다.
