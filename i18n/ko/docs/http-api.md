<!-- source: faf44f093f8b -->

# HTTP API, TCP 서버, spamd


## HTTP API

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

`--host`로 달리 지정하지 않는 한 127.0.0.1에서 수신합니다. 토큰을 설정하면 `/health`를 제외한 모든 요청에 `Authorization: Bearer <token>`이 필요합니다. 이 컴퓨터 밖으로 공개하기 전에는 TLS를 쓰는 리버스 프록시 뒤에 두십시오.

| 메서드와 경로            | 본문     | 응답                                           |
| ------------------ | ------ | -------------------------------------------- |
| `GET /health`      |        | `{"ok": true, "version": "7.0.0"}`           |
| `POST /scan`       | 원본 메시지 | JSON 형식의 [검사 결과](api.md#the-result)          |
| `POST /check`      | 원본 메시지 | `X-Spam-*` 헤더를 추가한 메시지(`message/rfc822` 형식)  |
| `POST /learn/spam` | 원본 메시지 | `{"ok": true, "learned": "spam"}`. 토큰이 필요합니다 |
| `POST /learn/ham`  | 원본 메시지 | `{"ok": true, "learned": "ham"}`. 토큰이 필요합니다  |

쿼리 매개변수로 SMTP 세션 정보를 전달합니다.

| 매개변수         | 의미                                          |
| ------------ | ------------------------------------------- |
| `ip`         | 클라이언트 IP 주소                                 |
| `hostname`   | 검증된 역방향 DNS 이름                              |
| `helo`       | HELO 또는 EHLO 이름                             |
| `from`       | 엔벌로프 발신자                                    |
| `to`         | 수신자. 여러 번 지정하거나 쉼표로 구분해 여러 명을 지정합니다         |
| `verbose=1`  | `/scan`: 단어 목록과 제목도 반환합니다                   |
| `subjectTag` | `/check`: 스팸의 제목 앞에 붙일 문자열. 예: `%5BSPAM%5D` |

`/check`는 `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Action`도 응답 헤더로 반환하므로, 클라이언트는 메시지를 파싱하지 않고도 판단할 수 있습니다.

25MB보다 큰 메시지에는 `413`을 반환합니다. 검사에 실패하면 `{"error": "..."}`와 함께 `500`을 반환합니다.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

`--out model.json`을 지정하면 `/learn`으로 학습한 내용이 요청마다 그 파일에 저장됩니다. 지정하지 않으면 학습 내용은 서버를 재시작할 때까지만 유지됩니다.

Node.js에서:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

Python에서:

```python
import os, urllib.request

request = urllib.request.Request(
    'http://127.0.0.1:7832/scan',
    data=open('message.eml', 'rb').read(),
    headers={'Authorization': f"Bearer {os.environ['SPAMSCANNER_TOKEN']}"},
    method='POST',
)
print(urllib.request.urlopen(request).read().decode())
```


## TCP 서버

```sh
spamscanner server --port 7830
```

원본 메시지를 보내고, 연결의 송신 쪽을 닫은 뒤, JSON 한 줄을 읽습니다.

```sh
nc -N 127.0.0.1 7830 < message.eml
```

`--verbose`를 사용하면 응답은 텍스트 한 줄이 됩니다. 예: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` 또는 `HAM -2.5/5.0 BAYES_00`.


## spamd

```sh
spamscanner spamd --port 783
```

spamc, Exim, Haraka 등 SpamAssassin 클라이언트를 위한 SpamAssassin 호환 서버입니다. [Exim과 Haraka 설정](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| 명령              | 응답                                                  |
| --------------- | --------------------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                           |
| `SYMBOLS`       | 판정과 발동한 테스트의 이름                                     |
| `REPORT`        | 판정과 테스트, 점수, 이유를 담은 표                               |
| `REPORT_IFSPAM` | `REPORT`와 같지만, ham이면 보고서가 비어 있습니다                   |
| `PROCESS`       | 판정과 `X-Spam-*` 헤더를 추가한 메시지                          |
| `HEADERS`       | 판정과 `X-Spam-*` 헤더를 추가한 메시지의 헤더 블록                   |
| `PING`          | `PONG`                                              |
| `SKIP`          | 없음                                                  |
| `TELL`          | `--allow-tell` 사용 시 스팸 또는 ham으로 학습하고 `--out`에 저장합니다 |

압축된 요청(`Compress: zlib`)은 거부합니다.
