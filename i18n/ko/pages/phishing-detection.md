<!-- source: 0378a5e0f12b -->

<!--
label: 피싱 탐지
title: 이메일 피싱 탐지: 유사 도메인, 기만적인 링크, 사칭
description: Spam Scanner의 피싱 메일 탐지 방식: 유니코드 유사 도메인, 표시 주소와 실제 주소가 다른 링크, 브랜드 표시 이름, Cloudflare 악성코드 리졸버, DMARC.
keywords: 피싱 탐지, 피싱 메일 차단, 이메일 피싱 필터, 동형 문자 공격, IDN 동형 문자, 유사 도메인 탐지, 기만적인 링크, 브랜드 사칭 이메일
-->

# 이메일 피싱 탐지

피싱은 다른 누군가인 척하는 방식으로 이루어집니다. Spam Scanner는 그 위장이 드러나는 곳을 검사합니다.


## 유사 도메인

링크의 각 도메인을 유니코드 혼동 문자(confusables) 표로 골격 형태로 줄이고, 자주 사칭되는 브랜드 100개 가까이와 비교합니다.

| 도메인                                 | 탐지 유형             |
| ----------------------------------- | ----------------- |
| `pаypal.com`(키릴 문자 а)               | 혼동하기 쉬운 문자        |
| `paypa1-secure.top`                 | 뒤바뀐 문자            |
| `xn--pple-43d.com`                  | `аpple.com`의 퓨니코드 |
| `paypal.com.account-verify.example` | 다른 사람의 도메인 속 브랜드  |
| `paypall.com`                       | 한 글자 차이           |

브랜드는 추가할 수 있으며, 소유한 도메인은 허용 목록에 넣을 수 있습니다.


## 기만적인 링크

텍스트는 `https://www.paypal.com/signin`이지만 `http://paypa1-secure.top/login`을 가리키는 것처럼, 텍스트에 표시된 주소와 실제 대상이 다른 HTML 링크는 3점을 더합니다.


## 표시 이름과 사칭

* 다른 도메인 주소에서 보낸, 브랜드가 들어간 표시 이름("PayPal Security").
* 다른 이메일 주소가 들어 있는 표시 이름.
* 수신자 자신의 도메인에서 왔다고 주장하지만 SPF, DKIM, DMARC에 실패한 메일.


## 알려진 악성 사이트

링크 호스트는 알려진 악성코드 사이트와 피싱 사이트를 차단하는 Cloudflare의 1.1.1.2 리졸버에서 조회하며, 선택적으로 Spamhaus DBL 같은 도메인 차단 목록에서도 조회합니다.


## 첨부 파일

피싱은 오프라인으로 가짜 로그인 페이지를 그리는 HTML 첨부 파일이나, `.pdf`로 이름을 바꾼 실행 파일로도 도착합니다. 둘 다 내용으로 찾아냅니다.

```sh
spamscanner scan message.eml
```

```text
SPAM  score 16.3 (spam at 5.0, reject at 15.0)  action: reject  language: en
     +6.3  BAYES_999                    Classifier spam probability 99.9%
     +5.0  PHISHING_LOOKALIKE_DOMAIN    "paypa1-secure.top" imitates paypal by swapping characters
     +3.0  DECEPTIVE_LINK               A link shows "https://www.paypal.com/signin" but goes to paypa1-secure.top
     +2.0  FROM_NAME_BRAND              Display name says "paypal" but the message is from paypa1-secure.top
```

[검사의 작동 방식](../../docs/how-it-works.md#phishing)
