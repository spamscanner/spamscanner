<!-- source: 8860e232d858 -->

# Spam Scanner 문서

Spam Scanner는 Node.js와 명령줄을 위한 스팸 필터이며, 소스 코드는 GitHub에 있습니다. 원본 이메일 메시지를 읽고, 언어와 관계없이 그 메시지가 스팸, 피싱, 사기인지 또는 악성코드를 담고 있는지 판정합니다. 라이브러리, 명령줄 도구, Postfix 또는 Sendmail milter, Postfix 콘텐츠 필터, SpamAssassin 호환 spamd 서버, HTTP API, TCP 서버로 실행할 수 있습니다.

[Forward Email](https://forwardemail.net)이 자사 메일 서버에 쓰기 위해 개발했습니다.


## 메시지 판정 방식

각 검사는 점수를 더하거나 뺍니다. 합계로 결과가 정해집니다.

| 점수     | 동작       | 메일 서버의 처리        |
| ------ | -------- | ---------------- |
| 5 미만   | `accept` | 메시지를 전달합니다       |
| 5~14.9 | `tag`    | 스팸으로 표시해 전달합니다   |
| 15 이상  | `reject` | SMTP 세션 중에 거부합니다 |

두 임계값 모두 변경할 수 있습니다. 모든 결과에는 발동한 테스트가 점수와 이유와 함께 나열되므로, 판정은 언제나 설명할 수 있습니다.

검사 항목:

* **학습된 분류기**는 문자 체계와 관계없이 메시지의 단어, 링크의 형태, 발신자, 첨부 파일을 읽습니다. 공개 데이터 세트로 학습된 상태로 배포되며, 직접 받은 메일로 추가 학습합니다. [분류기의 작동 방식](how-it-works.md#the-classifier)
* **피싱 검사**는 유사 도메인(`paypa1.com`, 키릴 문자 а가 들어간 `pаypal.com`), 링크 텍스트에 표시된 주소와 실제 대상이 다른 링크, 브랜드를 사칭하는 표시 이름을 잡아냅니다. [피싱](how-it-works.md#phishing)
* **첨부 파일 검사**는 실행 파일, 문서로 이름을 바꾼 실행 파일, 이중 확장자, 오른쪽에서 왼쪽 쓰기 문자를 이용한 파일 이름 속임수, ZIP 파일 안의 실행 파일, Office 매크로, 동적 PDF 콘텐츠를 찾아냅니다. ClamAV로 첨부 파일의 바이러스를 검사할 수도 있습니다. [첨부 파일](how-it-works.md#attachments)
* **인증**: 클라이언트 IP 주소를 알 때 SPF, DKIM, DMARC, ARC를 검사합니다. [인증](how-it-works.md#authentication)
* **DNS 차단 목록**으로 클라이언트 IP 주소와 링크 속 도메인을 조회하고, Cloudflare의 필터링 리졸버로 알려진 악성코드 사이트와 성인 사이트를 확인합니다. [차단 목록](how-it-works.md#blocklists)
* **규칙**은 분류기가 학습할 필요가 없는 패턴을 다룹니다. GTUBE 테스트 문자열, 섹스토션 제목, PayPal 청구서 사기, 자기 도메인 사칭, AI 필터를 노리고 숨긴 지시문이 여기에 해당합니다. [규칙](scoring.md#rules)
* **언어 모델**(선택 사항)은 애매한 메시지에 대해 두 번째 의견을 냅니다. Ollama나 OpenAI 호환 서버를 통한 로컬 모델, Cloudflare의 Clef 같은 결정 모델, 또는 Claude, ChatGPT, Gemini 등을 사용할 수 있습니다. 기본적으로 답을 작성하는 대신 한 단계로 각 판정의 확률을 돌려줍니다. [언어 모델](llm.md)


## 시작 위치

* [시작하기](getting-started.md): 설치하고 첫 메시지를 검사합니다.
* [명령줄](cli.md): 모든 명령과 옵션.
* [Postfix와 Sendmail](postfix.md): milter나 콘텐츠 필터로 메일 서버를 필터링합니다.
* [기타 메일 서버](mail-servers.md): Exim, Haraka, Dovecot, procmail, 그리고 HTTP API를 호출할 수 있는 모든 것.
* [학습](training.md): 직접 받은 메일로 학습시키고 결과를 측정합니다.
* [언어 모델](llm.md): 결정과 생성, 측정한 정확도와 속도, 결정 모델, 제공자, 권장 공개 모델, 개인정보 보호, 프롬프트 인젝션.
* [언어](languages.md): 중국어, 아랍어, 태국어를 비롯한 모든 문자 체계를 읽는 방식.
* [Forward Email](forward-email.md): Forward Email의 사용 방식과 버전 5 또는 6에서 업그레이드하는 방법.
* [API 레퍼런스](api.md)와 [테스트와 점수](scoring.md).
* [보안과 개인정보](security.md): 컴퓨터 밖으로 나가는 데이터와 이를 막는 방법.
