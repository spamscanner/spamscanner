<!-- source: 6f6b765c5fc1 -->

# 테스트와 점수

메시지는 5점에서 스팸이 되고 15점에서 거부됩니다. 아래의 각 테스트는 점수를 더하거나 빼며, 결과에는 발동한 테스트가 나열됩니다.

임계값은 `threshold`와 `rejectThreshold`로 변경합니다. 점수는 `scores`로 변경합니다. 설정 키로 지정하거나(`scores: {deceptiveLink: 4}`) 테스트 이름으로 지정할 수 있으며, 테스트 이름으로 지정하면 그 테스트의 점수가 고정됩니다(`scores: {FROM_NAME_BRAND: 4}`).


## 분류기

| 테스트                      | 점수         | 의미                                                                                                                                                                                                                                          |
| ------------------------ | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BAYES_00` ~ `BAYES_999` | -2.5~+6.25 | 로그 오즈 척도로 나타낸 분류기의 스팸 확률입니다. 90%에서 2.4점, 99%에서 5점, 99.9%에서 6.25점이므로, 분류기 단독으로는 99% 이상 확신할 때만 스팸으로 표시합니다. 이름은 구간을 나타냅니다. `BAYES_999`는 99.9% 이상, `BAYES_99`는 99%~99.9%, `BAYES_50`은 40%~60%입니다. 설정 키 `bayesHam`과 `bayesSpam`으로 양 끝의 점수를 정합니다. |


## 피싱과 링크

| 테스트                         |  점수 | 설정 키                | 의미                                       |
| --------------------------- | --: | ------------------- | ---------------------------------------- |
| `PHISHING_LOOKALIKE_DOMAIN` |   5 | `homograph`         | 링크의 도메인이 비슷하게 생기거나 뒤바뀐 글자로 브랜드를 흉내 냅니다   |
| `MIXED_SCRIPT_DOMAIN`       |   3 | `mixedScriptDomain` | 도메인 레이블에 여러 알파벳이 섞여 있습니다                 |
| `BRAND_IN_DOMAIN`           | 1.5 | `brandInDomain`     | 다른 사람의 도메인 안에 브랜드 이름이 들어 있습니다            |
| `TYPO_DOMAIN`               |   1 | `typoDomain`        | 브랜드 도메인과 한 글자만 다릅니다                      |
| `DECEPTIVE_LINK`            |   3 | `deceptiveLink`     | 링크가 표시하는 주소와 실제로 가는 주소가 다릅니다             |
| `MALICIOUS_DOMAIN`          |   6 | `maliciousDomain`   | Cloudflare의 악성코드 리졸버가 링크된 도메인을 차단합니다     |
| `ADULT_DOMAIN`              |   2 | `adultDomain`       | Cloudflare의 가족용 리졸버가 링크된 도메인을 차단합니다      |
| `URIBL_<LIST>`              |   5 | `uriblListed`       | 링크된 도메인이 도메인 차단 목록에 있습니다. 예: `URIBL_DBL` |


## 첨부 파일

| 테스트                     |     점수 | 설정 키                                     | 의미                                |
| ----------------------- | -----: | ---------------------------------------- | --------------------------------- |
| `EXECUTABLE_ATTACHMENT` |     10 | `executable`                             | 프로그램 또는 스크립트                      |
| `DISGUISED_EXECUTABLE`  |     12 | `disguisedExecutable`                    | 문서나 이미지처럼 이름을 붙인 프로그램             |
| `DOUBLE_EXTENSION`      |      6 | `doubleExtension`                        | `invoice.pdf.exe` 같은 이름           |
| `RTL_OVERRIDE_FILENAME` |      6 | `rtlOverride`                            | 오른쪽에서 왼쪽 쓰기 재정의 문자가 실제 확장자를 숨깁니다  |
| `EXECUTABLE_IN_ARCHIVE` |      8 | `executableInArchive`                    | ZIP 파일 안의 프로그램                    |
| `ENCRYPTED_ARCHIVE`     |      2 | `encryptedArchive`                       | 검사기가 열 수 없는 압축 파일                 |
| `MACRO_ATTACHMENT`      |      4 | `macro`                                  | 매크로가 있는 Office 파일                 |
| `PDF_ACTIVE_CONTENT`    |      3 | `pdfActive`                              | JavaScript, 실행 동작, 포함된 파일이 있는 PDF |
| `RTF_EMBEDDED_OBJECT`   |      4 | `rtfObject`                              | 개체가 포함된 RTF 파일                    |
| `HTML_ATTACHMENT`       | 1 또는 3 | `htmlAttachment`, `activeHtmlAttachment` | HTML 파일. 스크립트나 폼이 있으면 3점          |
| `VIRUS`                 |    100 | `virus`                                  | ClamAV가 바이러스를 발견했습니다              |


## 규칙

| 테스트                       |   점수 | 의미                                                            |
| ------------------------- | ---: | ------------------------------------------------------------- |
| `GTUBE`                   | 1000 | GTUBE 테스트 문자열                                                 |
| `SEXTORTION_SUBJECT`      |    6 | 섹스토션과 계정 탈취 사기에 쓰이는 제목                                        |
| `PAYPAL_INVOICE`          |    6 | PayPal 청구서 또는 송금 요청. 사기에 악용되는 경로입니다                           |
| `MICROSOFT_SPAM_VERDICT`  |    5 | Microsoft가 메시지를 중계하기 전에 스팸으로 표시했습니다(Microsoft 서버에서 온 경우에만 신뢰) |
| `MICROSOFT_HIGH_SCL`      |    3 | Microsoft가 높은 스팸 신뢰 수준(SCL)을 매겼습니다(위와 같음)                     |
| `PROMPT_INJECTION`        |    3 | AI 필터를 겨냥한 텍스트                                                |
| `SELF_SPOOF`              |    3 | 수신자 자신의 도메인에서 왔다고 주장하지만 인증되지 않습니다                             |
| `FROM_NAME_OTHER_ADDRESS` |  2.5 | 표시 이름에 다른 이메일 주소가 들어 있습니다                                     |
| `FROM_NAME_BRAND`         |    2 | 표시 이름이 주소와 관계없는 브랜드를 내세웁니다                                    |
| `DATE_IN_FUTURE`          |    1 | 날짜가 하루 넘게 미래로 되어 있습니다                                         |
| `MISSING_DATE`            |  0.5 | Date 헤더가 없습니다                                                 |
| `MISSING_MESSAGE_ID`      |  0.5 | Message-ID 헤더가 없습니다                                           |

스팸 임계값 이상의 점수를 가진 규칙은 이전 버전과 마찬가지로 `results.arbitrary`에도 나타납니다.


## 난독화와 언어

| 테스트                    |  점수 | 설정 키                  | 의미                                 |
| ---------------------- | --: | --------------------- | ---------------------------------- |
| `INVISIBLE_CHARACTERS` |   2 | `invisibleCharacters` | 텍스트 안에 보이지 않는 문자가 세 개 이상 있습니다      |
| `MIXED_SCRIPT_WORDS`   | 2.5 | `mixedScriptWords`    | 두 개 이상의 단어에 서로 다른 알파벳의 글자가 섞여 있습니다 |
| `STYLED_LETTERS`       | 1.5 | `styledLetters`       | 수학용 글자나 둘러싼 글자가 일반 텍스트 행세를 합니다     |
| `LANGUAGE_NOT_ALLOWED` |   3 | `languageNotAllowed`  | `allowedLanguages`에 없는 언어입니다       |


## 인증

클라이언트 IP 주소와 `authentication: true`가 필요합니다.

| 테스트            |   점수 | 설정 키(`authentication.weights` 안) |
| -------------- | ---: | -------------------------------- |
| `SPF_PASS`     | -0.5 | `spfPass`                        |
| `SPF_FAIL`     |    2 | `spfFail`                        |
| `SPF_SOFTFAIL` |    1 | `spfSoftfail`                    |
| `DKIM_PASS`    | -0.5 | `dkimPass`                       |
| `DKIM_FAIL`    |    1 | `dkimFail`                       |
| `DMARC_PASS`   | -1.5 | `dmarcPass`                      |
| `DMARC_FAIL`   |  3.5 | `dmarcFail`                      |
| `ARC_PASS`     | -0.5 | `arcPass`                        |
| `ARC_FAIL`     |    1 | `arcFail`                        |


## 평판과 차단 목록

| 테스트            |  점수 | 설정 키          | 의미                                     |
| -------------- | --: | ------------- | -------------------------------------- |
| `DENYLISTED`   | 100 | `denylisted`  | 발신자의 IP 주소, 도메인 또는 주소가 거부 목록에 있습니다     |
| `ALLOWLISTED`  | -20 | `allowlisted` | 허용 목록에 있습니다                            |
| `TRUTH_SOURCE` |  -5 | `truthSource` | 평판 서비스가 발신자를 신뢰할 수 있다고 표시합니다           |
| `RBL_<LIST>`   |   4 | `rblListed`   | 클라이언트 IP 주소가 차단 목록에 있습니다. 예: `RBL_ZEN` |


## 언어 모델과 선택적 모델

| 테스트                                                   | 점수    | 설정 키       | 의미                         |
| ----------------------------------------------------- | ----- | ---------- | -------------------------- |
| `LLM_SPAM`, `LLM_PHISHING`, `LLM_SCAM`, `LLM_MALWARE` | 최대 +6 | `llmSpam`  | 모델의 판정에 확신도를 곱한 값          |
| `LLM_HAM`                                             | 최소 -3 | `llmHam`   | 위와 같음                      |
| `TOXIC_CONTENT`                                       | 3     | `toxicity` | 직접 제공한 유해성 모델이 텍스트를 표시했습니다 |
| `NSFW_IMAGE`                                          | 3     | `nsfw`     | 직접 제공한 이미지 모델이 이미지를 표시했습니다 |
