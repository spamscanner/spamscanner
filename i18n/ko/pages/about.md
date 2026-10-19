<!-- source: 599bd320e55a -->

<!--
label: 소개
title: Spam Scanner 소개, 라이선스와 개인정보
description: Spam Scanner를 누가 만드는지, 버그나 취약점을 어떻게 신고하는지, 어떤 라이선스인지, 이 사이트가 무엇을 수집하는지 설명합니다. 쿠키도 분석 도구도 없습니다.
keywords: Spam Scanner 소개, Forward Email, Spam Scanner 라이선스, BUSL-1.1, Spam Scanner 연락처, Spam Scanner 개인정보
-->

# Spam Scanner 소개

Spam Scanner는 개인정보 보호에 중점을 둔 이메일 서비스 [Forward Email](https://forwardemail.net)이 자사 메일 서버를 위해 만든 이메일 스팸 필터입니다. 소스 코드, 이슈, 릴리스는 [GitHub](https://github.com/spamscanner/spamscanner)에, 패키지는 [npm](https://www.npmjs.com/package/spamscanner)에 있습니다.


## 만드는 곳

Forward Email 팀이 Spam Scanner를 개발하고 유지 관리합니다. Forward Email은 메시지 내용의 로그를 남기지 않기 때문에 외부 필터링 서비스로 메일을 보낼 수 없었습니다. 필터는 자체 서버에서 실행되어야 했고, 사람이 메일을 읽지 않고도 모든 판정의 이유를 설명해야 했습니다. [Forward Email의 사용 방식](../../docs/forward-email.md)

Forward Email도 오픈 소스이며 [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net)에 공개되어 있습니다. 창업자는 DuckDuckGo의 초기 직원 중 한 명이었습니다.


## 연락처

* **질문, 버그, 기능 요청:** [GitHub](https://github.com/spamscanner/spamscanner/issues)에 이슈를 등록하세요.
* **보안 취약점:** 공개 이슈가 아니라 [GitHub의 취약점 신고](https://github.com/spamscanner/spamscanner/security/advisories/new)로 비공개 신고해 주세요. 같은 주소가 [security.txt](https://spamscanner.net/.well-known/security.txt)에도 있습니다.
* **다른 라이선스:** [Forward Email](https://forwardemail.net)에 문의하세요.


## 라이선스 조건

Spam Scanner의 [라이선스](https://github.com/spamscanner/spamscanner/blob/master/LICENSE)는 Business Source License 1.1이며, Change License는 Apache License 2.0입니다. 라이선스에 적힌 Change Date는 이미 지났고, 그날부터 라이선스는 Apache License 2.0에 따른 권리를 부여합니다.


## 개인정보

이 사이트는 쿠키를 설정하지 않으며, 다른 사이트에서 분석 도구, 추적기, 광고, 글꼴, 스크립트를 불러오지 않습니다. 모든 파일은 spamscanner.net에서 제공됩니다.

* 테마, 선택한 언어, 공유할 Mastodon 서버는 브라우저의 로컬 저장소에 저장되며 어디로도 전송되지 않습니다.
* 동영상은 재생할 때만 불러옵니다.
* 공유 링크는 일반 링크이므로, 링크를 열기 전까지 해당 네트워크에서 아무것도 불러오지 않습니다.
* 사이트는 GitHub Pages에서 호스팅되며, GitHub는 보안을 위해 방문자마다 IP 주소를 기록합니다. [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages)와 [GitHub 개인정보처리방침](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement)을 참고하세요.


## 소프트웨어가 보내는 것

Spam Scanner는 원격 측정 데이터를 보내지 않고 업데이트도 확인하지 않습니다. 기본적으로 메시지 링크의 호스트 이름을 Cloudflare의 필터링 DNS 리졸버에서 확인할 뿐, 그 밖의 어떤 것도 머신 밖으로 나가지 않습니다. 다른 네트워크 검사는 켜기 전까지 꺼져 있습니다. [보안과 개인정보](../../docs/security.md)


## 릴리스

독립 실행 바이너리는 공개 저장소에서 GitHub Actions가 빌드합니다. 각 릴리스는 바이너리의 해시를 `SHA256SUMS` 파일에 나열하고 설치 스크립트가 이를 확인하며, 각 바이너리에는 서명된 빌드 출처 증명이 있습니다. 릴리스와 릴리스 노트는 [GitHub](https://github.com/spamscanner/spamscanner/releases)에 있습니다.
