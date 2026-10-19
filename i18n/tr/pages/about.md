<!-- source: 599bd320e55a -->

<!--
label: Hakkında
title: Spam Scanner, lisansı ve gizlilik hakkında
description: Spam Scanner'ı kimin yaptığı, bir hatayı veya güvenlik açığını nasıl bildireceğiniz, lisansı ve bu sitenin ne topladığı: çerez ve analiz yok.
keywords: Spam Scanner hakkında, Forward Email, Spam Scanner lisansı, BUSL-1.1, Spam Scanner iletişim, Spam Scanner gizlilik
-->

# Spam Scanner hakkında

Spam Scanner, gizlilik odaklı e-posta hizmeti [Forward Email](https://forwardemail.net) tarafından kendi posta sunucuları için yapılmış bir e-posta spam filtresidir. Kaynak kod, sorun kayıtları ve sürümler [GitHub](https://github.com/spamscanner/spamscanner) üzerindedir, paket ise [npm](https://www.npmjs.com/package/spamscanner) üzerindedir.


## Kim yapıyor

Spam Scanner'ı Forward Email ekibi yazar ve bakımını yapar. Forward Email ileti içeriğinin kaydını tutmaz, bu yüzden postayı dışarıdaki bir filtreleme hizmetine gönderemezdi: filtrenin kendi sunucularında çalışması ve postayı bir insan okumadan her kararı açıklaması gerekiyordu. [Forward Email onu nasıl kullanıyor](../../docs/forward-email.md)

Forward Email de açık kaynaklıdır: [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). Kurucusu, DuckDuckGo'nun ilk çalışanlarından biriydi.


## İletişim

* **Sorular, hatalar ve özellik istekleri:** [GitHub](https://github.com/spamscanner/spamscanner/issues) üzerinde bir sorun kaydı açın.
* **Güvenlik açıkları:** bunları herkese açık sorun kayıtlarında değil, [GitHub'ın güvenlik açığı bildirimi](https://github.com/spamscanner/spamscanner/security/advisories/new) üzerinden gizli olarak bildirin. Aynı adres [security.txt](https://spamscanner.net/.well-known/security.txt) dosyasında da var.
* **Diğer lisanslar:** [Forward Email](https://forwardemail.net) ile iletişime geçin.


## Lisans koşulları

Spam Scanner'ın [lisansı](https://github.com/spamscanner/spamscanner/blob/master/LICENSE), Change License olarak Apache License 2.0'ı belirten Business Source License 1.1'dir. Lisansta belirtilen Change Date geçti ve o tarihten itibaren lisans size Apache License 2.0 kapsamında haklar tanır.


## Gizlilik

Bu site çerez yerleştirmez ve başka sitelerden analiz, izleyici, reklam, yazı tipi veya betik yüklemez. Her dosya spamscanner.net'ten gelir.

* Tema, seçtiğiniz dil ve paylaştığınız Mastodon sunucusu tarayıcınızın yerel depolamasına kaydedilir ve hiçbir yere gönderilmez.
* Video yalnızca siz oynattığınızda yüklenir.
* Paylaşım bağlantıları sıradan bağlantılardır, bu yüzden siz birine tıklayana kadar o ağlardan hiçbir şey yüklenmez.
* Site GitHub Pages üzerinde barındırılır ve GitHub güvenlik amacıyla her ziyaretçinin IP adresini kaydeder. Bkz. [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) ve [GitHub Gizlilik Bildirimi](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## Yazılım ne gönderir

Spam Scanner telemetri göndermez ve güncelleme denetlemez. Varsayılan olarak bir iletideki bağlantıların ana bilgisayar adlarını Cloudflare'in filtreleyen DNS çözümleyicilerinde arar ve makineden başka hiçbir şey çıkmaz. Diğer ağ denetimleri siz açana kadar kapalıdır. [Güvenlik ve gizlilik](../../docs/security.md)


## Sürümler

Bağımsız ikili dosyaları GitHub Actions herkese açık depodan derler. Her sürüm, kurulum betiğinin denetlediği bir `SHA256SUMS` dosyasında bunların karma değerlerini listeler ve her ikili dosya imzalı bir derleme kaynağı onayı taşır. Sürümler ve notları [GitHub](https://github.com/spamscanner/spamscanner/releases) üzerindedir.
