<!-- source: f33722183f00 -->

<!--
label: Spamový filtr pro Postfix
title: Spamový filtr pro Postfix s milterem nebo obsahovým filtrem
description: Filtrování spamu na serveru Postfix milterem nebo obsahovým filtrem Spam Scanneru: nastavení, jednotka systemd, odmítání 4xx či 5xx a složka Junk.
keywords: spamový filtr Postfix, antispam Postfix, Postfix milter, smtpd_milters, obsahový filtr Postfix, content filter Postfix, odmítání spamu Postfix
-->

# Spamový filtr pro Postfix

Spam Scanner začne filtrovat server s Postfixem zhruba za pět minut. Běží jako milter, takže se ho Postfix na každou zprávu ptá během relace SMTP a může spam odmítnout dřív, než ho přijme.


## Instalace a spuštění

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth` kontroluje SPF, DKIM, DMARC a ARC; `--subject-tag` označí spam v předmětu. Každá zpráva dostane hlavičky `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status` a `X-Spam-Action` a jakákoli hlavička `X-Spam-*`, kterou vložil odesílatel, se nejprve odstraní.


## Připojení Postfixu

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept` propustí poštu nefiltrovanou, pokud milter neběží; `tempfail` místo toho požádá odesílatele, aby to zkusili znovu.


## Odmítání spamu během relace SMTP

```sh
spamscanner milter --port 7831 --auth --reject
```

Zprávy na prahu odmítnutí (15 bodů) se odmítají s `451 4.7.1 Message rejected as spam`. Kód 451 je dočasný: odesílatel si zprávu ponechá a zkusí to znovu, takže špatné rozhodnutí stojí zpoždění, ne ztracenou zprávu. Až budou výsledky vypadat správně, `--reject-code 550` udělá z odmítnutí trvalé.


## Bez milteru

Obsahový filtr běží až poté, co Postfix zprávu přijme: Postfix ji rourou předá do `spamscanner filter`, který přidá hlavičky a vrátí ji zpět. Během relace se nikdy nic neodmítne a selhání vždy doručení odloží, místo aby zprávu vrátilo. [Nastavení obsahového filtru](../../docs/postfix.md#content-filter)


## Spam do složky Junk

S Dovecotem přesune označenou poštu pravidlo Sieve:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## Otestováno proti skutečnému Postfixu

Testy end-to-end projektu spouštějí Postfix s milterem i obsahovým filtrem: ham se doručí s hlavičkami a s odstraněnou podvrženou `X-Spam-Flag`, spam se označí a GTUBE se během relace SMTP odmítne s kódem 550.

Dále: [úplný návod pro Postfix a Sendmail](../../docs/postfix.md) s jednotkou systemd a `INPUT_MAIL_FILTER` pro Sendmail.
