<!-- source: 1151282f29d3 -->

# Muut postipalvelimet

Spam Scanner puhuu neljää protokollaa, joten useimmat postiohjelmistot voivat käyttää sitä ilman omaa laajennustaan:

| Protokolla | Komento                                  | Käyttäjät                                                  |
| ---------- | ---------------------------------------- | ---------------------------------------------------------- |
| Milter     | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD (filter-milterin kanssa)      |
| spamd      | `spamscanner spamd`                      | spamc, Exim, Haraka ja kaikki SpamAssassinille kirjoitettu |
| HTTP       | `spamscanner http`                       | Skriptit, webhookit, mukautetut MTA:t ja palvelut          |
| Putki      | `spamscanner scan`, `spamscanner filter` | Postfixin putket, procmail, maildrop, cron-ajot            |

[Postfixilla ja Sendmaililla](postfix.md) on oma sivunsa.


## Suora korvaaja SpamAssassinin spamd:lle

`spamscanner spamd` vastaa SpamAssassinin spamd-protokollaan: `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` ja valitsimella `--allow-tell` myös `TELL`. SpamAssassinille kirjoitettu ohjelmisto toimii muuttamattomana; pysäytä `spamd` ja käynnistä Spam Scanner samaan porttiin.

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

spamc:n kanssa:

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

Repositorion päästä päähän -testit ajavat SpamAssassinin omaa spamc:tä sitä vastaan.


## Exim

Eximin `spam`-ACL-ehto keskustelee spamd:n kanssa. Pääasetuksissa:

```text
spamd_address = 127.0.0.1 783
```

DATA-ACL:ssä (Debianin exim4:ssä `acl_check_data`):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer` vastaa väliaikaisella 4xx-virheellä, joten lähettäjät yrittävät uudelleen ja virheen voi korjata. Vaihda se muotoon `deny` pysyvää hylkäystä varten, kun tulokset näyttävät oikeilta.


## Haraka

Harakan `spamassassin`-laajennus keskustelee spamd:n kanssa. Ota se käyttöön tiedostossa `config/plugins` ja aseta tiedostoon `config/spamassassin.ini`:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: Junk-kansio ja oppiminen

Sieve-sääntö siirtää merkityn postin Junk-kansioon:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

IMAPSieven avulla viestin siirtäminen Junk-kansioon tai sieltä pois voi opettaa mallia. Käynnistä HTTP API tunnisteen ja mallitiedoston kanssa:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

ja osoita milter- tai spamd-palvelin samaan malliin valitsimella `--model /var/lib/spamscanner/model.json` (tai muuttujalla `SPAMSCANNER_MODEL`). Käynnistä se aika ajoin uudelleen, jotta opittu otetaan käyttöön. `sieve_pipe`:n ajama skripti lähettää viestin:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

Dovecotin [roskapostista ilmoittamisen opas](https://doc.dovecot.org/main/core/config/spam_reporting.html) näyttää loput määrityksistä, jotka ovat samat mille tahansa skriptistä oppivalle roskapostisuodattimelle.


## procmail ja maildrop

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

`scan --headers` päättyy roskapostille koodiin 1. procmail ja maildrop käyttävät yllä olevilla säännöillä tulostetta, eivät paluukoodia.


## HTTP API

Mikä tahansa ohjelma, joka osaa tehdä HTTP-pyynnön, voi tarkistaa postia:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

[HTTP API](http-api.md) luettelee kaikki päätepisteet.


## Node.js-postipalvelimen sisällä

Kutsu kirjastoa suoraan [smtp-serverillä](https://nodemailer.com/extras/smtp-server/), Haraka-laajennuksissa tai millä tahansa muulla Node.js-palvelimella:

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

smtp-serverin `session.envelope` on valmiiksi siinä `mailFrom`- ja `rcptTo`-muodossa, jota Spam Scanner lukee.
