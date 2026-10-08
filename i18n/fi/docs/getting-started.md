<!-- source: 8263c06f1dab -->

# Aloittaminen

Spam Scanner tarvitsee Node.js 18:n tai uudemman, tai ei mitään, jos käytät erillistä binääriä.


## Asennus

Komentorivityökaluna:

```sh
npm install --global spamscanner
spamscanner version
```

Kirjastona Node.js-projektissa:

```sh
npm install spamscanner
```

Erillisenä binäärinä Linuxille tai macOS:lle, Node.js ja malli sisäänrakennettuina:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Binäärit Linuxille (x64 ja arm64), macOS:lle (Intel ja Apple silicon) ja Windowsille on liitetty jokaiseen [julkaisuun](https://github.com/spamscanner/spamscanner/releases).


## Viestin tarkistaminen

Tallenna viesti tiedostoksi (useimmissa sähköpostiohjelmissa toiminto on nimeltään "Tallenna nimellä" tai "Näytä alkuperäinen") ja tarkista se:

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

Paluukoodi on 0 hamille (halutulle postille), 1 roskapostille ja 2 virheelle, joten skriptit voivat käyttää sitä suoraan. `--json` tulostaa koko tuloksen ja `--headers` tulostaa viestin, johon on lisätty `X-Spam-*`-otsakkeet.

Viestit voivat tulla myös vakiosyötteestä:

```sh
cat message.eml | spamscanner scan -
```


## Käyttö Node.js:stä

```js
import SpamScanner from 'spamscanner';
import {readFile} from 'node:fs/promises';

const scanner = new SpamScanner();
const result = await scanner.scan(await readFile('message.eml'));

console.log(result.isSpam, result.score, result.action);
for (const test of result.tests) {
  console.log(test.name, test.score, test.description);
}
```

Myös CommonJS toimii:

```js
const SpamScanner = require('spamscanner');
```

`scan()` ottaa raakaviestin Bufferina, merkkijonona, Uint8Arrayna tai luettavana virtana. Merkkijono on aina viestin tekstiä: Spam Scanner ei koskaan lue tiedostoa sillä perusteella, että merkkijono näyttää polulta. Käytä tiedostoille `scanner.scanFile(path)`.


## SMTP-istunnon tietojen välittäminen

Asiakkaan IP-osoite, sen varmennettu isäntänimi, HELO-nimi ja kirjekuoritiedot tekevät tuloksesta tarkemman: todennus tarvitsee IP-osoitteen, ja oman verkkotunnuksen väärentämistä koskeva sääntö tarvitsee vastaanottajat.

```js
const result = await scanner.scan(raw, {
  session: {
    remoteAddress: '203.0.113.5',
    resolvedClientHostname: 'mail.example.com',
    helo: 'mail.example.com',
    envelope: {
      mailFrom: {address: 'alice@example.com'},
      rcptTo: [{address: 'bob@example.org'}],
    },
  },
});
```

Sama komentoriviltä:

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## Lisätarkistusten käyttöönotto

Mikään näistä ei ole oletuksena käytössä, koska jokainen tarvitsee palvelun tai päätöksen:

| Tarkistus                          | Kirjaston valinta                                | Komentorivi                 |
| ---------------------------------- | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC              | `authentication: true`                           | `--auth`                    |
| IP-estolista                       | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| Linkkien verkkotunnusten estolista | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                             | `clamav: true` tai `clamav: {socket}`            | `--clamav [socket]`         |
| Kielimalli                         | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| Sallitut ja estetyt -listat        | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

Cloudflaren suodattavilta DNS-palveluilta (1.1.1.2 haittaohjelmille, 1.1.1.3 aikuissisällölle) kysytään oletuksena linkkien isännistä. Poista tämä käytöstä valinnalla `phishing: {cloudflare: false}` tai `--no-cloudflare`. [Mitä koneelta lähtee](security.md)

Spamhaus ja jotkin muut estolistat eivät vastaa kyselyihin, jotka lähetetään julkisten DNS-palvelujen, kuten 8.8.8.8 tai 1.1.1.1, kautta. Käytä niitä paikallisen välimuistia käyttävän DNS-palvelimen kanssa ja tarkista niiden käyttöehdot omalle liikennemäärällesi.


## Seuraavat vaiheet

* Aseta se postipalvelimen eteen: [Postfix ja Sendmail](postfix.md), [muut palvelimet](mail-servers.md).
* Opeta sille oma postisi: [koulutus](training.md).
* Lisää kielimalli epäselviä tapauksia varten: [kielimallit](llm.md).
