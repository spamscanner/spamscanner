<!-- source: 0378a5e0f12b -->

<!--
label: Tietojenkalastelun tunnistus
title: Tietojenkalastelun tunnistus: huijausverkkotunnukset ja -linkit
description: Miten Spam Scanner tunnistaa tietojenkalastelun: samannäköiset Unicode-verkkotunnukset, harhaanjohtavat linkit, tuotemerkit, Cloudflaren suodatus ja DMARC.
keywords: tietojenkalastelun tunnistus, phishing tunnistus, sähköpostin tietojenkalastelusuodatin, homografihyökkäys, IDN homografi, samannäköinen verkkotunnus, harhaanjohtava linkki, tuotemerkin jäljittely sähköposti
-->

# Sähköpostin tietojenkalastelun tunnistus

Tietojenkalastelu perustuu siihen, että lähettäjä näyttää joltakulta muulta. Spam Scanner tarkistaa kohdat, joissa naamiointi paljastuu.


## Samannäköiset verkkotunnukset

Jokainen linkin verkkotunnus pelkistetään luurangoksi Unicoden sekoitettavien merkkien taulukon avulla ja sitä verrataan lähes 100 yleisesti jäljiteltyyn tuotemerkkiin:

| Verkkotunnus                        | Tunnistetaan                                |
| ----------------------------------- | ------------------------------------------- |
| `pаypal.com` (kyrillinen а)         | Sekoitettavat merkit                        |
| `paypa1-secure.top`                 | Vaihdetut merkit                            |
| `xn--pple-43d.com`                  | Punycode-muoto osoitteesta `аpple.com`      |
| `paypal.com.account-verify.example` | Tuotemerkki jonkun toisen verkkotunnuksessa |
| `paypall.com`                       | Yhden kirjaimen päässä                      |

Tuotemerkkejä voi lisätä, ja omistamasi verkkotunnukset voi lisätä sallittujen listalle.


## Harhaanjohtavat linkit

HTML-linkki, jonka teksti on yksi osoite ja kohde toinen, kuten teksti `https://www.paypal.com/signin`, joka osoittaa kohteeseen `http://paypa1-secure.top/login`, lisää 3 pistettä.


## Näyttönimet ja väärentäminen

* Tuotemerkin sisältävä näyttönimi ("PayPal Security") toisen verkkotunnuksen osoitteesta.
* Näyttönimi, joka sisältää eri sähköpostiosoitteen.
* Posti, joka väittää tulevansa vastaanottajan omasta verkkotunnuksesta eikä läpäise SPF:ää, DKIM:ää ja DMARC:ia.


## Tunnetut haitalliset sivustot

Linkkien isännät tarkistetaan Cloudflaren DNS-palvelusta 1.1.1.2, joka estää tunnetut haittaohjelma- ja tietojenkalastelusivustot, ja valinnaisesti verkkotunnusten estolistoista, kuten Spamhaus DBL:stä.


## Liitteet

Tietojenkalastelu saapuu myös HTML-liitteinä, jotka piirtävät väärennetyn kirjautumissivun ilman verkkoyhteyttä, sekä suoritettavina tiedostoina, jotka on nimetty uudelleen muotoon `.pdf`. Molemmat tunnistetaan sisällön perusteella.

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

[Miten tarkistukset toimivat](../../docs/how-it-works.md#phishing)
