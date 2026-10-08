<!-- source: 9537a0e62eb0 -->

# Języki

Spam przychodzi w każdym języku, tak samo jak zwykła poczta. Spam Scanner czyta jedno i drugie i jest ostrożny wobec języków, o których wie niewiele: filtr antyspamowy, który oznacza każdą wiadomość po arabsku czy chińsku, jest gorszy niż żaden.


## Czytanie każdego pisma

* **Słowa.** Tekst jest dzielony przez `Intl.Segmenter`, który stosuje reguły granic słów Unicode i używa słowników dla chińskiego, japońskiego, tajskiego, laotańskiego, khmerskiego i birmańskiego, czyli pism zapisywanych bez spacji. Długie teksty są najpierw dzielone na kawałki, bo segmenter w Node.js 18 zwalnia na bardzo długich ciągach.
* **Normalizacja.** Unicode NFKC zamienia litery pełnej szerokości i większość liter stylizowanych (𝐅𝐑𝐄𝐄, Ⓕⓡⓔⓔ) na zwykłe. Tekst jest zamieniany na małe litery według reguł Unicode.
* **Maskowanie.** Niewidoczne znaki wewnątrz słów (`free` ze spacją o zerowej szerokości między dwiema literami, miękkie łączniki) są usuwane i liczone. Słowa mieszające alfabety, takie jak `pаypal` z cyrylickim а, są mapowane z powrotem na jeden alfabet i liczone. Cyfry użyte jako litery (`v1agra`) są zamieniane. Każdy rodzaj maskowania jest osobną cechą, a trzy lub więcej niewidocznych znaków albo dwa lub więcej słów mieszanych dodają też punkty.


## Wykrywanie języka

Język każdej wiadomości jest wykrywany na podstawie pisma, a w przypadku pism wspólnych dla wielu języków na podstawie liter:

* Hangul to koreański; hiragana i katakana oznaczają japoński; tajski, grecki, hebrajski, ormiański, gruziński, bengalski, tamilski i inne pisma używane przez jeden język wskazują go bezpośrednio.
* Litery cyrylicy występujące tylko w jednym języku rozstrzygają między ukraińskim (і, ї, є, ґ), białoruskim (ў), serbskim (ђ, ћ, џ), macedońskim (ѓ, ќ, ѕ) i rosyjskim (ы, э, ё).
* Tekst w pismach wspólnych dla kilku języków (łacińskie, cyrylica, arabskie, dewanagari i inne), jeśli jest wystarczająco długi do oceny, trafia do [franc](https://github.com/wooorm/franc), ograniczonego do języków częstych w poczcie e-mail, aby krótkie wiadomości nie dostawały etykiet rzadkich języków.

Język jest podawany jako `result.language`, a `allowedLanguages: ['en', 'de']` (`--allow-language en,de`) dodaje 3 punkty poczcie, która z pewnością została rozpoznana jako napisana w innym języku.


## Języki, o których model wie niewiele

Klasyfikator uczy się na przykładach. Publiczne zbiory spamu zawierają znacznie więcej obcojęzycznego spamu niż obcojęzycznego hamu, więc naiwny klasyfikator uczy się, że sam tekst po chińsku czy arabsku oznacza spam. Spam Scanner koryguje to na trzy sposoby:

1. **Język nigdy nie jest dowodem.** Wykryty język i pismo nie są używane jako wskazówki.
2. **Słowa są ważone w obrębie swojego języka.** Prawdopodobieństwo spamu dla słowa jest liczone względem liczby wiadomości spamu i hamu, które klasyfikator widział w języku wiadomości, a nie we wszystkich językach. Codzienne portugalskie słowo w modelu, który widział głównie portugalski spam, pozostaje neutralne.
3. **Pewność wynika z pokrycia.** Wynik jest przyciągany do „niepewne” proporcjonalnie do tego, ile wiadomości każdego rodzaju klasyfikator widział w tym języku: pełna pewność wymaga 1000 wiadomości każdego rodzaju (lub 2% mniejszej klasy w przypadku małych modeli osobistych). Język bez hamu w danych treningowych zawsze dostaje „niepewne”.

Dołączony model nigdy nie widział [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset), czyli wiadomości SMS przetłumaczonych maszynowo na 21 języków. Przed wprowadzeniem tych reguł oznaczał jako spam 5,7% tego hamu, w tym 55% portugalskiego i 41% francuskiego. Z nimi 0,18%: zero po chińsku, arabsku, koreańsku, japońsku, w hindi, po portugalsku, francusku i w 20 innych językach oraz 0,27% po angielsku.


## Wyłapywanie spamu w tych językach

Wynik „niepewne” jest bezpieczny, ale nie wyłapuje spamu. Robią to trzy rzeczy:

* **Inne kontrole** nie zależą od języka: podobne domeny, mylące linki, pliki wykonywalne, makra, uwierzytelnianie, czarne listy, reguły.
* **Model językowy.** Nowoczesne otwarte modele czytają od 100 do 200 języków, a Spam Scanner pyta model zawsze, gdy klasyfikator nie jest pewny. Testy end-to-end sprawdzają, czy `qwen3.5:4b` wyłapuje spam i przepuszcza ham po chińsku, arabsku, koreańsku, w hindi i po tajsku. [Modele językowe](llm.md)
* **Trenowanie na twojej poczcie.** W modelu wytrenowanym na twojej własnej poczcie kilkaset wiadomości każdego rodzaju w danym języku daje klasyfikatorowi pełną pewność w tym języku. [Trenowanie](training.md) oraz [opcjonalny zbiór danych](training.md#more-languages), który dodaje 21 języków.
