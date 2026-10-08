<!-- source: 6f6b765c5fc1 -->

# Tests et scores

Un message est du spam à partir de 5 points et rejeté à partir de 15. Chaque test ci-dessous ajoute ou retire des points ; le résultat liste ceux qui se sont déclenchés.

Modifiez les seuils avec `threshold` et `rejectThreshold`. Modifiez les points avec `scores`, soit par clé de réglage (`scores: {deceptiveLink: 4}`), soit par nom de test, ce qui fixe les points de ce test (`scores: {FROM_NAME_BRAND: 4}`).


## Classifieur

| Test                      | Points       | Signification                                                                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BAYES_00` to `BAYES_999` | −2,5 à +6,25 | La probabilité de spam selon le classifieur, sur une échelle logarithmique des cotes : 2,4 points à 90 %, 5 à 99 % et 6,25 à 99,9 % ; le classifieur ne marque donc un spam à lui seul que s’il en est sûr à au moins 99 %. Le nom indique la tranche : `BAYES_999` correspond à 99,9 % ou plus, `BAYES_99` à 99 %–99,9 %, `BAYES_50` à 40 %–60 %. Les clés de réglage `bayesHam` et `bayesSpam` fixent les deux extrémités. |


## Hameçonnage et liens

| Test                        | Points | Clé de réglage      | Signification                                                                       |
| --------------------------- | -----: | ------------------- | ----------------------------------------------------------------------------------- |
| `PHISHING_LOOKALIKE_DOMAIN` |      5 | `homograph`         | Le domaine d’un lien imite une marque avec des caractères sosies ou intervertis     |
| `MIXED_SCRIPT_DOMAIN`       |      3 | `mixedScriptDomain` | Une étiquette de domaine mélange plusieurs alphabets                                |
| `BRAND_IN_DOMAIN`           |    1,5 | `brandInDomain`     | Un nom de marque dans le domaine de quelqu’un d’autre                               |
| `TYPO_DOMAIN`               |      1 | `typoDomain`        | À une lettre près du domaine d’une marque                                           |
| `DECEPTIVE_LINK`            |      3 | `deceptiveLink`     | Un lien affiche une adresse et mène à une autre                                     |
| `MALICIOUS_DOMAIN`          |      6 | `maliciousDomain`   | Le résolveur anti-malware de Cloudflare bloque un domaine lié                       |
| `ADULT_DOMAIN`              |      2 | `adultDomain`       | Le résolveur familial de Cloudflare bloque un domaine lié                           |
| `URIBL_<LIST>`              |      5 | `uriblListed`       | Un domaine lié figure sur une liste de blocage de domaines, par exemple `URIBL_DBL` |


## Pièces jointes

| Test                    | Points | Clé de réglage                           | Signification                                                                       |
| ----------------------- | -----: | ---------------------------------------- | ----------------------------------------------------------------------------------- |
| `EXECUTABLE_ATTACHMENT` |     10 | `executable`                             | Un programme ou un script                                                           |
| `DISGUISED_EXECUTABLE`  |     12 | `disguisedExecutable`                    | Un programme nommé comme un document ou une image                                   |
| `DOUBLE_EXTENSION`      |      6 | `doubleExtension`                        | Un nom comme `invoice.pdf.exe`                                                      |
| `RTL_OVERRIDE_FILENAME` |      6 | `rtlOverride`                            | Un caractère de forçage de droite à gauche masque la véritable extension            |
| `EXECUTABLE_IN_ARCHIVE` |      8 | `executableInArchive`                    | Un programme dans un fichier ZIP                                                    |
| `ENCRYPTED_ARCHIVE`     |      2 | `encryptedArchive`                       | Une archive que les antivirus ne peuvent pas ouvrir                                 |
| `MACRO_ATTACHMENT`      |      4 | `macro`                                  | Un fichier Office contenant des macros                                              |
| `PDF_ACTIVE_CONTENT`    |      3 | `pdfActive`                              | Un PDF contenant du JavaScript, des actions de lancement ou des fichiers incorporés |
| `RTF_EMBEDDED_OBJECT`   |      4 | `rtfObject`                              | Un fichier RTF contenant des objets incorporés                                      |
| `HTML_ATTACHMENT`       | 1 ou 3 | `htmlAttachment`, `activeHtmlAttachment` | Un fichier HTML ; 3 s’il contient des scripts ou des formulaires                    |
| `VIRUS`                 |    100 | `virus`                                  | ClamAV a trouvé un virus                                                            |


## Règles

| Test                      | Points | Signification                                                                                                             |
| ------------------------- | -----: | ------------------------------------------------------------------------------------------------------------------------- |
| `GTUBE`                   |   1000 | La chaîne de test GTUBE                                                                                                   |
| `SEXTORTION_SUBJECT`      |      6 | Un objet utilisé par les arnaques à la sextorsion et au piratage de compte                                                |
| `PAYPAL_INVOICE`          |      6 | Une facture ou une demande d’argent PayPal, un canal détourné pour des arnaques                                           |
| `MICROSOFT_SPAM_VERDICT`  |      5 | Microsoft a marqué le message comme spam avant de le relayer (pris en compte uniquement depuis les serveurs de Microsoft) |
| `MICROSOFT_HIGH_SCL`      |      3 | Microsoft lui a attribué un niveau de confiance de spam élevé (même condition)                                            |
| `PROMPT_INJECTION`        |      3 | Texte adressé à un filtre d’IA                                                                                            |
| `SELF_SPOOF`              |      3 | Prétend venir du propre domaine du destinataire et ne s’authentifie pas                                                   |
| `FROM_NAME_OTHER_ADDRESS` |    2,5 | Le nom d’affichage contient une autre adresse e-mail                                                                      |
| `FROM_NAME_BRAND`         |      2 | Le nom d’affichage se réclame d’une marque à laquelle l’adresse n’appartient pas                                          |
| `DATE_IN_FUTURE`          |      1 | Daté de plus d’un jour dans le futur                                                                                      |
| `MISSING_DATE`            |    0,5 | Aucun en-tête Date                                                                                                        |
| `MISSING_MESSAGE_ID`      |    0,5 | Aucun en-tête Message-ID                                                                                                  |

Les règles qui valent au moins le seuil de spam apparaissent aussi dans `results.arbitrary`, comme dans les versions précédentes.


## Obfuscation et langue

| Test                   | Points | Clé de réglage        | Signification                                                            |
| ---------------------- | -----: | --------------------- | ------------------------------------------------------------------------ |
| `INVISIBLE_CHARACTERS` |      2 | `invisibleCharacters` | Trois caractères invisibles ou plus dans le texte                        |
| `MIXED_SCRIPT_WORDS`   |    2,5 | `mixedScriptWords`    | Deux mots ou plus mélangent des lettres d’alphabets différents           |
| `STYLED_LETTERS`       |    1,5 | `styledLetters`       | Lettres mathématiques ou cerclées se faisant passer pour du texte simple |
| `LANGUAGE_NOT_ALLOWED` |      3 | `languageNotAllowed`  | Absente de `allowedLanguages`                                            |


## Authentification

Nécessite l’adresse IP du client et `authentication: true`.

| Test           | Points | Clé de réglage (dans `authentication.weights`) |
| -------------- | -----: | ---------------------------------------------- |
| `SPF_PASS`     |   −0,5 | `spfPass`                                      |
| `SPF_FAIL`     |      2 | `spfFail`                                      |
| `SPF_SOFTFAIL` |      1 | `spfSoftfail`                                  |
| `DKIM_PASS`    |   −0,5 | `dkimPass`                                     |
| `DKIM_FAIL`    |      1 | `dkimFail`                                     |
| `DMARC_PASS`   |   −1,5 | `dmarcPass`                                    |
| `DMARC_FAIL`   |    3,5 | `dmarcFail`                                    |
| `ARC_PASS`     |   −0,5 | `arcPass`                                      |
| `ARC_FAIL`     |      1 | `arcFail`                                      |


## Réputation et listes de blocage

| Test           | Points | Clé de réglage | Signification                                                                      |
| -------------- | -----: | -------------- | ---------------------------------------------------------------------------------- |
| `DENYLISTED`   |    100 | `denylisted`   | L’adresse IP, le domaine ou l’adresse de l’expéditeur figure sur la liste de refus |
| `ALLOWLISTED`  |    −20 | `allowlisted`  | Il figure sur la liste d’autorisation                                              |
| `TRUTH_SOURCE` |     −5 | `truthSource`  | Un service de réputation marque l’expéditeur comme fiable                          |
| `RBL_<LIST>`   |      4 | `rblListed`    | L’adresse IP du client figure sur une liste de blocage, par exemple `RBL_ZEN`      |


## Modèle de langage et modèles facultatifs

| Test                                                  | Points     | Clé de réglage | Signification                                                |
| ----------------------------------------------------- | ---------- | -------------- | ------------------------------------------------------------ |
| `LLM_SPAM`, `LLM_PHISHING`, `LLM_SCAM`, `LLM_MALWARE` | jusqu’à +6 | `llmSpam`      | Le verdict du modèle, multiplié par sa confiance             |
| `LLM_HAM`                                             | jusqu’à −3 | `llmHam`       | De même                                                      |
| `TOXIC_CONTENT`                                       | 3          | `toxicity`     | Un modèle de toxicité que vous fournissez a signalé le texte |
| `NSFW_IMAGE`                                          | 3          | `nsfw`         | Un modèle d’images que vous fournissez a signalé une image   |
