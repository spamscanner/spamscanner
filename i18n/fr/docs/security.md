<!-- source: 1d7373f991c2 -->

# Sécurité et confidentialité

Spam Scanner lit du courrier, qui est privé, provenant d’expéditeurs, qui peuvent être hostiles. Cette page liste ce qu’il envoie où que ce soit, et comment il traite ce qu’il lit.


## Ce qui quitte la machine

Par défaut, une seule chose : les **noms d’hôte des liens** d’un message sont interrogés auprès des résolveurs filtrants de Cloudflare, 1.1.1.2 et 1.0.0.2 (logiciels malveillants et hameçonnage) et 1.1.1.3 et 1.0.0.3 (également contenu pour adultes). Ce sont des requêtes DNS ordinaires pour des noms comme `example.com` ; aucune partie du message ni de ses adresses n’est envoyée. Désactivez-les avec `phishing: {cloudflare: false}` ou `--no-cloudflare`, ou seulement la vérification du contenu pour adultes avec `phishing: {adult: false}`.

Tout le reste est désactivé tant qu’il n’est pas configuré :

| Vérification        | Envoie                                                                                                                                  | À                                                                                     |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `authentication`    | Des requêtes DNS pour les enregistrements SPF, DKIM, DMARC et ARC de l’expéditeur                                                       | Votre résolveur, ou `dnsServers`                                                      |
| `dnsbl`             | L’adresse IP du client, inversée, et les domaines des liens, sous forme de requêtes DNS                                                 | Les serveurs de noms des listes de blocage, via votre résolveur ou `dns.servers`      |
| `llm`               | Un résumé du message, dont les données personnelles sont retirées pour les fournisseurs distants                                        | Le serveur de modèle de langage que vous indiquez ([confidentialité](llm.md#privacy)) |
| `reputation.apiUrl` | L’adresse IP et le nom d’hôte vérifié du client, ainsi que les adresses From, d’expéditeur d’enveloppe et Reply-To, avec leurs domaines | Le service que vous indiquez                                                          |
| `clamav`            | Les pièces jointes                                                                                                                      | Votre clamd, via son socket                                                           |

Il n’y a aucune télémétrie, aucune vérification de mise à jour et aucun téléchargement à l’exécution. Le modèle est livré dans le paquet.


## Ce qu’il conserve

Rien, sauf demande. Les analyses ne sont ni journalisées ni stockées. `learn()` modifie le classifieur en mémoire ; il n’est écrit sur le disque que par `saveModel()`, `spamscanner learn` ou l’option `--out` des serveurs. Un fichier de modèle contient des décomptes de caractéristiques hachées, pas des mots ni le texte des messages.

Les réponses du modèle de langage sont mises en cache en mémoire, indexées par un hachage de ce qui a été envoyé : les copies répétées d’un même message ne sont soumises qu’une seule fois. Les réponses DNS sont mises en cache en mémoire pendant dix minutes, et celles d’un service de réputation pendant cinq (`reputation.cacheTtl` ; une requête échouée pendant une minute).


## Entrées hostiles

* Les pièces jointes sont identifiées par leurs octets, jamais exécutées ni ouvertes par un autre programme. Les archives ZIP sont lues à partir de leur répertoire central, avec des limites sur le nombre d’entrées (2000) et sur les octets de leurs noms (1 Mio ; un nom de plus de 1 Kio garde ses premiers et ses derniers 512 octets, et les constats en montrent au plus 100 caractères), chaque entrée étant lue une seule fois quel que soit le nombre de répertoires qui pointent vers elle ; rien n’est décompressé, donc les programmes contenus dans des archives imbriquées ou compressées ne sont pas vus. Les messages joints (`message/rfc822`, ou pièces jointes dont le nom de fichier se termine par `.eml`) sont ouverts jusqu'à trois niveaux de profondeur, pour au plus 100 de leurs pièces jointes et 25 Mo de messages joints au total ; les pièces jointes du message lui-même sont toujours toutes inspectées. Un message qui dépasse les limites de l’analyseur MIME (plus de 1000 parties, ou l’en-tête d’une partie de plus de 1 Mo) est lu aussi loin que l’analyseur le permet (ses premières parties, avec un en-tête trop grand réduit pour que son expéditeur compte encore) et reçoit `MIME_TOO_COMPLEX`, qu’aucun crédit ne compense ; ClamAV le lit en entier. Un message joint sur lequel l’analyseur échoue le reçoit aussi, et ne fait jamais échouer l’analyse. Les champs d’adresse sont lus jusqu’à 16 Ko chacun (2000 adresses, 16 groupes imbriqués) et 64 Ko au total pour chaque message, coupés seulement à la fin d’une adresse entière, car l’analyseur d’adresses prend un temps qui croît avec le carré du nombre d’adresses ; mailauth lit From et Return-Path ainsi bornés lui aussi (les autres champs tels quels, pour qu’une signature qui les couvre reste valide), et un en-tête qu’il mettrait plus qu’un temps linéaire à lire (des milliers de lignes repliées, ou des signatures nommant des milliers de champs) est réduit. Un champ From coupé fait échouer DMARC et n’autorise rien par la liste d’autorisation. Le HTML est lu par l’analyseur propre à Spam Scanner, en temps linéaire, quelle que soit la profondeur de son imbrication.
* Le corps du message est lu jusqu’à `maxLength` (100 000 caractères) et les serveurs acceptent les messages jusqu’à 25 Mo. Les liens sont lus jusqu'à `phishing.maxLength` (1 000 000 caractères).
* Chaque vérification réseau a un délai maximal (`timeout`, 10 secondes par défaut). Une vérification qui échoue ou dépasse le délai est ignorée et l’analyse se termine sans elle. L'authentification et le modèle d'images (les 10 premières images) se terminent chacun dans ce délai au total : l’authentification n’envoie aucune requête DNS après lui, ni plus de 300 pour un message (de quoi faire SPF aux limites de la RFC 7208, avec DKIM, ARC, DMARC et BIMI), et ne vérifie que les 8 premières signatures DKIM d’un message (mailauth lui-même lit au plus 50 ensembles ARC). L’en-tête `Authentication-Results` qu’ajoute le milter contient au plus 8 Kio de résultats. ClamAV (quatre pièces jointes à la fois) a sa propre limite pour toutes les pièces jointes d’un message (`clamav.timeout`, 60 secondes), et les pièces jointes qu’il n’a pas pu analyser sont listées dans `results.virusScanErrors`. Le modèle de langage a son propre délai (`llm.timeout`).
* La liste d'autorisation ne fait confiance qu'à ce qu'un expéditeur ne peut pas falsifier : l'adresse et le nom d'hôte vérifié du client, et les domaines d'expéditeur que l'authentification confirme. [Listes d'autorisation et de blocage](api.md#allowlist-and-denylist)
* Les en-têtes `X-Spam-*` déjà présents dans un message sont supprimés par le milter, le filtre de contenu et `--headers` : les expéditeurs ne peuvent pas marquer leur propre courrier comme sain.
* Les en-têtes de verdict de spam de Microsoft ne sont pris en compte que si le message provient directement des serveurs de Microsoft, et les en-têtes Received ne servent jamais à déterminer la provenance d’un message.
* Le texte qui s’adresse aux filtres d’IA est noté comme du spam, et le modèle de langage est averti que le message est une donnée, pas une instruction. [Injection de prompt](llm.md#prompt-injection)


## Serveurs

Les serveurs milter, HTTP, TCP et spamd écoutent sur 127.0.0.1, sauf indication contraire de `--host`. L’API HTTP compare son jeton en temps constant et refuse `/learn` sans jeton. Aucun ne parle TLS : pour les joindre à travers un réseau, utilisez un réseau privé, un tunnel SSH ou un proxy inverse avec TLS.

Exécutez-les sous un utilisateur non privilégié. L’[unité systemd du guide Postfix](postfix.md#1-run-the-milter) ajoute le durcissement habituel.


## Signaler une vulnérabilité

Signalez les problèmes de sécurité en privé via le [signalement de vulnérabilités de GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), et non dans des tickets publics.
