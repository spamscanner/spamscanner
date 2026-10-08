<!-- source: 60f00f92b5aa -->

# Sécurité et confidentialité

Spam Scanner lit du courrier, qui est privé, provenant d’expéditeurs, qui peuvent être hostiles. Cette page liste ce qu’il envoie où que ce soit, et comment il traite ce qu’il lit.


## Ce qui quitte la machine

Par défaut, une seule chose : les **noms d’hôte des liens** d’un message sont interrogés auprès des résolveurs filtrants de Cloudflare, 1.1.1.2 et 1.0.0.2 (logiciels malveillants et hameçonnage) et 1.1.1.3 et 1.0.0.3 (également contenu pour adultes). Ce sont des requêtes DNS ordinaires pour des noms comme `example.com` ; aucune partie du message ni de ses adresses n’est envoyée. Désactivez-les avec `phishing: {cloudflare: false}` ou `--no-cloudflare`, ou seulement la vérification du contenu pour adultes avec `phishing: {adult: false}`.

Tout le reste est désactivé tant qu’il n’est pas configuré :

| Vérification        | Envoie                                                                                           | À                                                                                     |
| ------------------- | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------- |
| `authentication`    | Des requêtes DNS pour les enregistrements SPF, DKIM, DMARC et ARC de l’expéditeur                | Votre résolveur, ou `dnsServers`                                                      |
| `dnsbl`             | L’adresse IP du client, inversée, et les domaines des liens, sous forme de requêtes DNS          | Les serveurs de noms des listes de blocage, via votre résolveur ou `dns.servers`      |
| `llm`               | Un résumé du message, dont les données personnelles sont retirées pour les fournisseurs distants | Le serveur de modèle de langage que vous indiquez ([confidentialité](llm.md#privacy)) |
| `reputation.apiUrl` | L’adresse IP, le domaine et l’adresse de l’expéditeur                                            | Le service que vous indiquez                                                          |
| `clamav`            | Les pièces jointes                                                                               | Votre clamd, via son socket                                                           |

Il n’y a aucune télémétrie, aucune vérification de mise à jour et aucun téléchargement à l’exécution. Le modèle est livré dans le paquet.


## Ce qu’il conserve

Rien, sauf demande. Les analyses ne sont ni journalisées ni stockées. `learn()` modifie le classifieur en mémoire ; il n’est écrit sur le disque que par `saveModel()`, `spamscanner learn` ou l’option `--out` des serveurs. Un fichier de modèle contient des décomptes de caractéristiques hachées, pas des mots ni le texte des messages.

Les réponses du modèle de langage sont mises en cache en mémoire, indexées par un hachage de ce qui a été envoyé : les copies répétées d’un même message ne sont soumises qu’une seule fois. Les réponses DNS sont mises en cache en mémoire pendant dix minutes.


## Entrées hostiles

* Les pièces jointes sont identifiées par leurs octets, jamais exécutées ni ouvertes par un autre programme. Les archives ZIP sont lues à partir de leur répertoire central, avec une limite sur le nombre d’entrées ; les archives imbriquées ne sont pas décompressées.
* Le corps du message est lu jusqu’à `maxLength` (100 000 caractères) et les serveurs acceptent les messages jusqu’à 25 Mo.
* Chaque vérification réseau a un délai maximal (`timeout`, 10 secondes par défaut). Une vérification qui échoue ou dépasse le délai est ignorée et l’analyse se termine sans elle.
* Les en-têtes `X-Spam-*` déjà présents dans un message sont supprimés par le milter, le filtre de contenu et `--headers` : les expéditeurs ne peuvent pas marquer leur propre courrier comme sain.
* Les en-têtes de verdict de spam de Microsoft ne sont pris en compte que si le message provient directement des serveurs de Microsoft, et les en-têtes Received ne servent jamais à déterminer la provenance d’un message.
* Le texte qui s’adresse aux filtres d’IA est noté comme du spam, et le modèle de langage est averti que le message est une donnée, pas une instruction. [Injection de prompt](llm.md#prompt-injection)


## Serveurs

Les serveurs milter, HTTP, TCP et spamd écoutent sur 127.0.0.1, sauf indication contraire de `--host`. L’API HTTP compare son jeton en temps constant et refuse `/learn` sans jeton. Aucun ne parle TLS : pour les joindre à travers un réseau, utilisez un réseau privé, un tunnel SSH ou un proxy inverse avec TLS.

Exécutez-les sous un utilisateur non privilégié. L’[unité systemd du guide Postfix](postfix.md#1-run-the-milter) ajoute le durcissement habituel.


## Signaler une vulnérabilité

Signalez les problèmes de sécurité en privé via le [signalement de vulnérabilités de GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), et non dans des tickets publics.
