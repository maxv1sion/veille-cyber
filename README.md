# Veille cyber

Veille automatique des vulnérabilités et menaces utiles à un RSSI, publiée avec GitHub Pages.

- **Au quotidien** (`index.html`) : liste « à traiter en priorité », puis toutes les publications filtrables par période, type, priorité, éditeur, source, parc suivi et failles exploitées
- **Synthèse de la semaine** (`hebdo.html`) : récapitulatif du lundi au dimanche, imprimable en PDF et copiable en texte pour un mail

## Sources

| Source | Contenu | Accès |
|---|---|---|
| CERT-FR (ANSSI) | Alertes et avis de sécurité, avec éditeurs, produits, CVE et risques | API JSON officielle |
| CERT-FR (ANSSI) | Rapports sur la menace, bulletins d'actualité, recommandations | Flux RSS |
| CERT Santé (ANS) | Alertes et vulnérabilités | Flux RSS |
| CISA KEV | Catalogue des failles dont l'exploitation est confirmée | JSON |
| FIRST EPSS | Probabilité d'exploitation d'une CVE sous 30 jours | API |
| ZATAZ, BleepingComputer, The Hacker News | Actualité cyber | Flux RSS |
| Clubic, LeMagIT | Actualité cyber (seuls les articles dont le titre parle de cyber sont gardés) | Flux RSS |

## Fonctionnement

GitHub Actions lance `scripts/collecte.mjs` toutes les 3 heures (fichier `.github/workflows/collecte.yml`). Le script :

1. récupère les sources et ne relit en détail que les avis CERT-FR nouveaux ou modifiés
2. croise les CVE avec le catalogue KEV et les scores EPSS
3. repère les signaux dans la presse (faille critique, zero-day, correctif d'urgence…)
4. regroupe les doublons : articles sur un même sujet, presse rattachée à l'avis officiel, avis CERT Santé repris par le CERT-FR (voir « Doublons »)
5. repère les éditeurs du parc suivi
6. calcule une priorité (critique, haute, moyenne, information)
7. met à jour `data/registre.json`, purge selon la conservation et produit la synthèse hebdo dans `data/hebdo/`
8. enregistre les changements dans le dépôt, ce qui met le site à jour

Aucun outil à installer sur le poste : tout tourne chez GitHub.

## Règles de priorité

- **Critique** : alerte CERT-FR en cours, CVE présente dans le catalogue KEV, ou EPSS d'au moins 50 %
- **Haute** : exécution de code à distance, EPSS d'au moins 10 %, ou alerte clôturée
- **Moyenne** : autres avis de sécurité
- **Information** : rapports, bulletins, recommandations et presse

Un article de presse passe en **haute** s'il cite une faille exploitée ou s'il annonce une faille critique, un zero-day, une exécution de code à distance, un correctif d'urgence ou une faille non corrigée. S'il n'existe pas encore d'avis officiel, il apparaît dans « À traiter en priorité » sous « Signalé par la presse, en attente d'avis officiel ». Les récapitulatifs hebdomadaires de la presse ne déclenchent pas de signal.

## Doublons

- **Entre médias** : les articles qui parlent du même sujet à 3 jours d'écart sont regroupés sous un seul, avec la mention « Aussi relayé par ». Deux articles sont rapprochés s'ils partagent une CVE, deux noms propres ou expressions (« Rank Math », « cloud backup »), ou un nom propre et un même signal d'alerte. Un seul nom propre en commun ne suffit pas s'il s'agit d'un grand éditeur ou d'une plateforme citée dans beaucoup d'histoires (Microsoft, WordPress, OpenAI, éditeurs du parc…). Les noms propres sont repérés grâce à la liste `config/mots-courants.txt`
- **Presse et sources officielles** : quand un avis CERT-FR, CERT Santé ou une fiche KEV traite du même sujet, l'article y est rattaché (« Dans la presse ») et quitte la rubrique « Signalé par la presse »
- **CERT-FR et CERT Santé** : un avis CERT Santé dont toutes les CVE figurent dans un avis ou une alerte CERT-FR est replié sous celui-ci (« Aussi publié par »)
- **Bloc « À traiter »** : une même CVE n'y apparaît qu'une fois, même si plusieurs sources la publient

## Fichiers

| Fichier | Rôle |
|---|---|
| `index.html`, `hebdo.html`, `assets/` | Le site (page quotidienne et synthèse hebdo) |
| `scripts/collecte.mjs` | Collecte, croisement KEV et EPSS, priorités, synthèse hebdo |
| `scripts/sujets.mjs` | Signaux presse et regroupement des doublons |
| `tests/sujets.test.mjs` | Cas réels de regroupement, à relancer après toute modification des règles (`node --test tests/sujets.test.mjs`) |
| `config/editeurs.json` | Éditeurs du parc suivi et leurs mots-clés |
| `config/sources.json` | Sources, durées de conservation, filtres |
| `config/mots-courants.txt` | Mots courants français et anglais, pour repérer les noms propres dans les titres |
| `data/` | Données produites automatiquement, à ne pas modifier à la main |

## Personnaliser

- **Éditeurs suivis** : `config/editeurs.json`. Chaque éditeur a une liste de mots-clés cherchés dans l'éditeur, le produit et le titre des bulletins
- **Sources et conservation** : `config/sources.json`. Mettre `"actif": false` pour couper une source. Conservation par défaut : 2 ans pour les avis et alertes, 90 jours pour les fiches de failles exploitées (KEV) et pour la presse. Le croisement avec le catalogue KEV complet reste actif quelle que soit cette durée

Les modifications se font directement dans GitHub (crayon « Edit this file »), elles sont prises en compte au passage suivant.

## Lancer une collecte à la main

Onglet **Actions** du dépôt, workflow « Collecte veille cyber », bouton **Run workflow**. Cocher « Régénérer la synthèse » pour refaire celle de la semaine précédente.

## Mise en ligne (une seule fois)

**Settings > Pages** : source **Deploy from a branch**, branche `main`, dossier `/ (root)`, puis **Save**.

Le site est ensuite accessible à l'adresse https://maxv1sion.github.io/veille-cyber/ (compter une à deux minutes pour la première publication).
