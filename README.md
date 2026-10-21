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

## Fonctionnement

GitHub Actions lance `scripts/collecte.mjs` toutes les 3 heures (fichier `.github/workflows/collecte.yml`). Le script :

1. récupère les sources et ne relit en détail que les avis CERT-FR nouveaux ou modifiés
2. croise les CVE avec le catalogue KEV et les scores EPSS
3. repère les éditeurs du parc suivi
4. calcule une priorité (critique, haute, moyenne, information)
5. met à jour `data/registre.json`, purge selon la conservation et produit la synthèse hebdo dans `data/hebdo/`
6. enregistre les changements dans le dépôt, ce qui met le site à jour

Aucun outil à installer sur le poste : tout tourne chez GitHub.

## Règles de priorité

- **Critique** : alerte CERT-FR en cours, CVE présente dans le catalogue KEV, ou EPSS d'au moins 50 %
- **Haute** : exécution de code à distance, EPSS d'au moins 10 %, ou alerte clôturée
- **Moyenne** : autres avis de sécurité
- **Information** : rapports, bulletins, recommandations et presse (passent en haute s'ils citent une faille exploitée)

## Personnaliser

- **Éditeurs suivis** : `config/editeurs.json`. Chaque éditeur a une liste de mots-clés cherchés dans l'éditeur, le produit et le titre des bulletins
- **Sources et conservation** : `config/sources.json`. Mettre `"actif": false` pour couper une source. Conservation par défaut : 2 ans pour les vulnérabilités, 90 jours pour la presse

Les modifications se font directement dans GitHub (crayon « Edit this file »), elles sont prises en compte au passage suivant.

## Lancer une collecte à la main

Onglet **Actions** du dépôt, workflow « Collecte veille cyber », bouton **Run workflow**. Cocher « Régénérer la synthèse » pour refaire celle de la semaine précédente.

## Mise en ligne (une seule fois)

1. **Settings > Actions > General** : dans « Workflow permissions », choisir **Read and write permissions**
2. **Actions** : lancer « Collecte veille cyber » une première fois avec **Run workflow**
3. **Settings > Pages** : source **Deploy from a branch**, branche `main`, dossier `/ (root)`

Le site est ensuite accessible à l'adresse `https://<compte>.github.io/veille-cyber/`.
