# Découvertes réelles faites en construisant ce projet

## 1. `service rsyslog start` ne fonctionne pas dans un conteneur minimal

**Constat :** le conteneur `ssh-target` plantait immédiatement au démarrage
avec l'erreur `rsyslog: unrecognized service`.

**Cause :** la commande `service` s'appuie sur les scripts d'init système
(SysVinit), absents ou incomplets dans une image Debian slim pensée pour les
conteneurs (pas de vrai système d'init comme dans une VM classique).

**Correction :** lancer le démon directement (`/usr/sbin/rsyslogd`) plutôt
que de passer par la commande `service`, dans `ssh_target/entrypoint.sh`.

## 2. `unquote()` ne décode pas les "+" — les injections passaient inaperçues

**Constat :** sur 5 tentatives d'injection envoyées, le moteur de détection
n'en repérait que 2 (traversée de répertoire, XSS), alors que les 5 étaient
bien présentes dans Elasticsearch.

**Cause :** une requête HTTP encode les espaces soit en `%20`, soit en `+`
(encodage "application/x-www-form-urlencoded"). La bibliothèque standard
`urllib.parse.unquote()` ne décode que les séquences `%XX` — elle laisse les
`+` tels quels. Résultat : le payload `' OR '1'='1` devenait
`'+OR+'1'='1` après décodage, et l'expression régulière (qui cherche un
espace entre "or" et "'1'") ne correspondait plus.

**Correction :** utiliser `urllib.parse.unquote_plus()`, qui décode les deux
formes d'encodage à la fois. Un test de non-régression dédié
(`test_injection_detected_even_when_url_encoded_with_plus_signs`) vérifie
maintenant explicitement ce cas.

**À retenir :** un test avec une donnée "propre" (`test_no_false_positive`)
n'aurait jamais révélé ce bug — il fallait un test avec une donnée
*réellement* encodée comme le serait un vrai payload d'attaque.

## 3. Elasticsearch tué par manque de mémoire (OOM) au premier lancement

**Constat :** au tout premier `docker compose up`, Elasticsearch et Kibana
disparaissaient quelques dizaines de secondes après leur démarrage (code de
sortie 137, la signature classique d'un `SIGKILL` envoyé par le noyau).

**Cause :** la machine virtuelle Docker (gérée par Colima sur ce Mac) était
allouée avec seulement 4 Go de RAM. Faire tourner simultanément
Elasticsearch (qui a besoin d'environ 1 à 1,5 Go), Kibana (~700 Mo),
Prometheus, Grafana et plusieurs autres conteneurs dépassait cette limite —
le noyau Linux de la VM a alors tué le processus le plus gourmand
(Elasticsearch) pour survivre.

**Correction :** augmentation de la mémoire allouée à la VM (4 Go → 6 Go), et
démarrage des services par étapes (Elasticsearch et Kibana d'abord, vérifiés
stables, puis le reste) plutôt que tout d'un coup — une pratique de bon sens
pour diagnostiquer un problème de ressources plutôt que de deviner.

## 4. cAdvisor ne voit pas les conteneurs applicatifs dans cet environnement

**Constat :** le panel Grafana censé afficher la mémoire par conteneur
(`container_memory_usage_bytes` groupé par nom) ne renvoyait aucune donnée.

**Diagnostic :** en interrogeant directement Prometheus, les seules séries
disponibles pour cette métrique correspondaient aux cgroups système de la VM
Colima (`/system.slice/...`) et non aux conteneurs applicatifs
(elasticsearch, webapp...). Dans cet environnement (Docker exécuté à
l'intérieur d'une VM Linux légère elle-même virtualisée sur macOS), cAdvisor
n'a pas la visibilité attendue sur les cgroups des conteneurs applicatifs.

**Contournement retenu :** remplacer ce panel par une métrique système
équivalente et fiable (mémoire totale utilisée via `node-exporter`), tout en
gardant cAdvisor dans la stack et en documentant cette limite plutôt que de
masquer le problème. Dans un vrai cluster Kubernetes/VM Linux native, ce
problème ne se poserait pas — c'est une particularité de l'environnement de
démonstration (VM imbriquée), pas une erreur de configuration de cAdvisor.
