# SWI — Laboratoire 1

## 1. Deauthentication attack

> Quel code est utilisé par aircrack pour déauthentifier un client 802.11. Quelle est son interpretation ?

Le code utilisé est le 7 « Class 3 frame received from nonassociated station ».

> À l'aide d'un filtre d'affichage, essayer de trouver d'autres trames de déauthentification dans votre capture. Avez-vous en trouvé d'autres ? Si oui, quel code contient-elle et quelle est son interpretation ?

Avec Wireshark on peut utiliser le filtre suivant: `(wlan.fc.type eq 0) && (wlan.fc.type_subtype eq 12)`. On a trouvé les codes 3 (réseau quitté volontairement) et 4 (réseau quitté à cause d'inactivité).

> Quels codes/raisons justifient l'envoie de la trame à la STA cible et pourquoi ?

1, 4, 5

> Quels codes/raisons justifient l'envoie de la trame à l'AP et pourquoi ?

1, 8

> Comment essayer de déauthentifier toutes les STA ?

Mettre en adresse cible client (pour les codes 1, 4 et 5) l'adresse FF:FF:FF:FF:FF:FF qui est l'adresse de broadcast.

> Quelle est la différence entre le code 3 et le code 8 de la liste ?

D'après cette [spécification](https://www.iith.ac.in/~tbr/teaching/docs/802.11-2007.pdf), le code 3 annonce une déauthentification alors que le code 8 annonce une désassociation.

> Expliquer l'effet de cette attaque sur la cible.

La cible va être déconnectée du réseau Wifi, il est ainsi possible d'effectuer un déni de service en effectuant continuellement cette attaque (la cible ne restera jamais connectée au WiFi assez longtemps pour pouvoir profiter du service).

## 2. Fake channel evil tween attack

> Expliquer l'effet de cette attaque sur la cible

Si la cible est déjà connectée à un réseau, cette attaque n'aura probablement pas d'effet. Par contre, si la cible est déconnectée de ce réseau (par exemple avec l'attaque 1), elle pourra être amenée à se connectée au réseau malicieux.
