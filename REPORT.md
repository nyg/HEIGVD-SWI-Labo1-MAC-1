# SWI — Laboratoire 1

## 1. Deauthentication attack

> __Question__ : quel code est utilisé par aircrack pour déauthentifier un client 802.11. Quelle est son interpretation ?

Le code utilisé est le 0x7. Class 3 frame received from nonassociated station.

> __Question__ : A l'aide d'un filtre d'affichage, essayer de trouver d'autres trames de déauthentification dans votre capture. Avez-vous en trouvé d'autres ? Si oui, quel code contient-elle et quelle est son interpretation ?

Avec Wireshark on peut utiliser le filtre suivant: `(wlan.fc.type eq 0) && (wlan.fc.type_subtype eq 12)`. On a trouvé les codes 3 (réseau quitté volontairement), 4 (réseau quitté à cause d'inactivité), 6.

> __Question__ : quels codes/raisons justifient l'envoie de la trame à la STA cible et pourquoi ?

1,4,5 - Je ne sai pas encore

> __Question__ : quels codes/raisons justifient l'envoie de la trame à l'AP et pourquoi ?

8 - Je ne sais pas encore

> __Question__ : Comment essayer de déauthentifier toutes les STA ?

Mettre en addresse cible client (pour les codes 1,4 et 5) l'adresse FF:FF:FF:FF:FF:FF

> __Question__ : Quelle est la différence entre le code 3 et le code 8 de la liste ?

Une c'est l'AP qui informe et l'autre la STA ?

> __Question__ : Expliquer l'effet de cette attaque sur la cible.

Elle est déconnectée du réseau, dans certains cas testé le client doit réentrer le mot de passe du WiFi.

## 2. Fake channel evil tween attack

> __Question__ : Expliquer l'effet de cette attaque sur la cible
