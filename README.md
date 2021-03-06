[Livrables](#livrables)

[Échéance](#échéance)

[Quelques pistes importantes](#quelques-pistes-utiles-avant-de-commencer-)

[Travail à réaliser](#travail-à-réaliser)

1. [Deauthentication attack](#1-deauthentication-attack)
2. [Fake channel evil tween attack](#2-fake-channel-evil-tween-attack)
3. [SSID Flood attack](#3-ssid-flood-attack)

# Sécurité des réseaux sans fil

## Laboratoire 802.11 MAC 1

__A faire en équipes de deux personnes__

### Pour cette partie pratique, vous devez être capable de :

*	Détecter si un certain client WiFi se trouve à proximité
*	Obtenir une liste des SSIDs annoncés par les clients WiFi présents

Vous allez devoir faire des recherches sur internet pour apprendre à utiliser Scapy et la suite aircrack pour vos manipulations. __Il est fortement conseillé d'employer une distribution Kali__ (on ne pourra pas assurer le support avec d'autres distributions). __Si vous utilisez une VM, il vous faudra une interface WiFi usb, disponible sur demande__.

__ATTENTION :__ Pour vos manipulations, il pourrait être important de bien fixer le canal lors de vos captures et/ou vos injections (à vous de déterminer si ceci est nécessaire pour les manipulations suivantes ou pas). Si vous en avez besoin, la méthode la plus sure est d'utiliser l'option :

```--channel``` de ```airodump-ng```

et de garder la fenêtre d'airodump ouverte en permanence pendant que vos scripts tournent ou vos manipulations sont effectuées.


## Quelques pistes utiles avant de commencer :

- Si vous devez capturer et injecter du trafic, il faudra configurer votre interface 802.11 en mode monitor.
- Python a un mode interactif très utile pour le développement. Il suffit de l'invoquer avec la commande ```python```. Ensuite, vous pouvez importer Scapy ou tout autre module nécessaire. En fait, vous pouvez même exécuter tout le script fourni en mode interactif !
- Scapy fonctionne aussi en mode interactif en invoquant la commande ```scapy```.  
- Dans le mode interactif, « nom de variable + <enter> » vous retourne le contenu de la variable.
- Pour visualiser en détail une trame avec Scapy en mode interactif, on utilise la fonction ```show()```. Par exemple, si vous chargez votre trame dans une variable nommée ```beacon```, vous pouvez visualiser tous ces champs et ses valeurs avec la commande ```beacon.show()```. Utilisez cette commande pour connaître les champs disponibles et les formats de chaque champ.

## Travail à réaliser

### 1. Deauthentication attack

Une STA ou un AP peuvent envoyer une trame de déauthentification pour mettre fin à une connexion.

Les trames de déauthentification sont des trames de management, donc de type 0, avec un sous-type 12 (0x0c). Voici le format de la trame de déauthentification :

![Trame de déauthentification](images/deauth.png)

Le corps de la trame (Frame body) contient, entre autres, un champ de deux octets appelé "Reason Code". Le but de ce champ est d'informer la raison de la déauthentification. Voici toutes les valeurs possibles pour le Reason Code :

| Code | Explication 802.11                                                                                                                                     |
|------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0    | Reserved                                                                                                                                              |
| 1    | Unspecified reason                                                                                                                                    |
| 2    | Previous authentication no longer valid                                                                                                               |
| 3    | station is leaving (or has left) IBSS or ESS                                                                                                          |
| 4    | Disassociated due to inactivity                                                                                                                       |
| 5    | Disassociated because AP is unable to handle all currently associated stations                                                                        |
| 6    | Class 2 frame received from nonauthenticated station                                                                                                  |
| 7    | Class 3 frame received from nonassociated station                                                                                                     |
| 8    | Disassociated because sending station is leaving (or has left) BSS                                                                                    |
| 9    | Station requesting (re)association is not authenticated with responding station                                                                       |
| 10   | Disassociated because the information in the Power Capability element is unacceptable                                                                 |
| 11   | Disassociated because the information in the Supported Channels element is unacceptable                                                               |
| 12   | Reserved                                                                                                                                              |
| 13   | Invalid information element, i.e., an information element defined in this standard for which the content does not meet the specifications in Clause 7 |
| 14   | Message integrity code (MIC) failure                                                                                                                                              |
| 15   | 4-Way Handshake timeout                                                                                                                                              |
| 16   | Group Key Handshake timeout                                                                                                                                              |
| 17   | Information element in 4-Way Handshake different from (Re)Association Request/Probe Response/Beacon frame                                                                                                                                              |
| 18   | Invalid group cipher                                                                                                                                              |
| 19   | Invalid pairwise cipher                                                                                                                                              |
| 20   | Invalid AKMP                                                                                                                                              |
| 21   | Unsupported RSN information element version                                                                                                                                              |
| 22   | Invalid RSN information element capabilities                                                                                                                                              |
| 23   | IEEE 802.1X authentication failed                                                                                                                                              |
| 24   | Cipher suite rejected because of the security policy                                                                                                                                              |
| 25-31 | Reserved                                                                                                                                              |
| 32 | Disassociated for unspecified, QoS-related reason                                                                                                                                              |
| 33 | Disassociated because QAP lacks sufficient bandwidth for this QSTA                                                                                                                                              |
| 34 | Disassociated because excessive number of frames need to be acknowledged, but are not acknowledged due to AP transmissions and/or poor channel conditions                                                                                                                                              |
| 35 | Disassociated because QSTA is transmitting outside the limits of its TXOPs                                                                                                                                              |
| 36 | Requested from peer QSTA as the QSTA is leaving the QBSS (or resetting)                                                                                                                                              |
| 37 | Requested from peer QSTA as it does not want to use the mechanism                                                                                                                                              |
| 38 | Requested from peer QSTA as the QSTA received frames using the mechanism for which a setup is required                                                                                                                                              |
| 39 | Requested from peer QSTA due to timeout                                                                                                                                              |
| 40 | Peer QSTA does not support the requested cipher suite                                                                                                                                              |
| 46-65535 | Reserved                                                                                                                                              |

a) Utiliser la fonction de déauthentification de la suite aircrack, capturer les échanges et identifier le Reason code et son interpretation.

__Question__ : quel code est utilisé par aircrack pour déauthentifier un client 802.11. Quelle est son interpretation ?

___Réponse___ : Le reason code 7 ("Class 3 frame received from nonassociated station") est généré par aircrack-ng. Ce reason code peut être envoyé à une STA depuis un AP lorsque, par exemple, un client (STA) tente de transmettre des paquets (layer 3) avant d'être associé avec l'AP (mais déjà authentifié).

![](./images/reason_code_airoplay.png)

__Question__ : A l'aide d'un filtre d'affichage, essayer de trouver d'autres trames de déauthentification dans votre capture. Avez-vous en trouvé d'autres ? Si oui, quel code contient-elle et quelle est son interpretation ?

___Réponse___ : Nous avons trouvé des trames avec les codes :<br/>
1 (Unspecified): Ce reason code peut être utilisé pour n'importe quelle raison de déauthentification.<br/>
3 (Station is leaving (or has left) IBSS or ESS): Ce reason code est envoyé depuis une STA à un AP pour indiquer à l'AP que la STA est entrain de se déauthentifier (ou s'est déauthentifié) de l'AP. Cela peut arriver lorsqu'on désactive le wifi de notre téléphone par exemple.<br/>
6 (Class 2 frame received from nonauthenticated station) : Ce reason code ressemble fortement à la description du reason code 7 à la différence près que, pour celui-ci, la STA tente de transmettre une trame (layer 2) à l'AP alors qu'elle n'est pas authentifiée avec l'AP.<br/>
f (4-Way Handshake timeout): Ce reason code peut être envoyé depuis/aux deux parties (STA ou AP) pour indiquer un handshake qui ne s'est jamais terminé.<br/>

![](./images/deauthMultiRC.png)

b) Développer un script en Python/Scapy capable de générer et envoyer des trames de déauthentification. Le script donne le choix entre des Reason codes différents (liste ci-après) et doit pouvoir déduire si le message doit être envoyé à la STA ou à l'AP :
* 1 - Unspecified
* 4 - Disassociated due to inactivity
* 5 - Disassociated because AP is unable to handle all currently associated stations
* 8 - Deauthenticated because sending STA is leaving BSS

Afin de vérifier la connectivité de la cible, nous avons exécuté un ping en continue dans un terminal pendant l'attaque. Voici le résultat :


![](./images/pings2.png)

__Question__ : quels codes/raisons justifient l'envoie de la trame à la STA cible et pourquoi ?

__Réponse__ :

Le code 1: Comme expliqué plus haut, ce reason code peut être utilisé pour justifier n'importe quel problème et peut être envoyé autant depuis l'AP que depuis la STA.<br/>
Le code 5: Ce reason code est envoyé depuis une AP à une STA pour lui indiquer qu'il est saturé et ne peut donc pas s'associer avec la STA pour l'instant.

__Question__ : quels codes/raisons justifient l'envoie de la trame à l'AP et pourquoi ?

__Réponse__ :

Le code 1: Comme expliqué plus haut, ce reason code peut être utilisé pour justifier n'importe quel problème et peut être envoyé autant depuis l'AP que depuis la STA.<br/>
Le code 4: Ce reason code est envoyé depuis une STA à un AP pour informer l'AP qu'elle n'est plus accessible (timeout). Ce genre de situation peut arriver si, par exemple, on s'éloigne trop d'une AP avec son téléphone mobile et qu'on ne reçoit plus de données.<br/>
Le code 8: Ce reason code est envoyé depuis une STA à un AP pour lui indiquer qu'elle quitte la BSS actuelle, c'est à dire qu'elle change d'AP sans forcément changer d' IBSS/ESS (sans changer de réseau).

__Question__ : Comment essayer de déauthentifier toutes les STA ?

__Réponse__ : Avec Aircrack, Il est possible d'utiliser l'adresse MAC de broadcast comme cible (dans la commande aireplay-ng) pour envoyer les trames de déauthentification à toutes les STA authentifiées ou associées avec un AP.

__Question__ : Quelle est la différence entre le code 3 et le code 8 de la liste ?

__Réponse__ : Le code 3 indique une déauthentification tandis que le code 8 indique une désassociation.

Pour rappel, lorsqu'une STA veut se connecter à une AP, le processus se fait en deux étapes.<br/>
Tout d'abord, la phase d'authentification dans laquelle la STA transmet les identifiants fournis par l'utilisateur à l'AP.<br/>
L'AP les comparent avec les identifiants stockés dans la base de donnée local du routeur ou à travers d'un serveur d'authentification.<br/>
Si les identifiants correspondent, le processus est complété et l'utilisateur obtient les droits d'accès aux communications avec l'AP.

La seconde étape est la phase d'association dans laquelle la STA et l'AP vont se mettre d'accord sur les paramètrages techniques pour pouvoir communiquer au mieux. Par exemple, le canal de communication, la vitesse de transfert des données, etc.

Finalement, un reason code 3 sera utilisé lorsqu'un une STA quitte le réseau, par exemple, désactivation du wifi sur un téléphone mobile. un reason code 8 sera utilisé lorsqu'une STA change d'AP en restant sur connecté au même réseau par exemple.

__Question__ : Expliquer l'effet de cette attaque sur la cible

__Réponse__ : Cette permet de ralentir voir stopper complétement les communications entre une/des STA et un AP en faisant croire aux deux parties que les appareils souhaitent se déauthentifier. C'est une attaque de type "Deny of Service". Cette attaque peut aussi être utilisée pour récupérer des handshakes utiles pour d'autres attaques.

### 2. Fake channel evil tween attack
a)	Développer un script en Python/Scapy avec les fonctionnalités suivantes :

* Dresser une liste des SSID disponibles à proximité
* Présenter à l'utilisateur la liste, avec les numéros de canaux et les puissances
* Permettre à l'utilisateur de choisir le réseau à attaquer
* Générer un beacon concurrent annonçant un réseau sur un canal différent se trouvant à 6 canaux de séparation du réseau original

__Question__ : Expliquer l'effet de cette attaque sur la cible

__Réponse__ : Cela aura comme effet de forcer les STA connectée au réseau à essayer de changer de canal pour communiquer. L'AP légitime n'étant pas sur ce canal, va à son tour, envoyer des beacons indiquant le bon canal. Cette attaque lancée en continue peut mener à un DoS des appareils connectés au réseau.

On peut voir le fonctionnement du script sur le screen ci dessous :

![evil twin attack proof](./images/proof_evil_twin.png)

On a simulé le wifi nommé Honor 8 qui était à la base sur le channel 1 et envoyé un beacon identique mais cette fois sur le channel 7

### 3. SSID flood attack

Développer un script en Python/Scapy capable d'inonder la salle avec des SSID dont le nom correspond à une liste contenue dans un fichier text fournit par un utilisateur. Si l'utilisateur ne possède pas une liste, il peut spécifier le nombre d'AP à générer. Dans ce cas, les SSID seront générés de manière aléatoire.



## Livrables

Un fork du repo original . Puis, un Pull Request contenant :

- Script de Deauthentication de clients 802.11 __abondamment commenté/documenté__

- Script fake chanel __abondamment commenté/documenté__

- Script SSID flood __abondamment commenté/documenté__

- Captures d'écran du fonctionnement de chaque script

-	Réponses aux éventuelles questions posées dans la donnée. Vous répondez aux questions dans votre ```README.md``` ou dans un pdf séparé

-	Envoyer le hash du commit et votre username GitHub par email au professeur et à l'assistant


## Échéance

Le 9 mars 2020 à 23h59
