# IP-over-DNS tunneling (Client part)

## Aperçu

**IP-over-DNS tunneling** (ou **DNS tunneling** plus court) est une méthode qui 
permet d'emballer des requêtes et des réponses typiques (par exemple de type 
HTTP) sous forme de DNS en utilisant le protocole standard de DNS. Ceci a un 
avantage : lorsqu'on veut se connecter à un Wi-Fi payant qui est, par contre, 
peu sécurisé, comme les requêtes DNS sont moins checkées, ces données ne seront 
pas bloquées. 

Le projet consiste principalement en 2 parties : client et serveur. D'un côté, 
le client est celui qui veut se connecter donc il posséde un programme qui 
emballe les requêtes en DNS et déballe les réponses DNS. D'un autre côté, le 
serveur est celui qui a l'accès à l'internet et qui sert d'un intermédiaire 
pour déballer les paquets DNS et les envoyer au serveur à qui le client veut se 
connecter, et inversement pour la réponse.

L'idée de l'implémentation est de créer une interface virtuelle dite **tap** 
dans la machine et modifier la table de routage de sorte que tous les traffics 
passent par cette interface. Ce programme *DNS_Client* exploite les données 
lues sur tap et les emballe en DNS. Pour cela nous avons créé une struct, 
nommée *DNS_Packet*, qui possède tous les champs correspondant au protocole 
standard, qu'on remplit en fonction des données écoutées sur tap. Nous avons 
ensuite implémenté dans le fichier *DNS_Query.h* une fonction *DNS_to_Binary* 
qui transforme les packets DNS en tableaux d'octets. 


### Usage

Pour tester et visualiser cette partie de code :

- Télécharger **openvpn** en tapant par exemple : `sudo apt-get install openvpn`

- Lancer : `sudo ./setup_tap.sh`

Tous les traffics allant à 8.8.8.8 vont passer par l'interface virtuelle 
**tap0**

- Compiler en tapant : `make`

- Lancer : 

`./DNS_Client www.google.com 127.0.0.1`

www.google.com c'est pour indiquer à la partie serveur à qui je veux me 
connecter ; **127.0.0.1** aurait dû être l'adresse IP du serveur mais ici on 
utilise la machine elle-même pour tester.

- Constater à l'écran des messages parasites lus sur **tap0** (raison inconnue) 
mais si on essaie de "pinger" 8.8.8.8 (dans un autre terminal) on verra des 
messages créés : ce sont des données à être emballées en DNS et envoyées au 
serveur.

- Pour tuer **tap0**, lancer : `sudo ./shut_tap.sh`


### Remarques

En fait il existe d'autres complications que nous n'avons pas réussi à résoudre,
surtout l'écoute de la réponse, car DNS utilise UDP où il n'y a pas de 
*handshake*. Il faudrait envoyer des requêtes *vides* pour demander au serveur 
s'il y a des réponses pour lui car le serveur ne communique pas spontanément au 
client même s'il y a déjà une réponse, par exemple, de la part de google. 
D'autre part, la manière dont on transforme les packets DNS en tableaux 
d'octets ne suivent pas exactement le protocole standard (mais très 
similaire !), donc un vrai serveur DNS ne le comprendrait pas. Ceci pourrait se 
réparer facilement mais comme le serveur est encore plus compliqué à 
implémenter, finalement nous avons terminé le projet avec une version plutôt 
simplifiée, comme la communication client/serveur et les processus 
d'encodage/décodage étaient avec succès.