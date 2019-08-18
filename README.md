# IP-over-DNS (Client part)


## English version

TODO


## French version

**IP-over-DNS** est une méthode qui permet d'emballer des requêtes et des réponses "normales" (par exemple de type HTTP) sous forme de DNS en utilisant un protocole standard du DNS. Ceci a un avantage : lorsqu'on veut se connecter à un wifi payant mais peu sécurisé, comme les requêtes DNS sont moins checkées, ces données ne seront pas bloquées. Le projet consiste principalement en 2 parties : client et serveur. Le client est celui qui veut se connecter donc il doit posséder un programme qui emballe les requêtes sous forme de DNS et déballe les réponses DNS. Le serveur est celui qui a l'accès à l'internet et qui sert d'un intermédiaire pour déballer les paquets DNS et les envoyer au serveur à qui le client veut se connecter, et inversement pour la réponse.

L'idée de l'implémentation est de créer une interface virtuelle dite **tap** dans la machine et modifier la table de routage de sorte que tous les traffics passent par cette interface. Ce programme *DNS_Client* exploite les données lues sur tap et les emballe en DNS. Pour cela nous avons créé une struct, nommée *DNS_Packet*, qui possède tous les champs correspondant au standard, qu'on remplit en fonction des données écoutées sur tap. On a ensuite implémenté dans le fichier *DNS_Query.h* une fonction *DNS_to_Binary* qui transforme les packets DNS en tableaux d'octets. Pour tester et visualiser cette partie de code :



- Télécharger **openvpn**

- Lancer :

> sudo ./setup_tap.sh

Tous les traffics allant à 8.8.8.8 vont passer par l'interface virtuelle **tap0**

- Compiler en tapant :

> make

- Lancer : 

> ./DNS_Client www.google.com 127.0.0.1 

- www.google.com c'est pour indiquer à la partie serveur à qui je veux me connecter ; **127.0.0.1** aurait dû être l'adresse IP du serveur mais ici on utilise la machine elle-même pour tester.

- Constater à l'écran des messages parasites lus sur **tap0** (raison inconnue) mais si on essaie de "pinger" 8.8.8.8 (dans un autre terminal) on verra des messages créés : ce sont des données à être emballées en DNS et envoyées au serveur.

- Lancer pour tuer **tap0** :

> sudo ./shut_tap.sh



En fait il existe d'autres complications que nous n'avons pas réussi à résoudre, surtout l'écoute de la réponse, car DNS utilise UDP où il n'y a pas de "handshake". Il faudrait envoyer des requêtes "vides" pour demander au serveur s'il y a des réponses pour le client car le serveur ne communique pas spontanément au client s'il y a une réponse, par exemple, de la part de google. D'autre part, la manière dont on transforme les packets DNS en tableaux d'octets ne suivent pas le protocole standard (mais très similaire !), donc un vrai serveur DNS ne le comprendrait pas. Ceci pourrait se refaire facilement mais comme le serveur est encore plus compliqué à implémenter, finalement nous avons réalisé le projet avec une version plutôt simplifiée, mais la communication entre le client et le serveur et les procédures d'encodage et de décodage étaient avec succès.


