# Challenge Brigitte Friang - L’énigme de la crypte
> par Ak3la, équipe InSecurity

### Description

>  Une livraison de souffre doit avoir lieu 47°N 34 2°W 1 39.
>
> Elle sera effectuée par un certain REJEWSKI. Il a reçu des instructions sur un foulard pour signaler à Evil Gouv son arrivée imminente.
>
> Nous avons une photo du foulard, mais celle-ci n'est pas très nette et nous n'avons pas pu lire toutes les informations. Le fichier foulard.txt, est la retranscription du foulard.
>
> Nous avons un peu avancé sur les parties illisibles :
>
> (texte illisible 1) est deux lettres un espace deux lettres. Il pourrait y avoir un lien avec le dernier code d'accès que vous avez envoyé à Antoine Rossignol.
>
> (texte illisible 2) a été totalement effacé et enfin (texte illisible 3) semble être deux lettres.
>
> REJEWSKI vient d'envoyer un message (final.txt). Il faut que vous arriviez à le déchiffrer. Je vous conseille d'utiliser openssl pour RSA.
>
> Le flag est de la forme DGSESIEE{MESSAGE} où MESSAGE correspond à la partie centrale du texte en majuscules sans espace.
>
> final.txt (SHA256=1e93526cd819aedb8496430a800a610068e95762536b0366ca7c303a74eaab03) : http://challengecybersec.fr/d3d2bf6b74ec26fdb57f76171c36c8fa/final.txt
> foulard.txt (SHA256=9c8b0caf9d72fa68ddb6b4a68e860ee594683f7fe4a01a821914539ef81a1f21) : http://challengecybersec.fr/d3d2bf6b74ec26fdb57f76171c36c8fa/foulard.txt 

Ce challenge est un challenge de cryptanalyse. Le scénario qui nous est donné explique qu’un message, envoyé par un certain agent ennemi nommé REJEWSKI, a été intercepté. Son protocole de chiffrement a également été partiellement intercepté. Le message se trouve dans le fichier final.txt et le protocole dans le fichier foulard.txt.
Voici comment nous avons procédé à la récupération du flag.

<u>Compréhension du chiffrement :</u>

Dans un premier temps il nous faut comprendre comment le message a été encodé. On se base donc sur les informations données dans foulard.txt.
On sait qu’il y a une première phase de chiffrement, puis un chiffrement RSA avant que le message soit envoyé.
Pour trouver la première phase de chiffrement, les informations qu’il faut noter sont les mots en allemand (Ringstellung, Steckerverbindungen, Grundstellung), l’indicatif « m3 » et le nom l’agent ennemi « REJEWSKI ».

En effectuant une recherche rapide, on comprend que la première partie du processus de chiffrement est une utilisation de la machine Enigma m3.
(m3 est la version de Enigma utilisée, Ringstellung, Steckerverbindungen et Grundstellung des paramètre de la machine et REJEWSKI est le nom de famille d’un mathématiciens polonais qui a travaillé sur le déchiffrement de message codé par Enigma pendant la Seconde Guerre Mondiale)
La méthode est donc de d’abord déchiffrer le RSA, puis de passer le résultat dans Enigma avec les bon paramètre pour avoir le message d’origine, donc le flag.

### Etape 1 : déchiffrement du RSA

Pour décoder le fichier RSA, il nous faut la clé privé que nous n’avons pas. Cependant, cette clé peut être déduite à partir de la clé publique, que nous n’avons pas non plus.
Ce que nous avons (Modulus et PublicExponent) permettent de calculer la clé publique.
Nous utilisons donc l’outils RsaCtfTool (sur github) pour calculer la clé publique et le même outil pour calculer la clé privée.

Calcul de la clé publique :
```sh
~$: python3 RsaCtfTool.py --createpub -n “modulus” -e “PublicExponent”
```
Calcul de la clé privé a partir de la clé publique :
```sh
~$: python3 RsaCtfTool.py --publickey ./key.pub –private
```
Avec openssl, on décrypte le ficher final.txt :
```sh
~$: openssl rsautl -decrypt -in “encrypted_file” -out “output_file” -inkey privkey.pem
```
Nous obtenons en sortie le texte :
**IVQDQT NHABMPSVBYYUCJIYMJBRDWXAXP  THYVCROD**

### Etape 2 : déchiffrement du message Enigma

La machine Enigma m3 avait plusieurs paramètre à régler pour coder un message :
-	Les 3 rotors à utiliser sur les 8 disponibles 
-	La position de la bague sur le rotor (Ringstellung)
-	Les connecteurs entre les lettres sur la plugboard (Steckerverbindungen)
-	La position initiale de rotors (Grundstellung)
-	Le réflecteur utilisé (Umkehrwalze), B ou C
-	Une clé de chiffrement que l’opérateur choisi au hasard

<u>Le fichier foulard.txt nous aide à trouver ces paramètres :</u>

- « Uniquement les impairs en ordre croissant » fait référence aux rotors à utiliser donc le 1, le 3 et le donne la position des bagues sur les rotors est donné en plaintext : **REJ**
- Les connections entre les lettres sont a trouver dans le message envoyé à Antoine Rossignol pour les challenges préliminaire : « b a :e z ». La plugboard est donc **B-E** et **A-Z**
- La position initiale des rotors est donnée en plaintext : **MER**
- Le réflecteur à utiliser est à deviner dans la lettre **B**, seule partie du message qui se rapportait au réflecteur

A partir de ses informations, on peut commencer à décoder le message.

<u>Arrêtons-nous un instant sur la procédure de chiffrage et déchiffrage de deux opérateurs radio allemands pendant la guerre.</u>

Un opérateur1 reçoit un message à coder et à envoyer. 
Il se réfère aux tables à sa disposition pour avoir le réglage du jour pour les rotors, la position des bagues, les connecteurs de la plugboard et le réflecteur. Il peut choisir librement la position initiale des rotors et la clé du message. 

Seulement il faut que l’operateur2 qui recevra le message puisse utiliser la même clé pour décoder. Cette information était donc transmise en clair au début du message avant les informations codées. Avant 1940, la procédure était de coder deux fois la clé en début de message pour être certain qu’il n’y avait pas eu de perte dues aux interférences lors de la transmission. 

L’opérateur1 choisit donc une position initiale aléatoire, entre 2 fois la clé de 3 lettres, puis change la position initiale pour qu’elle corresponde à la clé puis envoie le message à l’opérateur2.
Le début de message comportait donc les informations (en prenant notre exemple) **MER IVQDQT** puis la suite du message codé.
Dans notre cas, nous connaissons les réglages **MER**, qui sont les réglages choisis, mais il nous manque la clé. En rentrant la sortie du RSA dans Enigma on voit que les 6 premières lettres **IVQDQT** donnent **BFGBFG** ce qui correspond à deux fois la clé d’encodage selon le protocole allemand.

Pour décoder le message, l’opérateur2 décode la clé, prend la clé comme position initiale et décode le message. 
Il faut donc décoder : **NHABMPSVBYYUCJIYMJBRDWXAXP  THYVCROD** avec comme position initiale **BFG** et on obtient le texte : **LESSANGLOTSLONGSDESVIOLONS WJVDLOIT**.
Notre message de flag est donc **LESSANGLOTSLONGSDESVIOLONS**. On reconnaît les trois premiers vers du célèbre poème « Chanson d’automne » de Paul Verlaine qui annonçait la préparation du débarquement allié. 

Le flag : **DGSESIEE{LESSANGLOTSLONGSDESVIOLONS}**

<u>Sources</u>

- Le document expliquant le protocole d’Enigma  : <http://denisjl.be/enigma/codecodage.pdf>

- L’outils RsaCtfTool : <https://github.com/Ganapati/RsaCtfTool>

- Paul Verlaine, « Chanson d’automne », _Poèmes saturniens_ : <https://www.poesie-francaise.fr/paul-verlaine/poeme-chanson-d-automne.php>