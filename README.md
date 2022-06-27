# **PHISHINGDTECTOOL**
---

**Phishingdtectool** est capable de détecter des sites potentiellement malveillants avant qu'une personne soit impactée 😁.

![](https://i.imgur.com/zNAoNhA.gif)


Nous utilisons l'outil d'aggrégation de flux de certificats **Certstream** afin d'analyser le flux en temps réel.

Le programme se base sur un système de scoring selon différents critères.


|    ETAT    |  SCORE   |
|:----------:|:--------:|
| PHISHING | 180 ou + |
| SUSPICIEUX  | 110 à 179 |
|   ATTENTION       |    90 à 109      |
|   VALIDE   |  0 à 89  |



## **INSTALLATION**

Pour installer le projet, faire un git clone :
```
git clone https://github.com/BDEMAY0/PHISHING-DTECTOOL.git
```

Ensuite, installer les bibliothèques requises :

```
pip3 install -r requirements.txt
```

Une fois que tout est installé, lancer le programme, en utilisant les paramètres requis :

![](https://i.imgur.com/vaZi8Tw.png)


Voici un exemple :

```
python3 PHISHINGDTECTOOL.py -bdd ma_superbe_bdd -ip 127.0.0.1
```
