# GENERATEUR

## INSTALLATION DES DEPENDANCES

Afin d'éxécuter le générateur, il faut installer Python sur son ordinateur. Télécharger et installer la dernière version de l'installeur Windows 64-bits: https://www.python.org/downloads/windows/

Puis éxécuter l'installeur, ce programme installe "pip", le gestionnaire de paquets pour Python, ainsi que la liste des prérequis présents dans le fichier "requirements.txt" : 
`py installer.py`

## PRÉPARATION DU DISQUE

Un script d'installation automatisée peut faire appel à des ressources (dépôts Linux locaux, des fichiers ISO, des pilôtes et autres executables Windows), qui doivent être disponibles lors de son execution. 

Pour éviter toutes erreurs d'éxécutions, le disque dur contenant les scripts d'installations doit respecter l'architecture suivante : 

_
 |
 |_ DEPOTS
 |	|_ ftp.pasteur.fr
 |	|_ mirrors.rit.edu
 |	|_ repo.zabbix.com
 |	|_ repository.veeam.com
 |	|_ ...
 |
 |_ PILOTES
 |	|_ sp112392.exe
 |	|_ ...
 |
 |_ ISO
 |	|_ Master_OS_CentOS_8.iso
 |	|_ Windows_10.iso
 |	|_ Windows_Server_2019.iso
 |	|_ ...
 |
 |_ INSTALLEURS
 |	|_ VCenter_7.0
 |	|_ Veeam_11.0
 |	|_ ...
 |
 |_ GENERATEUR
 	|_ configurations
 		|_ ...


## GÉNÉRATION DES DOSSIERS D'INSTALLATION

Pour générer les dossiers d'installations d'une plateforme, créer un dossier portant le nom de la plateforme, puis y ajouter un fichier de configuration "hosts.json" (il est possible de prendre exemple sur les fichiers de configuration existants) :

_
 |
 |_ GENERATEUR
 	|_ configurations
 		|_ <plateforme>
 			|_ hosts.json

Éxécuter le générateur Python, enter le numéro de la plateforme à générer

> py generateur.py

Les dossiers d'installations sont ajoutés aux côtés du fichier de configuration

_
 |
 |_ GENERATEUR
 	|_ configurations
 		|_ <plateforme>
 			|_ hosts.json