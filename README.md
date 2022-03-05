
# Implémentation de TAPS  
  
Le projet est décomposé en quatre fichiers :  
- [taps_getFlows.py]([https://github.com/Vytex0/TAPS/blob/main/taps_getFlows.py](https://github.com/Vytex0/TAPS/blob/main/taps_getFlows.py) "taps_getFlows.py")  
- [taps_getRealAttackers.py]([https://github.com/Vytex0/TAPS/blob/main/taps_getRealAttackers.py](https://github.com/Vytex0/TAPS/blob/main/taps_getRealAttackers.py)"taps_getRealAttackers.py")  
- [taps_calculateAttackers.py]([https://github.com/Vytex0/TAPS/blob/main/taps_calculateAttackers.py](https://github.com/Vytex0/TAPS/blob/main/taps_calculateAttackers.py)"taps_calculateAttackers.py")  
- [taps_getStats.py]([https://github.com/Vytex0/TAPS/blob/main/taps_getStats.py](https://github.com/Vytex0/TAPS/blob/main/taps_getStats.py) "taps_getStats.py")  
  
  
## taps_getFlows.py  
**Utilisation :** ./taps_getFlows.py <input pcap captures.pcap> <output sorted flows.json>  
  
**Type :** Ce script est un **script de préparation**. Une fois le fichier de sortie généré, il n'est plus nécessaire de le lancer à nouveau.  
  
**Variables à configurer :** 

- FLOW_MAX_DURATION_SECONDS : durée maximale en secondes entre 2 paquets d'un même flux
- NB_PACKETS : nombre de paquets dans la capture
  
**Description :** Ce script permet de récupérer tous les flux dans la capture donnée en paramètre. Les flux sont ensuite enregistrés dans un fichier JSON lisible pour les prochains scripts. Les flux déjà générés sont disponible ici : [Liste des flux calculés](https://drive.google.com/drive/folders/1vmYRL6OQ7jASi36vmv6TPWcxhOG6INXS?usp=sharing) (..-tbXX correspond à FLOW_MAX_DURATION_SECONDS = XX)
  
## taps_getRealAttackers.py  
**Utilisation :** ./taps_getRealAttackers.py <input pcap attackers captures.pcap> <output attackers.json>
  
**Type :** Ce script est un **script de préparation**. Une fois le fichier de sortie généré, il n'est plus nécessaire de le lancer à nouveau.  
  
**Variables à configurer :** Aucune
  
**Description :** Ce script permet de récupérer la liste de toutes les IPs du Botnet en format JSON présentes dans la capture PCAP.


  
## taps_calculateAttackers.py
**Utilisation :** ./taps_getRealAttackers.py <sorted flows file.json> <attackers list file.json> <output results.json>
  
**Type :** Ce script est le **script principal**. Il éxecute l'algorithme de TAPS sur les flux précedemment calculés.
  
**Variables à configurer :** 

- TAPS_TIMER_SECONDS : paramètre de TAPS
- TAPS_η1 : paramètre de TAPS
- TAPS_η0 : paramètre de TAPS
- TAPS_θ0 : paramètre de TAPS
- TAPS_θ1 : paramètre de TAPS
- TAPS_k : paramètre de TAPS
  
**Description :** Ce script éxecute l'algorithme de TAPS en prenant en paramètre les flux calculés et la liste des IPs des attaquants. Il retourne un fichier concernant les résultats avec des statistiques.



  
## taps_getStats.py
**Utilisation :** ./taps_getRealAttackers.py <sorted flows file.json> <attackers list file.json>
  
**Type :** Ce script est le **script annexe**. 
  
**Variables à configurer :** Aucune
  
**Description :** Ce script récupère la liste des flux et la liste des attaquants et renvoie des statistiques sur ces deux fichiers.

