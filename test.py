from scapy.all import *

# conf.ifaces est un dictionnaire où la clé est le GUID/Nom et la valeur est l'objet Interface
interfaces = conf.ifaces
grjer = scapy.interfaces.show_interfaces()

# Pour afficher les GUIDs (Clés) et les Noms/Descriptions (Propriétés de l'objet)
"""print("--- Dictionnaire des interfaces Scapy (conf.ifaces) ---")
for guid, iface_obj in interfaces.items():
    # Sur Windows, 'guid' est souvent le GUID, et iface_obj.name est le nom convivial.
    # iface_obj.description contient souvent aussi le nom du pilote ou la description longue.
    print(f"GUID : {guid.split("_")[1]}")
    print(f"Nom/Description Scapy : {iface_obj.description}")
    print(f"Nom Convivial (Windows) : {iface_obj.name}")
    print("-" * 20)"""

