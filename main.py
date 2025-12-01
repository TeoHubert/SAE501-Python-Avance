import scapy 
from scapy.all import *
import time
import asyncio
import threading

class NetworkFlowMonitor:
    def __init__(self):
        self.list_packet = []
        self.interface = ""
        self.thread = None

    def list_interface(self):
        noms_interfaces = list(scapy.interfaces.get_if_list()) #scapy.interfaces.show_interfaces() BCP mieux
        num_interface = 0
        self.interface = noms_interfaces[4]
        """Pour connaitre le lien entre le nom de l'interface et l'UID sur Windows :
        Get-NetAdapter | Select-Object Name, InterfaceDescription, InterfaceGuid """
        print("Interface réseau disponible :")
        for interfaces in noms_interfaces:
            print(f"{num_interface}: {interfaces.split('_')[1] if '_' in interfaces else interfaces}")
            num_interface += 1
        print(f"Démarrage de la surveillance pour l'interface : {self.interface}")

    def packet_callback(self, packet):
        #print(packet.summary())
        self.list_packet.append(packet)

    def sniffer_thread(self):
        try:
            sniff(iface=self.interface, prn=self.packet_callback,store=False)
        except Exception as e:
            # Cette ligne va capturer et imprimer le message d'erreur exact.
            print(f"\n {type(e).__name__} - {e}", file=sys.stderr)
            # Quitter le thread
            return

    def start_sniffing(self):
        self.thread = threading.Thread(target=self.sniffer_thread, daemon=True)
        self.thread.start()
        while True:
            time.sleep(3)
            tableau = self.stats()
            print("Nombre de paquets : " + str(len(self.list_packet)))
            for protocole in ["TCP", "UDP","ICMP", "Autre"]:
                data = tableau[protocole]
                packets = data['packets']
                octet_count = data['octet']
                
                # Format d'affichage identique à l'image
                print(f"  {protocole:<5}: {packets:>5} paquets ({octet_count:>6} octet)")

    def stats(self):
        tableau = {
            "TCP": {"packets": 0, "octet": 0},
            "UDP": {"packets": 0, "octet": 0},
            "ICMP": {"packets": 0, "octet": 0},
            "Autre": {"packets": 0, "octet": 0}
        }

        for packet in self.list_packet:

            packet_size = len(packet)

            if scapy.all.TCP in packet:
                key = "TCP"
            elif scapy.all.UDP in packet:
                key = "UDP"
            elif scapy.all.ICMP in packet:
                key = "ICMP"
            else:
                key = "Autre"
            
            # Mise à jour des compteurs
            tableau[key]["packets"] += 1
            tableau[key]["octet"] += packet_size
            
        return tableau



sniffer = NetworkFlowMonitor()
sniffer.list_interface()
sniffer.start_sniffing()
#sniffer.start_sniffing(r"\Device\NPF_{783DD499-BDAA-4A36-ABE0-34419FCA2678}")