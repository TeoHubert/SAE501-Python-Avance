import scapy 
from scapy.all import *
import time
import threading

class NetworkFlowMonitor:
    def __init__(self):
        self.list_packet = []
        self.interface = ""
        self.thread = None

    def list_interface(self):
        liste_interface = []
        noms_interfaces = list(scapy.interfaces.get_if_list()) #scapy.interfaces.show_interfaces() BCP mieux
        num_interface = 0
        self.interface = noms_interfaces[4]
        """Pour connaitre le lien entre le nom de l'interface et l'UID sur Windows :
        Get-NetAdapter | Select-Object Name, InterfaceGuid """
        print("Interfaces réseaux disponibles :")
        for interfaces in noms_interfaces:
            print(f"{num_interface}: {interfaces.split('_')[1] if '_' in interfaces else interfaces}")
            liste_interface.append(interfaces)
            num_interface += 1
        interface_voulu = input(f"Quelle interface voulez vous surveiller ? (Par défaut : {self.interface}) : ")
        if interface_voulu != "":
            try:
                self.interface = liste_interface[int(interface_voulu)]
                print(f"Interface sélectionnée : {self.interface} ")
            except ValueError:
                print("Tu as écrit n'importe quoi")
                print(f"Interface par défaut : {self.interface} ")
        

    def packet_callback(self, packet):
        self.list_packet.append(packet)

    def sniffer_thread(self):
        try:
            sniff(iface=self.interface, prn=self.packet_callback,store=False)
        except Exception as e:
            print(f"\n {type(e).__name__} - {e}", file=sys.stderr)
            return

    def start_sniffing(self):
        self.thread = threading.Thread(target=self.sniffer_thread, daemon=True)
        self.thread.start()
        try:
            time_affiche = int(input("Quelle intervalle de temps voulez-vous (en s) ? "))
        except ValueError:
            print("Valeur non autorisé")
            time_affiche = 5
        print(f'Affichage des statistics toutes les {time_affiche} secondes')
        while True:
            time.sleep(int(time_affiche))
            tableau = self.stats()
            print("Nombre de paquets : " + str(len(self.list_packet)))
            for protocole in ["TCP", "UDP","ICMP", "Autre"]:
                data = tableau[protocole]
                packets = data['packets']
                octet = data['octet']
                print(f"{protocole}: {packets} paquets ({octet} octet)")
            print("\n=======================\n")

    def stats(self):
        tableau = {"TCP": {"packets": 0, "octet": 0},
                "UDP": {"packets": 0, "octet": 0},
                "ICMP": {"packets": 0, "octet": 0},
                "Autre": {"packets": 0, "octet": 0}}
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
            tableau[key]["packets"] += 1
            tableau[key]["octet"] += packet_size
        return tableau



sniffer = NetworkFlowMonitor()
sniffer.list_interface()
sniffer.start_sniffing()
#sniffer.start_sniffing(r"\Device\NPF_{783DD499-BDAA-4A36-ABE0-34419FCA2678}")