import scapy 
from scapy.all import *
import time

class NetworkFlowMonitor:
    def __init__(self):
        self.list_packet = []

    def list_interface(self):
        noms_interfaces = list(scapy.interfaces.get_if_list()) #scapy.interfaces.show_interfaces() BCP mieux
        num_interface = 0
        int_wifi = noms_interfaces[5]
        """Pour connaitre le lien entre le nom de l'interface et l'UID sur Windows :
        Get-NetAdapter | Select-Object Name, InterfaceDescription, InterfaceGuid, Status """
        print("Interface réseau disponible :")
        for interface in noms_interfaces:
            print(f"{num_interface}: {interface.split("_")[1]}")
            num_interface += 1
        print(f"Démarrage de la surveillance pour l'interface : {int_wifi}")
        self.start_sniffing(int_wifi)

    def packet_callback(self, packet):
        self.list_packet.append(packet)

    def start_sniffing(self,interface):
        print("Appuyer Ctrl+C pour arrêter")
        start_time = time.time()
        capture = sniff(iface=interface, prn=self.packet_callback, store=True,count=20)
        end_time = time.time()
        full_time = end_time - start_time
        print(f"Durée : {full_time} secondes")
        #wrpcap("sessions_sniffer.pcap", capture)

sniffer = NetworkFlowMonitor()
sniffer.list_interface()
#sniffer.start_sniffing(r"\Device\NPF_{783DD499-BDAA-4A36-ABE0-34419FCA2678}")