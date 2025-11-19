import scapy 
from scapy.all import *

class NetworkFlowMonitor:
    def __init__(self):
        pass

    def list_interface(self):
        noms_interfaces = list(scapy.interfaces.get_if_list()) #scapy.interfaces.show_interfaces() BCP mieux
        nm_interface = 0
        """Pour connaitre le lien entre le nom de l'interface et l'UID sur Windows :
        Get-NetAdapter | Select-Object Name, InterfaceDescription, InterfaceGuid, Status """
        print("Interface réseau disponible :")
        for interface in noms_interfaces:
            print(f"{nm_interface}: {interface.split("_")[1]}")
            nm_interface += 1
        print("Interface par défaut")
        self.start_sniffing("Microsoft Wi-Fi Direct Virtual Adapter")

    def packet_callback(self, packet):
        print(packet.summary())

    def start_sniffing(self,interface):
        capture = sniff(iface=interface, prn=self.packet_callback, store=False)
        print("FIN")
        #scapy.wrpcap("sessions_sniffer.pcap", capture)

sniffer = NetworkFlowMonitor()
sniffer.list_interface()