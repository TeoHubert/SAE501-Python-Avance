import scapy
from scapy.all import Ether, ARP, srp1


class Cible :
    def __init__(self, ip, interface, mac=None):
        self.ip = ip
        self.interface = interface
        self.mac = mac if mac else self.get_mac_from_ip(ip, interface)


    def get_mac_from_ip(self, ip, interface):
        p = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
        reponse = srp1(p, iface=interface)
        if reponse:
            return reponse.hwsrc
        else:
            return None

