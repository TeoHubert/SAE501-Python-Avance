import scapy
from scapy.all import Ether, ARP, srp1, get_if_addr, get_if_hwaddr

class Cible:
    def __init__(self, ip, interface, mac=None):
        """Initialise une cible avec son adresse IP, son interface réseau et son adresse MAC (optionnelle). Si l'adresse MAC n'est pas fournie, elle est récupérée via une requête ARP."""
        self.ip = ip
        self.interface = interface
        self.mac = mac if mac else self.get_mac_from_ip(ip, interface)

    def get_mac_from_ip(self, ip, interface):
        """Récupère l'adresse MAC associée à une adresse IP donnée en envoyant une requête ARP sur l'interface spécifiée."""
        hwsrc = get_if_hwaddr(interface)
        ipsrc = get_if_addr(interface)
        p = Ether(dst="ff:ff:ff:ff:ff:ff", src=hwsrc) / ARP(op=1, hwsrc=hwsrc, psrc=ipsrc, pdst=ip)
        reponse = srp1(p, iface=interface, timeout=5, verbose=False)
        if reponse:
            return reponse.hwsrc
        else:
            return None

