import get_mac_from_ip
class MainInTheMiddle:
    def __init__(self, cible_1_ip, cible_2_ip, interface):
        self.cible_1 = get_mac_from_ip.Cible(cible_1_ip, interface)
        self.cible_2 = get_mac_from_ip.Cible(cible_2_ip, interface)
        self.interface = interface

    def start_mitm(self):
        pass

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

def ihm() :
    while True :
        print("=================================menu=================================")
        
        cible_1_ip = input("Entrez l'adresse IP de la cible 1 : ")
        cible_2_ip = input("Entrez l'adresse IP de la cible 2 : ")
        interface = input("Entrez le nom de l'interface réseau à utiliser : ")

        if verif_ip(cible_1_ip) and verif_ip(cible_2_ip):
            break
    print("======================================================================")
    mitm = MainInTheMiddle(cible_1_ip, cible_2_ip, interface)
    mitm.start_mitm()
    return mitm

mitm = ihm()
print(mitm.cible_1.mac)
print(mitm.cible_2.mac)
