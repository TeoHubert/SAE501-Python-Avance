from scapy.all import IP, TCP

def remove_checksum(packet):
    # print(f"check sum du packet : {IP(bytes(packet)).chksum}")
    del packet.chksum 
    return packet


#p = IP(dst="10.41.31.254")/TCP()

#print(remove_checksum(IP(bytes(p))).chksum)
