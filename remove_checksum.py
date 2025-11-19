from scapy.all import IP, TCP, UDP

def remove_checksum(packet):
    # print(f"check sum du packet : {IP(bytes(packet)).chksum}")
    if TCP in packet:
        del packet[TCP].chksum
    elif IP in packet:
        del packet[IP].chksum
    elif UDP in packet:
        del packet[UDP].chksum
    else:
        del packet.chksum 
    return packet


#p = IP(dst="10.41.31.254")/TCP()

#print(remove_checksum(IP(bytes(p))).chksum)
