from scapy.all import IP, TCP, UDP

def remove_checksum(packet):
    try:
        if TCP in packet:
            del packet[TCP].chksum
        elif IP in packet:
            del packet[IP].chksum
        elif UDP in packet:
            del packet[UDP].chksum
        else:
            del packet.chksum
        return packet 
    except Exception as e:
        print(f"Error removing checksum: {e}")
        return packet


#p = IP(dst="10.41.31.254")/TCP()

#print(remove_checksum(IP(bytes(p))).chksum)
