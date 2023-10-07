from scapy.all import rdpcap
from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString


class Node:
    def __init__(self, key, n, c):
        self.key = key
        self.number_of_sent_packets = n
        self.child = c


def read_int(current_packet):
    return int.from_bytes(current_packet, "big")


def create_file(output, file_name, ip_data, max_packets):
    file = {}
    file["name"] = "PKS2023/24"
    file["pcap_name"] = file_name
    file["packets"] = output
    file["ipv4_senders"] = ip_data
    file["max_send_packets_by"] = max_packets

    with open("data.yaml", "w") as f:
        yaml = YAML()
        yaml.dump(file, f)


def dst_mac(packet):
    mac_dst = ""
    for i in range(6):
        mac_dst += (str(format(packet[i], '02x')))
        if i != 5:
            mac_dst += ":"
    return mac_dst


def src_mac(packet):
    mac_src = ""
    for i in range(6):
        mac_src += str(format(packet[i + 6], '02x'))
        if i != 5:
            mac_src += ":"
    return mac_src


def src_ip(packet):
    ip = ""
    for byte in packet:
        ip = ip + str(byte)
        ip += '.'
    ip = ip[:-1]
    if ip not in ip_senders:
        ip_senders.append(ip)
        ip_sent.append(1)
    else:
        pos = ip_senders.index(ip)
        ip_sent[pos] += 1
    return ip


def dst_ip(packet):
    ip = ""
    for byte in packet:
        ip = ip + str(byte)
        ip += '.'
    ip = ip[:-1]
    return ip


def IEEEdetector(packet):
    if format(packet[15], '02x') == 'aa':
        data.update(frame_type="IEEE 802.3 LLC & SNAP")
        data.update(destination_mac=dst_mac(packet))
        data.update(source_mac=src_mac(packet))
        ProtocolID(packet)
    elif format(packet[16], '02x') == '03':
        data.update(frame_type="IEEE 802.3 LLC")
        data.update(destination_mac=dst_mac(packet))
        data.update(source_mac=src_mac(packet))
        ProtocolID(packet)
    else:
        data.update(frame_type="IEEE 802.3 RAW")


def ProtocolID(packet):
    if packet[20:22] == b'\x20\x00':
        data.update(pid='CDP')
    elif packet[20:22] == b'\x20\x04':
        data.update(pid='DTP')
    elif packet[12:].__contains__(b'\xff\xff'):
        data.update(sap='IPX')
    elif packet[14:17] == b'\xaa\xaa\x03' and packet[17:19] == b'\x80\x9b':
        data.update(pid='AppleTalk')
    elif packet[14:16] == b'\xf0\xf0':
        data.update(sap='NetBIOS')
    else:
        data.update(sap='STP')
        if packet[21:23] == b'\x01\x0b':
            data.update(pid='PVST+')


def app_protocol(packet):
    s = read_int(packet[34:36])
    d = read_int(packet[36:38])
    with open("ip_protocol_file.txt","r") as fl:
        line = fl.readline()
        while line:
            line = line.strip()
            split_line = line.split(':')
            if s == int(split_line[0]) or d == int(split_line[0]):
                data.update(app_protocol=split_line[1])
            line = fl.readline()




def ip_statistic():
    maxi = max(ip_sent)
    for i in range(len(ip_senders)):
        ipv4_data = {}
        ipv4_data.update(node=ip_senders[i])
        ipv4_data.update(number_of_sent_packets=ip_sent[i])
        ipv4_output.append(ipv4_data)
        if ip_sent[i] == maxi:
            max_packets_sent.append(ip_senders[i])

def hex_dump(packet1):
    hex_d = ""
    i = 1
    for byte in packet1:
        if i == 17:
            hex_d += "\n"
            i = 1
        hex_d += (format(byte, "02x"))
        if i != 16:
            hex_d += " "
        i = i + 1
    if hex_d.endswith(" "):
        hex_d = hex_d[:-1]
    hex_d += "\n"
    return hex_d


pcap_name = 'eth-3.pcap'
pcap_file = rdpcap(pcap_name)

pcap_file_in_bytes = []
ip_senders = []
ip_sent = []

frame_number = 0
len_frame_pcap = 0
len_frame_medium = 0

for packet in pcap_file:
    pcap_file_in_bytes.append(bytes(packet))


ipv4_output = []
max_packets_sent = []

output = []

for packet in pcap_file_in_bytes:
    frame_number = frame_number + 1
    data = {'frame_number': frame_number}

    if len(packet) < 64:
        data.update(len_frame_pcap=60)
        data.update(len_frame_medium=64)
    else:
        data.update(len_frame_pcap=len(packet))
        data.update(len_frame_medium=len(packet) + 4)

    ether_t = read_int(packet[12:14])
    if ether_t >= 1500:

        data.update(frame_type="Ethernet II")

        data.update(dst_mac=dst_mac(packet))
        data.update(src_mac=src_mac(packet))

        with open("ether-type_values.txt","r") as eth:
            eth_line = eth.readline()
            while eth_line:
                eth_line = eth_line.strip()
                split_eth_line = eth_line.split(':')
                if ether_t == int(split_eth_line[0]):
                    data.update(ether_type=split_eth_line[1])
                    data.update(src_ip=src_ip(packet[26:30]))
                    data.update(dst_ip=dst_ip(packet[30:34]))
                    if split_eth_line[1] == "IPv4":
                        with open("ipv4_protocol.txt","r") as ipv4_file:
                            ipv4_line = ipv4_file.readline()
                            protocol_nmb = packet[23]
                            while ipv4_line:
                                ipv4_line = ipv4_line.strip()
                                split_ipv4_line = ipv4_line.split(':')
                                if protocol_nmb == int(split_ipv4_line[0]):
                                    data.update(protocol=split_ipv4_line[1])
                                    if protocol_nmb == 6 or protocol_nmb == 17:
                                        data.update(src_port=read_int(packet[34:36]))
                                        data.update(dst_port=read_int(packet[36:38]))
                                        app_protocol(packet)
                                        break
                                    break
                                ipv4_line = ipv4_file.readline()
                    break
                eth_line = eth.readline()

        hex_dmp = hex_dump(packet)
        hex_dump1 = LiteralScalarString(hex_dmp)
        data.update(hexa_frame=hex_dump1)

    elif ether_t < 1500:
        IEEEdetector(packet)
        if len(packet) < 64:
            data.update(len_frame_pcap=60)
            data.update(len_frame_medium=64)
        else:
            data.update(len_frame_pcap=len(packet))
            data.update(len_frame_medium=len(packet) + 4)

        hex_dmp = hex_dump(packet)
        hex_dump1 = LiteralScalarString(hex_dmp)
        data.update(hexa_frame=hex_dump1)

    output.append(data)

ip_statistic()

create_file(output, pcap_name, ipv4_output, max_packets_sent)
