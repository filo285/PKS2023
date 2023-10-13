from scapy.all import rdpcap
from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString
import argparse


class Node:
    def __init__(self, key, n, c):
        self.key = key
        self.number_of_sent_packets = n
        self.child = c


class TCP:
    def __init__(self, port1, port2, ip1, ip2):
        self.port = [port1, port2]
        self.ip = [ip1, ip2]
        self.packets = []
        self.comm = []
        self.complete = False


class ARP:
    def __init__(self, ip):
        self.packet = []
        self.ip = ip
        self.packets = []
        self.bytes = []
        self.complete = False


class TFTP:
    def __init__(self,ip1, ip2):
        self.packet = []
        self.ip = [ip1,ip2]
        self.complete = False

class ICMP:
    def __init__(self, source_ip, destination_ip, idntf, sc):
        self.packets = []
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.identifier = idntf
        self.complete = False
        self.sequence = sc


def read_int(current_packet):
    return int.from_bytes(current_packet, "big")


def create_file(output_file, file_name, ip_data, max_packets, filt):
    file = {}
    file["name"] = "PKS2023/24"
    file["pcap_name"] = file_name
    file["filter"] = filt
    file["packets"] = output_file
    file["ipv4_senders"] = ip_data
    file["max_send_packets_by"] = max_packets

    with open("data.yaml", "w") as file_output:
        yaml = YAML()
        yaml.dump(file, file_output)


def dst_mac(packet_local):
    mac_dst = ""
    for i in range(6):
        mac_dst += (str(format(packet_local[i], '02x')))
        if i != 5:
            mac_dst += ":"
    return mac_dst


def src_mac(packet_local):
    mac_src = ""
    for i in range(6):
        mac_src += str(format(packet_local[i + 6], '02x'))
        if i != 5:
            mac_src += ":"
    return mac_src


def src_ip(packet_local):
    ip = ""
    for byte in packet_local:
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


def dst_ip(packet_local):
    ip = ""
    for byte in packet_local:
        ip = ip + str(byte)
        ip += '.'
    ip = ip[:-1]
    return ip


def IEEEdetector(packet_local, data_local):
    if format(packet_local[15], '02x') == 'aa':
        data_local.update(frame_type="IEEE 802.3 LLC & SNAP")
        data_local.update(destination_mac=dst_mac(packet_local))
        data_local.update(source_mac=src_mac(packet_local))
        ProtocolID(packet_local, data_local)
    elif format(packet_local[16], '02x') == '03':
        data_local.update(frame_type="IEEE 802.3 LLC")
        data_local.update(destination_mac=dst_mac(packet_local))
        data_local.update(source_mac=src_mac(packet_local))
        ProtocolID(packet_local, data_local)
    else:
        data_local.update(frame_type="IEEE 802.3 RAW")


def ProtocolID(packet_local, data_local):
    if packet_local[20:22] == b'\x20\x00':
        data_local.update(pid='CDP')
    elif packet_local[20:22] == b'\x20\x04':
        data_local.update(pid='DTP')
    elif packet_local[12:].__contains__(b'\xff\xff'):
        data_local.update(sap='IPX')
    elif packet_local[14:17] == b'\xaa\xaa\x03' and packet_local[17:19] == b'\x80\x9b':
        data_local.update(pid='AppleTalk')
    elif packet_local[14:16] == b'\xf0\xf0':
        data_local.update(sap='NetBIOS')
    else:
        data_local.update(sap='STP')
        if packet_local[21:23] == b'\x01\x0b':
            data_local.update(pid='PVST+')


def app_protocol(packet_local, data_local):
    s = read_int(packet_local[34:36])
    d = read_int(packet_local[36:38])
    data_local.update(app_protocol=[])
    with open("ip_protocol_file.txt", "r") as fl:
        line_local = fl.readline()
        while line_local:
            line_local = line_local.strip()
            split_line_local = line_local.split(':')
            if s == int(split_line_local[0]) or d == int(split_line_local[0]):
                data_local['app_protocol'].append(split_line_local[1])
            line_local = fl.readline()
    if data_local['app_protocol'].__len__() ==  0:
        del data_local['app_protocol']


def ip_statistic():
    if ip_sent:
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


def completion_test():
    for COMMUNICATION in tcp_communications:
        open_array = [False, False, False, False]
        close_array = [False, False, False, False]
        for byte in COMMUNICATION.comm:
            if open_array[0] == False and byte[47] == 2:
                open_array[0] = True
            elif open_array[1] == False and open_array[2] == False and byte[47] == 18:
                open_array[1] = True
                open_array[2] = True
            elif open_array[3] == False and byte[47] == 16:
                open_array[3] = True
            if False not in open_array:
                if close_array[0] == False and (byte[47] == 25 or byte[47] == 17):
                    close_array[0] = True
                elif close_array[0] == True and close_array[1] == False and byte[47] == 16:
                    close_array[1] = True
                elif close_array[0] == True and close_array[1] == True and close_array[2] == False and (
                        byte[47] == 25 or byte[47] == 17):
                    close_array[2] = True
                elif close_array[0] == True and close_array[1] == True and close_array[2] == True and close_array[3] == False and byte[47] == 16:
                    close_array[3] = True
                elif True not in close_array and (byte[47] == 20 or byte[47] == 4):
                    close_array[0] = True
                    close_array[1] = True
                    close_array[2] = True
                    close_array[3] = True
        if False not in open_array and False not in close_array:
            COMMUNICATION.complete = True


def tftp_completion_test():
    for comm in tftp_communications:
        length = 558
        tmp = 1
        for p in comm.packet:
            if p['src_ip'] == comm.ip[1] and p['dst_ip'] == comm.ip[0]:
                if p['len_frame_pcap'] < length:
                    if comm.packet[tmp] == comm.packet[-1]:
                        comm.complete = True
            tmp += 1

def icmp_completion_test():
    for comm_local in icmp_communications:
        arr = [False,False]
        for packet_local in comm_local.packets:
            if packet_local['type'] == 'request':
                arr[0] = True
            elif packet_local['type'] == 'reply':
                arr[1] = True
        if False not in arr:
            comm_local.complete = True



def analyze(packet_local, frame_number_local):
    data = {}
    data.update(frame_number=frame_number_local)

    if len(packet_local) < 64:
        data.update(len_frame_pcap=60)
        data.update(len_frame_medium=64)
    else:
        data.update(len_frame_pcap=len(packet_local))
        data.update(len_frame_medium=len(packet_local) + 4)

    ether_t = read_int(packet_local[12:14])
    if ether_t >= 1500:

        data.update(frame_type="Ethernet II")

        data.update(dst_mac=dst_mac(packet_local))
        data.update(src_mac=src_mac(packet_local))

        with open("ether-type_values.txt", "r") as eth:
            eth_line = eth.readline()
            while eth_line:
                eth_line = eth_line.strip()
                split_eth_line = eth_line.split(':')
                if ether_t == int(split_eth_line[0]):
                    data.update(ether_type=split_eth_line[1])
                    if split_eth_line[1] == 'ARP':
                        data.update(src_ip=src_ip(packet_local[28:32]))
                        data.update(dst_ip=dst_ip(packet_local[38:42]))
                    else:
                        data.update(src_ip=src_ip(packet_local[26:30]))
                        data.update(dst_ip=dst_ip(packet_local[30:34]))
                    if split_eth_line[1] == "IPv4":
                        with open("ipv4_protocol.txt", "r") as ipv4_file:
                            ipv4_line = ipv4_file.readline()
                            IHL = packet_local[14] & 0x0F
                            IHL = IHL * 4
                            protocol_nmb = packet_local[IHL + 3]
                            while ipv4_line:
                                ipv4_line = ipv4_line.strip()
                                split_ipv4_line = ipv4_line.split(':')
                                if protocol_nmb == int(split_ipv4_line[0]):
                                    data.update(protocol=split_ipv4_line[1])
                                    if protocol_nmb == 6 or protocol_nmb == 17:
                                        data.update(src_port=read_int(packet_local[34:36]))
                                        data.update(dst_port=read_int(packet_local[36:38]))
                                        app_protocol(packet_local, data)
                                        break
                                    break
                                ipv4_line = ipv4_file.readline()
                    break
                eth_line = eth.readline()

        hex_dmp = hex_dump(packet_local)
        hex_dump1 = LiteralScalarString(hex_dmp)
        data.update(hexa_frame=hex_dump1)

    elif ether_t < 1500:
        IEEEdetector(packet_local, data)
        hex_dmp = hex_dump(packet_local)
        hex_dump1 = LiteralScalarString(hex_dmp)
        data.update(hexa_frame=hex_dump1)

    return data


ip_senders = []
ip_sent = []
len_frame_pcap = 0
len_frame_medium = 0
data = {}
ipv4_output = []
max_packets_sent = []
args_parser = argparse.ArgumentParser()
args_parser.add_argument('-p', '--protocol', default="ICMP")

protocols = []

args = args_parser.parse_args()

pcap_name = "trace-6.pcap"
pcap_file = rdpcap(pcap_name)

pcap_file_in_bytes = []

frame_number = 1

comm_number = 0

for packet in pcap_file:
    pcap_file_in_bytes.append(bytes(packet))

supported_protocols = []
supported_protocols_nmb = []
with open("supported_protocols.txt", "r") as f:
    line = f.readline()
    while line:
        if line.__contains__(':'):
            line = line.strip()
            split_line = line.split(':')
            supported_protocols_nmb.append(split_line[0])
            supported_protocols.append(split_line[1])
        line = f.readline()
analyzed_packets = []
for packet in pcap_file_in_bytes:
    analyzed_packets.append(analyze(packet, frame_number))
    frame_number += 1


prev_packet = None

if args.protocol == "ARP":
    arp_communication = []
    incomplete_communication_request = [{'incomplete_communication': 'request'}]
    incomplete_communication_reply = [{'incomplete_communication': 'reply'}]
    for packet in analyzed_packets:
        if packet.__contains__('ether_type') and packet['ether_type'] == "ARP":
            if read_int(pcap_file_in_bytes[packet['frame_number']-1][20:22]) == 1:
                in_array = 0
                for arp in arp_communication:
                    if arp.ip == packet['dst_ip']:
                        arp.packets.append(packet)
                        in_array = 1
                if in_array == 0:
                    arp_communication.append(ARP(packet['dst_ip']))
                    arp_communication[-1].packets.append(packet)
            elif read_int(pcap_file_in_bytes[packet['frame_number']-1][20:22]) == 2:
                in_array = 0
                for arp in arp_communication:
                    if arp.ip == packet['src_ip']:
                        packet.update(ip_to_mac=(packet['src_ip'],packet['src_mac']))
                        arp.packets.append(packet)
                        arp.complete = True
                        in_array = 1
                if in_array == 0:
                    packet.update(ip_to_mac=(packet['src_ip'], packet['src_mac']))
                    incomplete_communication_reply.append(packet)
    output = []
    cmn = 1
    for communication in arp_communication:
        if communication.complete:
            data = {'communication number': cmn}
            output.append(data)
            output.append(communication.packets)
            cmn += 1
        else:
            incomplete_communication_request.append(communication.packets)
    if incomplete_communication_request.__len__()== 1 and incomplete_communication_reply.__len__()==1:
        create_file(output, pcap_name, ipv4_output, max_packets_sent, args.protocol)
    elif incomplete_communication_reply.__len__()==1:
        output+=incomplete_communication_request
        create_file(output, pcap_name, ipv4_output, max_packets_sent, args.protocol)
    elif incomplete_communication_request.__len__()==1:
        output+=incomplete_communication_reply
        create_file(output, pcap_name, ipv4_output, max_packets_sent, args.protocol)
    ip_statistic()
    create_file(output, pcap_name, ipv4_output, max_packets_sent, args.protocol)

elif args.protocol in supported_protocols:
    tcp_communications = []
    pindex = supported_protocols.index(args.protocol)
    protocol_number = int(supported_protocols_nmb[pindex])
    frame_number = 0

    for packet in analyzed_packets:
        frame_number += 1
        if read_int(pcap_file_in_bytes[frame_number - 1][12:14]) == 2048:
            ihl = pcap_file_in_bytes[frame_number - 1][14] & 0x0F
            ihl = ihl * 4
            protocol_nmb = pcap_file_in_bytes[frame_number - 1][ihl + 3]
            if protocol_nmb == 6:
                if packet["src_port"] == protocol_number or packet["dst_port"] == protocol_number:
                    in_array = 0
                    for acomm in tcp_communications:
                        if packet["src_port"] in acomm.port and packet["dst_port"] in acomm.port and packet["src_ip"] in acomm.ip and packet["dst_ip"] in acomm.ip:
                            acomm.comm.append(pcap_file_in_bytes[frame_number - 1])
                            acomm.packets.append(packet)
                            in_array = 1
                    if in_array == 0:
                        tcp_communications.append(
                            TCP(packet["src_port"], packet["dst_port"], packet["src_ip"], packet["dst_ip"]))
                        tcp_communications[comm_number].comm.append(pcap_file_in_bytes[frame_number - 1])
                        tcp_communications[comm_number].packets.append(packet)
                        comm_number += 1
    completion_test()
    output = []
    cmn = 1
    check = False
    for communication in tcp_communications:
        if communication.complete:
            data = {'communication number': cmn}
            output.append(data)
            output.append(communication.packets)
            cmn += 1
        elif not check:
            data = {'incomplete_communication': 1}
            output.append(data)
            output.append(communication.packets)
            check = True
    ip_statistic()
    create_file(output, pcap_name, ipv4_output, max_packets_sent, args.protocol)

elif args.protocol == "TFTP":
    tftp_communications = []
    frame_number = 0

    for packet in analyzed_packets:
        frame_number += 1
        if read_int(pcap_file_in_bytes[frame_number - 1][12:14]) == 2048:
            ihl = pcap_file_in_bytes[frame_number - 1][14] & 0x0F
            ihl = ihl * 4
            protocol_nmb = pcap_file_in_bytes[frame_number - 1][ihl + 3]
            if protocol_nmb == 17:
                if packet["dst_port"] == 69:
                    in_array = 0
                    for comm in tftp_communications:
                        if packet['dst_ip'] in comm.ip and packet['src_ip'] in comm.ip:
                            in_array = 1
                    if in_array == 0:
                        tftp_communications.append(TFTP(packet['src_ip'],packet['dst_ip']))
                        tftp_communications[-1].packet.append(packet)
                else:
                    for acomm in tftp_communications:
                        if packet['src_ip'] in acomm.ip and packet['dst_ip'] in acomm.ip:
                            acomm.packet.append(packet)
    tftp_completion_test()
    output = []
    cmn = 1
    for communication in tftp_communications:
        if communication.complete:
            data = {'communication number': cmn}
            output.append(data)
            output.append(communication.packet)
            cmn += 1
    ip_statistic()
    create_file(output, pcap_name, ipv4_output, max_packets_sent, args.protocol)
elif args.protocol == "ICMP":
    icmp_communications = []
    frame_number = 0

    for packet in analyzed_packets:
        if read_int(pcap_file_in_bytes[frame_number - 1][12:14]) == 2048:
            ihl = pcap_file_in_bytes[frame_number - 1][14] & 0x0F
            ihl = ihl * 4
            protocol_nmb = pcap_file_in_bytes[frame_number][ihl + 3]
            if packet['protocol'] == "ICMP":
                if pcap_file_in_bytes[frame_number][34] == 8:
                    in_array = 0
                    for acomm in icmp_communications:
                        if packet['dst_ip'] == acomm.destination_ip and packet['src_ip'] == acomm.source_ip and read_int(pcap_file_in_bytes[frame_number][38:40]) == acomm.identifier:
                            packet.update(type='request')
                            acomm.packets.append(packet)
                            in_array = 1
                    if in_array == 0:

                        icmp_communications.append(ICMP(packet['src_ip'], packet['dst_ip'], read_int(pcap_file_in_bytes[frame_number][38:40]),read_int(pcap_file_in_bytes[frame_number][40:42])))
                        packet.update(type='request')
                        icmp_communications[-1].packets.append(packet)
                elif pcap_file_in_bytes[frame_number][34] == 0:
                    in_array = 0
                    for comm in icmp_communications:

                        if packet['src_ip'] == comm.destination_ip and packet['dst_ip'] == comm.source_ip and read_int(pcap_file_in_bytes[frame_number][38:40]) == comm.identifier:
                            packet.update(type='reply')
                            comm.packets.append(packet)
                            in_array = 1
                    if in_array == 0:
                        icmp_communications.append(ICMP(packet['src_ip'], packet['dst_ip'], read_int(pcap_file_in_bytes[frame_number][38:40]),read_int(pcap_file_in_bytes[frame_number][40:42])))
                elif pcap_file_in_bytes[frame_number][34] == 11:
                    in_array = 0
                    for comm in icmp_communications:
                        if packet['src_ip'] == comm.destination_ip and packet['dst_ip'] == comm.source_ip and read_int(pcap_file_in_bytes[frame_number][38:40]) == comm.identifier:
                            packet.update(type='time exceeded')
                            comm.packets.append(packet)
                            in_array = 1
                    if in_array == 0:
                        icmp_communications.append(ICMP(packet['src_ip'], packet['dst_ip'], read_int(pcap_file_in_bytes[frame_number][38:40]), read_int(pcap_file_in_bytes[frame_number][40:42])))
                        packet.update(type='time exceeded')
                        icmp_communications[-1].packets.append(packet)
        frame_number += 1





    icmp_completion_test()
    output = []
    incomplete_communication = [{'incomplete_communication': 1}]
    cmn = 1
    for communication in icmp_communications:
        if communication.complete:
            data = {'communication number': cmn, 'identifier': communication.identifier, 'sequence': communication.sequence}
            output.append(data)
            output.append(communication.packets)
            cmn += 1
        else:
            incomplete_communication.append(communication.packets)
    ip_statistic()
    output += incomplete_communication
    create_file(output, pcap_name, ipv4_output, max_packets_sent, args.protocol)



else:
    output = []
    for packet in pcap_file_in_bytes:
        data = {}
        frame_number += 1
        output.append(analyze(packet, frame_number))
    create_file(output, pcap_name, ipv4_output, max_packets_sent, args.protocol)
