import socket
import struct

def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s", data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x" + ethernet_header[12].hex()

    print("=========ethernet_header=========")
    print("src_mac_address :", ether_src)
    print("dest_mac_address :", ether_dest)
    print("ip_version :", ip_header)

def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr = ":".join(ethernet_addr)
    return ethernet_addr

def parsing_ip_header(data):
    ip_header = struct.unpack("!1b1b2s2s2s1s1s2s4c4c", data)
    ip_version = ip_header[0] >> 4
    ip_Length = ip_header[0] & 15 #1b
    differentiated_Services_Codepoint = ip_header[1] >> 2
    explicit_Congestion_Notification = ip_header[1] & 3 #1b
    total_Length = int(ip_header[2].hex(), 16) #2s
    identification = int(ip_header[3].hex(), 16) #2s
    flags = "0x" + ip_header[4].hex() #2s
    flags_to_int = int(flags, 16)
    reserved_bit = flags_to_int >> 15
    not_fragment = (flags_to_int >> 14) & 1
    more_fragments = (flags_to_int >> 13) & 1
    fragment_offset = flags_to_int & 8191
    time_to_live = int(ip_header[5].hex(), 16)
    protocol = int(ip_header[6].hex(), 16)
    header_checksum = "0x" + ip_header[7].hex()
    source_ip_address = convert_ip_address(ip_header[8:12])
    destination_ip_address = convert_ip_address(ip_header[12:16])

    print("=========ip_header=========")
    print("ip_version :", ip_version)
    print("ip_Length :", ip_Length)
    print("Differentiated_Services_Codepoint :", differentiated_Services_Codepoint)
    print("Explicit_Congestion_Notification :", explicit_Congestion_Notification)
    print("Total_Length :", total_Length)
    print("Identification :", identification)
    print("Flags :", flags)
    print(">>>>Reserved_Bit :", reserved_bit)
    print(">>>>Don't_Fragment :", not_fragment)
    print(">>>>More_Fragments :", more_fragments)
    print(">>>>Fragment_Offset :", fragment_offset)
    print("Time_To_Live :", time_to_live)
    print("Protocol :", protocol)
    print("Header_Checksum :", header_checksum)
    print("Source_Ip_Address :", source_ip_address)
    print("Destination_Ip_Address :", destination_ip_address)
    return protocol

def convert_ip_address(data):
    ip_addr = list()
    for i in data:
        ip_addr.append(str(int(i.hex(), 16)))
    ip_addr = ".".join(ip_addr)
    return ip_addr

def parsing_tcp_header(data):
    tcp_header = struct.unpack("!2s2s4s4s2s2s2s2s", data)
    source_port = int(tcp_header[0].hex(), 16) #2s
    destination_port = int(tcp_header[1].hex(), 16) #2s
    sequence_number = int(tcp_header[2].hex(), 16) #4s
    acknowledgement_number = int(tcp_header[3].hex(), 16) #4s
    length_and_flag = hex_to_binary(tcp_header[4].hex())

    header_length = int(length_and_flag[0:4], 2)
    flags = int(length_and_flag[4:16], 2)
    #
    reserved = int(length_and_flag[4:7], 2)
    nonce = length_and_flag[7]
    cwr = length_and_flag[8]
    urgent = length_and_flag[10]
    acknowledgment = length_and_flag[11]
    push = length_and_flag[12]
    reset = length_and_flag[13]
    syn = length_and_flag[14]
    fin = length_and_flag[15]
    window_size_value = int(tcp_header[5].hex(), 16) #2s
    checksum = "0x" + tcp_header[6].hex() #2s
    urgent_pointer = int(tcp_header[7].hex(), 16) #2s

    print("=========tcp_header=========")
    print("Source_Port :", source_port)
    print("Destination_Port :", destination_port)
    print("Sequence_Number :", sequence_number)
    print("Acknowledgement_Number :", acknowledgement_number)
    print("Header_Length :", header_length)
    print("Flags :", flags)
    print("Reserved :", reserved)
    print("Nonce :", nonce)
    print("CWR :", cwr)
    print("Urgent :", urgent)
    print("Acknowledgment :", acknowledgment)
    print("Push :", push)
    print("Reset :", reset)
    print("Syn :", syn)
    print("Fin :", fin)
    print("Window_Size_Value :", window_size_value)
    print("Checksum :", checksum)
    print("Urgent_Pointer :", urgent_pointer)

def hex_to_binary(data):
    scale = 16
    num_of_bits = 16
    return bin(int(data, scale))[2:].zfill(num_of_bits)

def parsing_udp_header(data):
    udp_header = struct.unpack("!2s2s2s2s", data)
    source_port = int(udp_header[0].hex(), 16)
    destination_port = int(udp_header[1].hex(), 16)
    length = int(udp_header[2].hex(), 16)
    header_checksum = "0x" + udp_header[3].hex()

    print("=========udp_header=========")
    print("Source_Port :", source_port)
    print("Destination_Port :", destination_port)
    print("Length :", length)
    print("Header_Checksum :", header_checksum)


recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))


while True:
    print("<<<<<<<<<Packet_Capture_Start>>>>>>>>>")
    print("")
    
    data = recv_socket.recvfrom(20000)
    
    parsing_ethernet_header(data[0][0:14])
    
    protocol_id = parsing_ip_header(data[0][14:34])
    
    if(protocol_id == 6):
        parsing_tcp_header(data[0][34:54])
    elif(protocol_id == 17):
        parsing_udp_header(data[0][34:42])
    
    print("")
    print("<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>")
