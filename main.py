import socket as socket
import struct as struct
import os
import ctypes as ctypes

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    print("Scriptul nu rulează cu privilegii de administrator.")
    exit()

def sniffest_pack():
    # Get host
    host = socket.gethostbyname(socket.gethostname())
    print('IP: {}'.format(host))

    # Create a raw socket and bind it
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind((host, 0))

    # Include IP headers
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # Enable promiscuous mode
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:
        # Recive data
        raw_data, addr = conn.recvfrom(65536)
        # print("Address: ", addr)
        # print("Raw data: ", raw_data)
        network_layer_data,transport_layer_data = IP_header_packet(raw_data)
        print_network_layer_data(network_layer_data,transport_layer_data)
        protocol = network_layer_data[7]
        if protocol == 6: # TCP protocol
            transport_layer_data,application_layer_data = TCP_Transport_header_packet(transport_layer_data)
            print_tcp_transport_layer_data(transport_layer_data,application_layer_data)
        elif protocol == 7: # UDP protocol
            transport_layer_data,application_layer_data = UDP_Transport_header_packet(transport_layer_data)
            print_udp_transport_layer_data(transport_layer_data,application_layer_data)
        
        
# Network layer (ipv4 and ipv6 only)
def IP_header_packet(data):
    """
    Parses the IP header from raw packet data.

    This function extracts various fields from the IP header of a network packet.

    Args:
        data (bytes): The raw packet data containing the IP header.

    Returns:
        tuple: A tuple containing the following IP header fields:
            - version (int): IP version (4 or 6).
            - ihl (int): Internet Header Length in bytes.
            - tos (int): Type of Service.
            - total_length (int): Total length of the packet.
            - identification (int): Identification field for packet fragmentation.
            - flags_fragment (int): Flags and fragment offset.
            - ttl (int): Time to Live.
            - protocol (int): Protocol number (e.g., TCP=6, UDP=17).
            - header_checksum (int): Header checksum.
            - src (str): Source IP address.
            - dst (str): Destination IP address.
    """
    
    '''
    Unpacking the first 20 bytes of the IP header:
        Version and IHL (1 byte)
        Type of Service (TOS) (1 byte)
        Total Length (2 bytes)
        Identification (2 bytes)
        Flags and Fragment Offset (2 bytes)
        Time to Live (TTL) (1 byte)
        Protocol (1 byte)
        Header Checksum (2 bytes)
        Source Address (4 bytes)
        Destination Address (4 bytes)
    '''
    # Unpacking the first 20 bytes of the IP header
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    
    # Version and IHL (1 byte)
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4
    # Type of Service (TOS) (1 byte)
    tos = ip_header[1]
    # Total Length (2 bytes)
    total_length = ip_header[2]
    # Identification (2 bytes)
    identification = ip_header[3]
    # Flags and Fragment Offset (2 bytes)
    flags_fragment = ip_header[4]
    # Time to Live (TTL) (1 byte)
    ttl = ip_header[5]
    # Protocol (1 byte)
    protocol = ip_header[6]
    # Header Checksum (2 bytes)
    header_checksum = ip_header[7]
    # Source Address (4 bytes)
    src = socket.inet_ntoa(ip_header[8])
    # Destination Address (4 bytes)
    dst = socket.inet_ntoa(ip_header[9])
    
    # Calculate options and padding
    options_and_padding_length = ihl - 20  # Total Length of Options and Paddin
    # Extrage câmpurile Options și Padding
    options_and_padding = data[20:options_and_padding_length]
    
    # Rest of transport layer data
    transport_layer_data = data[ihl:]
    # Return the unpacked data
    return (version, ihl, tos, total_length, identification, flags_fragment, ttl, protocol, header_checksum, src, dst,options_and_padding) , transport_layer_data

def print_network_layer_data(network_layer,raw_data):
    """
    Prints the network layer details.
    """
    version, ihl, tos, length, id, flags_fragment, ttl, protocol, checksum, src, dst,options_and_padding = network_layer
    print("______Network Layer______")
    print(f"IP Version: {version}, Header Length: {ihl}, ToS: {tos}, Total Length: {length}")
    print(f"Identification: {id}, Flags/Fragment: {flags_fragment}, TTL: {ttl}, Protocol: {protocol}")
    print(f"Header Checksum: {checksum}")
    print(f"Source IP: {src}, Destination IP: {dst}")
    print(f"Options and Padding: {options_and_padding}")
    print(f"Raw header: {raw_data[:20].hex()}")
    print("-" * 50)

def IPv6_header_packet(data):
    """
    Parses the IPv6 header from raw packet data.

    This function extracts various fields from the IPv6 header of a network packet.

    Args:
        data (bytes): The raw packet data containing the IPv6 header.

    Returns:
        tuple: A tuple containing the following IPv6 header fields:
            - version (int): IP version (6).
            - traffic_class (int): Traffic Class.
            - flow_label (int): Flow Label.
            - payload_length (int): Payload Length.
            - next_header (int): Next Header.
            - hop_limit (int): Hop Limit.
            - src (str): Source IP address.
            - dst (str): Destination IP address.
    """
    
    '''
    Unpacking the first 40 bytes of the IPv6 header:
        Version (4 bits)
        Traffic Class (8 bits)
        Flow Label (20 bits)
        Payload Length (16 bits)
        Next Header (8 bits)
        Hop Limit (8 bits)
        Source Address (128 bits)
        Destination Address (128 bits)
    '''
    # Unpacking the first 40 bytes of the IPv6 header
    ipv6_header = struct.unpack('!4sHBB16s16s', data[:40])
    
    # Version, Traffic Class, Flow Label (4 bytes)
    version_traffic_flow = ipv6_header[0]
    version = (version_traffic_flow[0] >> 4) & 0xF
    traffic_class = ((version_traffic_flow[0] & 0xF) << 4) | (version_traffic_flow[1] >> 4)
    flow_label = ((version_traffic_flow[1] & 0xF) << 16) | (version_traffic_flow[2] << 8) | version_traffic_flow[3]
    
    # Payload Length (2 bytes)
    payload_length = ipv6_header[1]
    # Next Header (1 byte)
    next_header = ipv6_header[2]
    # Hop Limit (1 byte)
    hop_limit = ipv6_header[3]
    # Source Address (16 bytes)
    src = socket.inet_ntop(socket.AF_INET6, ipv6_header[4])
    # Destination Address (16 bytes)
    dst = socket.inet_ntop(socket.AF_INET6, ipv6_header[5])
    
    # Rest of transport layer data
    transport_layer_data = data[40:]
    # Return the unpacked data
    return (version, traffic_class, flow_label, payload_length, next_header, hop_limit, src, dst), transport_layer_data

def print_ipv6_network_layer_data(network_layer, raw_data):
    """
    Prints the IPv6 network layer details.
    """
    version, traffic_class, flow_label, payload_length, next_header, hop_limit, src, dst = network_layer
    print("______Network Layer (IPv6)______")
    print(f"IP Version: {version}, Traffic Class: {traffic_class}, Flow Label: {flow_label}")
    print(f"Payload Length: {payload_length}, Next Header: {next_header}, Hop Limit: {hop_limit}")
    print(f"Source IP: {src}, Destination IP: {dst}")
    print(f"Raw header: {raw_data[:40].hex()}")
    print("-" * 50)

# Transport layer (tcp and udp only)
def TCP_Transport_header_packet(data):
    """
    Parses the transport layer header from raw packet data.
    
    This function extracts various fields from the transport layer header of a network packet.
    
    Args:
    data (bytes): The raw packet data containing the transport layer header.
    
    Returns:
    tuple: A tuple containing the following transport layer header fields:
    - src_port (int): Source port number.
    - dst_port (int): Destination port number.
    - sequence (int): Sequence number.
    - acknowledgment (int): Acknowledgment number.
    - offset (int): Data offset.
    - reserved (int): Reserved bits.
    - flags (int): Flags.
    - window(sliding window) (int): Window size.
    - checksum (int): Checksum.
    - urgent_pointer (int): Urgent pointer.
    - options (bytes): Options (if any).
    - padding (int):
    - rest of the packet (bytes): Rest of the packet data.
    """
    
    '''
    Unpacking the first 20 bytes of the transport layer header:
    Source Port (2 bytes)
    Destination Port (2 bytes)
    Sequence Number (4 bytes)
    Acknowledgment Number (4 bytes)
    Data Offset (4 bits)
    Reserved (3 bits)
    Flags (9 bits)
    Window Size (2 bytes)
    Checksum (2 bytes)
    Urgent Pointer (2 bytes)
    Options (if any)
    Padding (if any)    
    '''
    # Unpacking the first 20 bytes of the transport layer header
    tcp_transport_header = struct.unpack('!HHLLHHHH', data[:20])
    
    # Source Port (2 bytes)
    src_port = tcp_transport_header[0]
    # Destination Port (2 bytes)
    dst_port = tcp_transport_header[1]
    # Sequence Number (4 bytes)
    sequence = tcp_transport_header[2]
    # Acknowledgment Number (4 bytes)
    acknowledgment = tcp_transport_header[3]
    # Data Offset (4 bits)
    offset = (tcp_transport_header[4] >> 4) * 4
    # Reserved (3 bits)
    reserved = (tcp_transport_header[4] & 0xE) >> 1 # 0x0E = 00001110
    # Flags (9 bits)
    flags = tcp_transport_header[4] & 0x1F  # 0x1F = 00011111
    # Window Size (2 bytes)
    window = tcp_transport_header[5]
    # Checksum (2 bytes)
    checksum = tcp_transport_header[6]
    # Urgent Pointer (2 bytes)
    urgent_pointer = tcp_transport_header[7]
    
    # Calculate options and padding
    options_and_padding_length = offset - 20  # Total Length of Options and Padding
    # Extrage câmpurile Options și Padding
    options_and_padding = data[20:options_and_padding_length]
    # Rest of the packet
    rest_of_packet = data[offset:]
    
    # Return the unpacked data
    return (src_port, dst_port, sequence, acknowledgment, offset, reserved, flags, window, checksum, urgent_pointer,options_and_padding),rest_of_packet
    
def UDP_Transport_header_packet(data):
    """
    Parses the transport layer header from raw packet data.
    
    This function extracts various fields from the transport layer header of a UDP packet.
    
    Args:
    data (bytes): The raw packet data containing the transport layer header.
    
    Returns:
    tuple: A tuple containing the following transport layer header fields:
    - src_port (int): Source port number.
    - dst_port (int): Destination port number.
    - length (int): Length of the UDP packet.
    - checksum (int): Checksum.
    - rest_of_packet (bytes): Rest of the packet data.
    """
    
    '''
    Unpacking the first 8 bytes of the transport layer header:
    Source Port (2 bytes)
    Destination Port (2 bytes)
    Length (2 bytes)
    Checksum (2 bytes)
    '''
    # Unpacking the first 8 bytes of the transport layer header
    udp_transport_header = struct.unpack('!HHHH', data[:8])
    
    # Source Port (2 bytes)
    src_port = udp_transport_header[0]
    # Destination Port (2 bytes)
    dst_port = udp_transport_header[1]
    # Length (2 bytes)
    length = udp_transport_header[2]
    # Checksum (2 bytes)
    checksum = udp_transport_header[3]
    
    # Rest of the packet
    rest_of_packet = data[8:]
    
    # Return the unpacked data
    return (src_port, dst_port, length, checksum), rest_of_packet

def print_tcp_transport_layer_data(transport_layer, raw_data):
    """
    Prints the transport layer details.
    """
    src_port, dst_port, sequence, acknowledgment, offset, reserved, flags, window, checksum, urgent_pointer,options_and_padding = transport_layer
    
    print("______Transport Layer (TCP)______")
    print(f"Source Port: {src_port}, Destination Port: {dst_port}")
    print(f"Sequence Number: {sequence}, Acknowledgment: {acknowledgment}")
    print(f"Data Offset: {offset}, Reserved: {reserved}, Flags: {flags}")
    print(f"Window Size: {window}, Checksum: {checksum}, Urgent Pointer: {urgent_pointer}")
    print(f"Options and Padding: {options_and_padding}")
    print(f"Raw header: {raw_data[:20].hex()}")
    print("-" * 50)

def print_udp_transport_layer_data(transport_layer, raw_data):
    """
    Prints the transport layer details.
    """
    src_port, dst_port, length, checksum = transport_layer
    
    print("______Transport Layer (UDP)______")
    print(f"Source Port: {src_port}, Destination Port: {dst_port}")
    print(f"Length: {length}, Checksum: {checksum}")
    print(f"Raw header: {raw_data[:8].hex()}")
    print("-" * 50)


if __name__ == '__main__':
    sniffest_pack()




