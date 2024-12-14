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

def main2():
    # the public network interface
    HOST = socket.gethostbyname(socket.gethostname())

    # create a raw socket and bind it to the public interface
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind((HOST, 0))

    # Include IP headers
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # receive all packets
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:
        packet, addr = s.recvfrom(65535)  # Use recvfrom to get data and address
        print(f"Received packet from {addr}")

    # disabled promiscuous mode
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)



def main3():
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
        version, ihl, tos, length, id, flags_fragment, ttl, protocol, checksum, src, dst = IP_header_packet(raw_data)
        print(f"IP Version: {version}, Header Length: {ihl}, ToS: {tos}, Total Length: {length}")
        print(f"Identification: {id}, Flags/Fragment: {flags_fragment}, TTL: {ttl}, Protocol: {protocol}")
        print(f"Header Checksum: {checksum}")
        print(f"Source IP: {src}, Destination IP: {dst}")
        print(f"Raw header: {raw_data[:20].hex()}")
        print("-" * 50)

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
    return version, ihl, tos, total_length, identification, flags_fragment, ttl, protocol, header_checksum, src, dst



if __name__ == '__main__':
    main3()
    # sniff(prn=packet_callback, store=0)



