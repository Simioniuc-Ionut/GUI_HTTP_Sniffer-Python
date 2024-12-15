import socket as socket
import struct as struct
import os
import time
import ctypes as ctypes

# Dictionary for storing and retrieving fragmented packets
fragmented_packets = {}

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
    # conn.bind(('127.0.0.1', 0)) # run on localhost interface


    # Include IP headers
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # Enable promiscuous mode
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:
        # Recive data
        raw_data, addr = conn.recvfrom(65536)
        print("Address: ", addr)
        # print("Raw data: ", raw_data)
        # Parse packet of raw data
        handler_protocols(raw_data)
        
def handler_protocols(raw_data):
    try:
        # Network layer
        network_layer_data,transport_layer_raw_data,protocol = IP_header_packet(raw_data)
        print_network_layer_data(network_layer_data,transport_layer_raw_data,protocol)
        
        # Transport layer
        if protocol == 6: # TCP protocol
            try:
                transport_layer_data,application_layer_data = TCP_Transport_header_packet(transport_layer_raw_data)
                print_tcp_transport_layer_data(transport_layer_data,application_layer_data)
                src_port = transport_layer_data[0]
                dsc_port = transport_layer_data[1]
                
                # Verify TCP Flags
                flags = transport_layer_data[6]
                if flags & 0x01:  # FIN flag
                    print("TCP connection closed (FIN).")
                    cleanup_connection(src_port, dsc_port)
                    return
                elif flags & 0x04:  # RST flag
                    print("TCP connection reset (RST).")
                    cleanup_connection(src_port, dsc_port)
                    return
                elif flags & 0x10:  # ACK flag
                    pass
                    # print("TCP acknowledgment packet (ACK).")
                
            except Exception as e:
                print(f"_______Error at TCP parser: {e}")
                return
        elif protocol == 17: # UDP protocol
            try:
                transport_layer_data,application_layer_data = UDP_Transport_header_packet(transport_layer_raw_data)
                print_udp_transport_layer_data(transport_layer_data,application_layer_data)
                src_port = transport_layer_data[0]
                dsc_port = transport_layer_data[1]
            except Exception as e:
                print(f"_______Error at UDP parser: {e}")
                return
        else:
            src_port = -1
            dsc_port = -1
            
        # Application layer
        # HTTPS request
        if  dsc_port == 443: 
            print("HTTPS protocol")
        elif dsc_port == 80:
            try:
                application_layer_data = HTTP_application_layer(application_layer_data,src_port, dsc_port)
                print_application_layer_data(application_layer_data)
            except Exception as e:
                print(f"_______Error parsing HTTP application layer: {e}")

        #HTTP Response
        if src_port == 443:
            print("HTTPS Response")
        elif src_port == 80:
            try:
                response_layer_data = HTTP_response_layer(application_layer_data,src_port, dsc_port)
                print_http_response_layer_data(response_layer_data)
            except Exception as e:
                print(f"Error parsing HTTP response layer: {e}")
        else :
            print("Unknown protocol")
    except Exception as e:
        print(f"_______Error at parser: {e}")
        
        
# Tested
def cleanup_connection(src_port, dsc_port):
    """
    Cleanup the fragmented packets and the connection associated with the given ports.
    """
    key = (src_port, dsc_port)
    if key in fragmented_packets:
        del fragmented_packets[key]
        print(f"Packets associated with the connecction {key} was deleted.")
        
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
    try:
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
        options_and_padding = data[20:20 + options_and_padding_length] if options_and_padding_length > 0 else b''
        
        # Rest of transport layer data
        transport_layer_data = data[ihl:]
        # Return the unpacked data
        return (version, ihl, tos, total_length, identification, flags_fragment, ttl, header_checksum, src, dst,options_and_padding) , transport_layer_data,protocol
    except Exception as e:
        print(f"______Error parsing IP header: {e}")
        return None, None, None

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
    try:
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
    except Exception as e:
        print(f"______Error parsing IPv6 header: {e}")
        return None, None

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
    try:
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
        offset = (tcp_transport_header[4] >> 4) & 0xF  # Extract the 4-bit data offset field
        offset *= 4  # Convert to bytes
        # Reserved (3 bits)
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
        # Extract options and padding
        options_and_padding = data[20:offset] if options_and_padding_length > 0 else b''
        # Rest of the packet (payload)
        rest_of_packet = data[offset:]
        # Return the unpacked data
        return (src_port, dst_port, sequence, acknowledgment, offset, reserved, flags, window, checksum, urgent_pointer,options_and_padding),rest_of_packet
    except Exception as e:
        print(f"______Error parsing TCP transport header: {e}")
        return None, None
    
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
    try:
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
    except Exception as e:
        print(f"______Error parsing UDP transport header: {e}")
        return None, None

# Application layer
# Tested
def find_http_method(decoded_data):
    start_index = -1
    for i in range(len(decoded_data)):
        if decoded_data[i:i+3] in ('GET', 'POS', 'HEA', 'PUT', 'DEL', 'OPT', 'PAT'):
            start_index = i
            break
    if start_index == -1:
        raise ValueError("Failed to find a valid HTTP request line")
    
    # Extract the valid HTTP data starting from the Request Line
    valid_http_data = decoded_data[start_index:]
    return valid_http_data
# Tested
def HTTP_application_layer(application_layer_data,src_port, dst_port):
    """
    Parses the application layer data from raw packet data.
    
    This function extracts the application layer data from a network packet and transforms it into a dictionary.
    
    Args:
    application_layer_data (bytes): The raw packet data containing the application layer data.
    
    Returns:
    dict: The application layer data as a dictionary.
    """
    try:
        # Generate a unique key for the packet
        key = (src_port, dst_port)
        
        # Store the packet data in the dictionary
        if key not in fragmented_packets:
            fragmented_packets[key] = b''
        fragmented_packets[key] += application_layer_data

        
        # Decode the raw packet data to a string
        decoded_data = fragmented_packets[key].decode('utf-8', errors='ignore')
        
        
        # Strip any leading/trailing whitespace or non-printable characters
        decoded_data = decoded_data.strip()
        # Debug: Print the raw decoded data
        # print("Raw decoded data:", decoded_data)
        
        # Extract methdods from raw decoded data and convert them to a valid http data structure
        valid_http_data = find_http_method(decoded_data)
        
        # Split the data into lines
        lines = valid_http_data.split('\r\n')
        
        # Initialize the dictionary to store the parsed data
        http_data = {}       
        request_line = lines[0]
        # The first line is the Request Line
        http_data['Request Line'] = request_line
        
        # Extract the HTTP method from the Request Line
        method = request_line.split(' ')[0]
        http_data['Method'] = method
    
        # The rest are Header Fields until an empty line is encountered
        for line in lines[1:]:
            if line == '':
                break
            key, value = line.split(': ', 1)
            http_data[key] = value
        return http_data
    except Exception as e:
        print(f"Error parsing HTTP application layer: {e}")
        return {"Error": "Failed to parse HTTP application layer"}

#HTTP response

# Tested
def find_http_status_line(decoded_data):
    """
    Finds the start index of the HTTP status line in the decoded data.
    
    Args:
    decoded_data (str): The decoded HTTP response data.
    
    Returns:
    dict: A dictionary containing the valid HTTP data or an error message.
    """
    start_index = -1
    for i in range(len(decoded_data)):
        if decoded_data[i:i+4] == 'HTTP':
            start_index = i
            break
    
    if start_index == -1:
        raise ValueError("Failed to find a valid HTTP status response line")

    # Extract the valid HTTP data starting from the Status Line
    valid_http_data = decoded_data[start_index:]
    return valid_http_data
# Tested
def parse_http_headers_and_body(valid_http_data):
    """
    Parses the HTTP headers and body from the valid HTTP data.
    
    Args:
    valid_http_data (str): The valid HTTP data starting from the status line.
    
    Returns:
    dict: A dictionary containing the HTTP headers and body.
    """
    
    # Split the data into lines
    lines = valid_http_data.split('\r\n')
    
    # Initialize the dictionary to store the parsed data
    http_data = {}
    
    # The first line is the Status Line
    status_line = lines[0]
    http_data['Status Line'] = status_line
    
    # The rest are Header Fields until an empty line is encountered
    headers_end_index = 1
    for line in lines[1:]:
        if line == '':
            break
        key, value = line.split(': ', 1)
        http_data[key] = value
        headers_end_index += 1
    
    # Extract the body of the response
    body = '\r\n'.join(lines[headers_end_index+1:])
    if body:
        http_data['Body'] = body
    
    return http_data
# Tested
def HTTP_response_layer(response_layer_data, src_port, dst_port):
    """
    Parses the HTTP response layer data from raw packet data.
    
    This function extracts the HTTP response layer data from a network packet and transforms it into a dictionary.
    
    Args:
    response_layer_data (bytes): The raw packet data containing the HTTP response layer data.
    
    Returns:
    dict: The HTTP response layer data as a dictionary.
    """
    try:
        
        # Generate a unique key for the packet
        key = (src_port, dst_port)
        
        # Store the packet data in the dictionary
        if key not in fragmented_packets:
            fragmented_packets[key] = b''
        fragmented_packets[key] += response_layer_data

        # Decode the raw packet data to a string
        decoded_data = fragmented_packets[key].decode('utf-8', errors='ignore')
        
        
        # Debug: Print the raw decoded data
        # print("Raw decoded data:", decoded_data)
        
        # Strip any leading/trailing whitespace or non-printable characters
        decoded_data = decoded_data.strip()
        
        #Extract http status line and structure raw data 
        valid_http_data = find_http_status_line(decoded_data)
        
        # Parse http header and body if it contains (optional)
        http_data = parse_http_headers_and_body(valid_http_data)
        
        return http_data
    except Exception as e:
        print(f"Error parsing HTTP response layer: {e}")
        return {"Error": "Failed to parse HTTP response layer"}

# Printing Zone
def print_http_response_layer_data(response_layer_data):
    """
    Prints the HTTP response layer details.
    """
    print("______HTTP Response Layer______")
    for key, value in response_layer_data.items():
        print(f"{key}: {value}")
    print("-" * 50)

def print_application_layer_data(application_layer_data):
    """
    Prints the application layer details.
    """
    print("______Application Layer (HTTP)______")
    for key, value in application_layer_data.items():
        print(f"{key}: {value}")
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

def print_tcp_transport_layer_data(transport_layer, raw_data):
    """
    Prints the transport layer details.
    """
    src_port, dst_port, sequence, acknowledgment, offset, reserved, flags, window, checksum, urgent_pointer,options_and_padding = transport_layer
    
    print("______Transport Layer (TCP)______")
    print(f"Source Port: {src_port}, Destination Port: {dst_port}")
    print(f"Sequence Number: {sequence}, Acknowledgment: {acknowledgment}")
    print(f"Data Offset: {offset}, Reserved: {reserved}, Flags: {format_tcp_flags(flags)}")
    print(f"Window Size: {window}, Checksum: {checksum}, Urgent Pointer: {urgent_pointer}")
    print(f"Options and Padding: {options_and_padding}")
    print(f"Raw header: {raw_data[:20].hex()}")
    print("-" * 50)

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

def print_network_layer_data(network_layer,raw_data,protocol):
    """
    Prints the network layer details.
    """
    version, ihl, tos, length, id, flags_fragment, ttl, checksum, src, dst,options_and_padding = network_layer
    print("______Network Layer______")
    print(f"IP Version: {version}, Header Length: {ihl}, ToS: {tos}, Total Length: {length}")
    print(f"Identification: {id}, Flags/Fragment: {format_ip_flags(flags_fragment)}, TTL: {ttl}, Protocol: {protocol}")
    print(f"Header Checksum: {checksum}")
    print(f"Source IP: {src}, Destination IP: {dst}")
    print(f"Options and Padding: {options_and_padding}")
    print(f"Raw header: {raw_data[:20].hex()}")
    print("-" * 50)

def format_tcp_flags(flags_fragment):
    """
    Converts the flags/fragment field to a human-readable string.
    """
    flags = []
    if flags_fragment & 0x01:
        flags.append("FIN")
    if flags_fragment & 0x02:
        flags.append("SYN")
    if flags_fragment & 0x04:
        flags.append("RST")
    if flags_fragment & 0x08:
        flags.append("PSH")
    if flags_fragment & 0x10:
        flags.append("ACK")
    if flags_fragment & 0x20:
        flags.append("URG")
    if flags_fragment & 0x40:
        flags.append("ECE")
    if flags_fragment & 0x80:
        flags.append("CWR")
    return ', '.join(flags) if flags else "None"

def format_ip_flags(flags_fragment):
    """
    Converts the IP flags field to a human-readable string.
    """
    flag_descriptions = []
    if flags_fragment & 0x4000:
        flag_descriptions.append("DF")
    if flags_fragment & 0x2000:
        flag_descriptions.append("MF")
    return ', '.join(flag_descriptions) if flag_descriptions else "None"

if __name__ == '__main__':
    sniffest_pack()
