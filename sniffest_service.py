import socket as socket
import struct as struct
import os
import time
import re
import ctypes as ctypes
from datetime import datetime, timedelta
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

def sniffest_run():
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
        # Here we have the packet defined
        network_layer_packet = {}
        transport_layer_packet = {}
        application_layer_packet = {} # Could be request or response
        
        
        # Network layer
        network_layer_data,transport_layer_raw_data,protocol = IP_header_packet(raw_data)
        print_network_layer_data(network_layer_data,transport_layer_raw_data,protocol)
        
        # Add to dict packet network layer data
        network_layer_packet=ipv4_network_layer_data_to_dict(network_layer_data,protocol)
        sequence_number = 0
        
        # Transport layer
        if protocol == 6: # TCP protocol
            try:
                transport_layer_data,application_layer_raw_data = TCP_Transport_header_packet(transport_layer_raw_data)
                print_tcp_transport_layer_data(transport_layer_data,application_layer_raw_data)
                sequence_number = transport_layer_data[2] # Sequence number
                # Add to dict packet transport layer TCP data
                transport_layer_packet=tcp_transport_layer_data_to_dict(transport_layer_data)
                
                src_port = transport_layer_data[0]
                dsc_port = transport_layer_data[1]
                
                # Verify TCP Flags
                flags = transport_layer_data[6]
                if flags & 0x01:  # FIN flag
                    print("TCP connection closed (FIN).")
                    cleanup_connection(src_port, dsc_port)
                    # Send current packet
                    anssemble_full_packet_and_send(network_layer_packet,transport_layer_packet,application_layer_packet)

                    return
                elif flags & 0x04:  # RST flag
                    print("TCP connection reset (RST).")
                    cleanup_connection(src_port, dsc_port)
                    
                    # Send current packet
                    anssemble_full_packet_and_send(network_layer_packet,transport_layer_packet,application_layer_packet)
                    return
                elif flags & 0x10:  # ACK flag
                    pass
                    # print("TCP acknowledgment packet (ACK).")
                
            except Exception as e:
                print(f"_______Error at TCP parser: {e}")
                return
        elif protocol == 17: # UDP protocol
            try:
                transport_layer_data,application_layer_raw_data = UDP_Transport_header_packet(transport_layer_raw_data)
                print_udp_transport_layer_data(transport_layer_data,application_layer_raw_data)
                
                # Add to dict packet transport layer UDP data
                transport_layer_packet=udp_transport_layer_data_to_dict(transport_layer_packet)
                
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
            application_layer_packet.update({"HTTPS Secured":"None"})
        elif dsc_port == 80:
            try:
                application_layer_data = HTTP_request_process_http_request_segment(application_layer_raw_data,src_port, dsc_port,sequence_number)
                print_application_layer_data(application_layer_data)
                
                #  Add to dict packet application layer data
                application_layer_packet=application_layer_data
                
            except Exception as e:
                print(f"_______Error parsing HTTP application layer: {e}")

        #HTTP Response
        if src_port == 443:
            print("HTTPS Response")
            application_layer_packet.update({"HTTPS Secured":"None"})
        elif src_port == 80:
            try:
                response_layer_data = HTTP_response_process_tcp_segment(application_layer_raw_data,src_port, dsc_port,sequence_number)
                print_http_response_layer_data(response_layer_data)
                
                #  Add to dict packet application layer data
                application_layer_packet=response_layer_data
                
            except Exception as e:
                print(f"Error parsing HTTP response layer: {e}")
        else :
            print("Unknown protocol")
            application_layer_packet.update({"Other protocol:" : "None"})
            
            
        # Send current packet
        anssemble_full_packet_and_send(network_layer_packet,transport_layer_packet,application_layer_packet)
    except Exception as e:
        print(f"_______Error at parser: {e}")
        

def anssemble_full_packet_and_send(network_layer_packet,transport_layer_packet,application_layer_packet):
    """
    Assemble the full packet by combining the parsed network, transport, and application layers
    """
    
    # full_pack = {
    #     "ip_version": network_layer_packet.get("ip_version"),
    #     "src_ip": network_layer_packet.get("src_ip"),
    #     "dst_ip": network_layer_packet.get("dst_ip"),
    #     "protocol": network_layer_packet.get("protocol"),
    #     "source_port": transport_layer_packet.get("source_port"),
    #     "destination_port": transport_layer_packet.get("destination_port"),
    #     "flags": transport_layer_packet.get("flags"),  # TCP-specific
    #     "sequence_number": transport_layer_packet.get("sequence_number"),  # TCP-specific
    #     "checksum": transport_layer_packet.get("checksum"),
    #     "http_method": application_layer_packet.get("Method", None),  # Example key for HTTP
    #     "http_host": application_layer_packet.get("Host", None),
    #     "http_url": application_layer_packet.get("URL", None),
    #     "timestamp": datetime.now(),
    #     "payload": { "network_layer_packet": network_layer_packet,
    #                 "transport_layer_packet": transport_layer_packet,
    #                 "application_layer_packet": application_layer_packet}
    # }
    print("________________________Network Layer Packet________________________",network_layer_packet)
    print("________________________Transport Layer Packet________________________",transport_layer_packet)
    print("________________________Application Layer Packet________________________",application_layer_packet)
        
    

# Tested
def cleanup_connection(src_port, dsc_port):
    """
    Cleanup the fragmented packets and the connection associated with the given ports.
    """
    key = (src_port, dsc_port)
    if key in fragmented_packets:
        del fragmented_packets[key]
        print(f"Packets associated with the connecction {key} was deleted.")

'''Parse the raw data'''
# Network layer (ipv4 and ipv6 only)
def IP_header_packet(data : bytes) -> tuple:
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

def IPv6_header_packet(data : bytes) -> tuple:
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
def TCP_Transport_header_packet(data : bytes) -> tuple:
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
    
def UDP_Transport_header_packet(data : bytes) -> tuple:
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

### Application layer


# Eliminate first corupted charactes
# Tested
def find_http_status_line(decoded_data) -> bytes:
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
def find_body(bod_data) -> bytes:
    """
    Finds the start index of the "{" from body in the decoded data.
    
    Args:
    bod_data (str): The decoded HTTP response data.
    
    Returns:
    bytes: The HTTP body data.
    """
    start_index = -1
    for i in range(len(bod_data)):
        if bod_data[i] == '{':
            start_index = i
            break
        if bod_data[i:i+2] == 'ar':
            # add "{" in front of the args: {}
            bod_data = '{ ' + bod_data[i:]
            start_index = i-2
            break
    
    if start_index == -1:
        raise ValueError("Failed to find a valid HTTP body")
    
    # Extract the HTTP body starting from the double CRLF delimiter
    body_data = bod_data[i:]
    return body_data

# Tested
def parse_http_request_header(valid_http_data):
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
# Tested
def find_http_request_type(decoded_data):
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
def HTTP_application_layer(application_layer_data : bytes,src_port, dst_port) -> dict :
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
        
        # Store the packet data in the fragmented dictionary
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
        valid_http_data = parse_http_request_header(decoded_data)
        
        #Extract header from the raw data
        http_data=parse_http_request_header(valid_http_data)

        # Check if the request is complete
        # In general we dont have problems with fragmetation for sending requests.
        
        # Clean up the fragmented packets dictionary
        cleanup_connection(src_port, dst_port)
        
        return http_data
    except Exception as e:
        print(f"Error parsing HTTP application layer: {e}")
        # Clean up the fragmented packets dictionary
        cleanup_connection(src_port, dst_port)
        return {"Error": "Failed to parse HTTP response layer"} 

def HTTP_request_process_http_request_segment(data: bytes, src_port: int, dst_port: int, seq_num: int):
    """
    Processes a single TCP segment for an HTTP request, handling segmentation.

    Args:
        data (bytes): The TCP payload (raw data from the segment).
        src_port (int): Source port of the connection.
        dst_port (int): Destination port of the connection.
        seq_num (int): TCP sequence number of the segment.

    Returns:
        dict or None: Parsed HTTP request if complete, or None if incomplete.
    """
    connection_key = (src_port, dst_port)

    # Initialize storage for the connection
    if connection_key not in fragmented_packets:
        fragmented_packets[connection_key] = {}

    # Store the segment in the correct order by sequence number
    fragmented_packets[connection_key][seq_num] = data
    
    # Reassemble all segments
    assembled_data = b''.join(
        fragmented_packets[connection_key][seq]
        for seq in sorted(fragmented_packets[connection_key])
    )   
    
    # Decode the data for easier processing
    try:
        decoded_data = assembled_data.decode('utf-8', errors='ignore')
    except Exception:
        return {"Error": "Failed to decode data"}

    # Check for the end of the header
    header_end_index = decoded_data.find('\r\n\r\n')
    if header_end_index == -1:
        # Header is incomplete
        print("Header incomplete, waiting for more data...")
        return None

    # Extract header and body
    header =find_http_request_type(decoded_data[:header_end_index])
    body = find_body(decoded_data[header_end_index + 4:])

    # Parse headers
    try:
        headers = dict(line.split(': ', 1) for line in header.split('\r\n')[1:] if ': ' in line)
    except ValueError:
        print("Malformed headers, waiting for more data...")
        return None

    content_length = int(headers.get("Content-Length", 0)) if "Content-Length" in headers else 0

    # Check if the body is complete
    if len(body) < content_length:
        print(f"Incomplete body: received {len(body)}, expected {content_length}")
        return None

    # Extract the full body
    full_body = body[:content_length]

    # Clean up buffer after processing
    del fragmented_packets[connection_key]

    # Return the parsed HTTP request
    return {
        "Request Line": header.split('\r\n')[0],
        "Headers": headers,
        "Body": full_body
    }

### HTTP response


def HTTP_response_process_tcp_segment(data: bytes, src_port: int, dst_port: int, seq_number: int):
    """
    Processes a single TCP segment, storing it by sequence number and reassembling data.

    Args:
        data (bytes): The TCP payload (raw data from the segment).
        src_port (int): Source port of the connection.
        dst_port (int): Destination port of the connection.
        seq_number (int): Sequence number of the TCP segment.

    Returns:
        dict or None: Parsed HTTP data if complete, or None if incomplete.
    """

    connection_key = (src_port, dst_port)

    # Initialize storage for the connection
    if connection_key not in fragmented_packets:
        fragmented_packets[connection_key] = {}

    # Store the segment in the correct order by sequence number
    fragmented_packets[connection_key][seq_number] = data

    # Reassemble all segments
    assembled_data = b''.join(
        fragmented_packets[connection_key][seq]
        for seq in sorted(fragmented_packets[connection_key])
    )

    # Decode data for processing
    try:
        decoded_data = assembled_data.decode('utf-8', errors='ignore')
    except Exception:
        return {"Error": "Failed to decode data"}

    # Check if header is complete
    header_end_index = decoded_data.find('\r\n\r\n')
    if header_end_index == -1:
        print("Header End Index:", header_end_index)
        print("Incomplete header, waiting for more data...")
        return None

    # Parse the header and process eventual cripted characters from the front of the header and body data
    header=find_http_status_line(decoded_data[:header_end_index])
    body = find_body(decoded_data[header_end_index + 4:])

    # Extract Content-Length to validate the body
    headers = dict(line.split(': ', 1) for line in header.split('\r\n') if ': ' in line)
    content_length = int(headers.get("Content-Length", 0))

    # Check if body is complete
    if len(body) < content_length:
        print(f"Incomplete body: received {len(body)}, expected {content_length}")
        return None

    # Clean up buffer after processing
    del fragmented_packets[connection_key]

    # Return the assembled HTTP data
    return {
        "Status Line": header.split('\r\n')[0],
        "Headers": headers,
        "Body": body[:content_length]
    }

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

#Anseembly packts
def ipv4_network_layer_data_to_dict(network_layer : tuple ,protocol) -> dict:
    """
    Parses and returns network layer details as a dictionary.
    """
    version, ihl, tos, length, id, flags_fragment, ttl, checksum, src, dst, options_and_padding = network_layer
    return {
        "ip_version": version,
        "header_length": ihl,
        "tos": tos,
        "total_length": length,
        "identification": id,
        "flags_fragment": flags_fragment,
        "ttl": ttl,
        "header_checksum": checksum,
        "src_ip": src,
        "dst_ip": dst,
        "options_and_padding": options_and_padding,
        "protocol": "TCP" if protocol == 6 else "UDP" if protocol == 17 else "Unknown"

    }
def tcp_transport_layer_data_to_dict(transport_layer : tuple) -> dict:
    """
    Parses and returns TCP transport layer details as a dictionary.
    """
    src_port, dst_port, sequence, acknowledgment, offset, reserved, flags, window, checksum, urgent_pointer, options_and_padding = transport_layer
    return {
        "source_port": src_port,
        "destination_port": dst_port,
        "sequence_number": sequence,
        "acknowledgment_number": acknowledgment,
        "data_offset": offset,
        "reserved": reserved,
        "flags": format_tcp_flags(flags),  # Formatează pentru a fi mai lizibil
        "window_size": window,
        "checksum": checksum,
        "urgent_pointer": urgent_pointer,
        "options_and_padding": options_and_padding
        # "raw_header": raw_data[:20].hex()
    }
def udp_transport_layer_data_to_dict(transport_layer : tuple) -> dict:
    """
    Parses and returns UDP transport layer details as a dictionary.
    """
    src_port, dst_port, length, checksum = transport_layer
    return {
        "source_port": src_port,
        "destination_port": dst_port,
        "length": length,
        "checksum": checksum
        # "raw_header": raw_data[:8].hex()
    }
def ipv6_network_layer_data_to_dict(network_layer : tuple) -> dict:
    """
    Parses and returns IPv6 network layer details as a dictionary.
    """
    version, traffic_class, flow_label, payload_length, next_header, hop_limit, src, dst = network_layer
    return {
        "ip_version": version,
        "traffic_class": traffic_class,
        "flow_label": flow_label,
        "payload_length": payload_length,
        "next_header": next_header,
        "hop_limit": hop_limit,
        "src_ip": src,
        "dst_ip": dst
    }


if __name__ == '__main__':
    sniffest_run()

