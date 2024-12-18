import json
def te():
    packet = {'network_layer_packet': {'ip_version': 4, 'header_length': 20, 'tos': 32, 'total_length': 903, 'identification': 52663, 'flags_fragment': 16384, 'ttl': 234, 'header_checksum': 58682, 'src_ip': '98.85.100.80', 'dst_ip': '192.168.83.16', 'options_and_padding': b'', 'protocol': 'TCP'}, 'transport_layer_packet': {'source_port': 80, 'destination_port': 59826, 'sequence_number': 2276749530, 'acknowledgment_number': 3854879125, 'data_offset': 4, 'reserved': 4, 'flags': 'PSH, ACK', 'window_size': 114, 'checksum': 51204, 'urgent_pointer': 0, 'options_and_padding': b''}, 'application_layer_packet': {'Status Line': 'HTTP/1.1 200 OK', 'Headers': {'Date': 'Wed, 18 Dec 2024 15:30:13 GMT', 'Content-Type': 'application/json', 'Content-Length': '616', 'Connection': 'keep-alive', 'Server': 'gunicorn/19.9.0', 'Access-Control-Allow-Origin': 'http://httpbin.org', 'Access-Control-Allow-Credentials': 'true'}, 'Body': '{\n  "args": {}, \n  "data": "", \n  "files": {}, \n  "form": {}, \n  "headers": {\n    "Accept": "application/json", \n    "Accept-Encoding": "gzip, deflate", \n    "Accept-Language": "en-US,en;q=0.9,ro;q=0.8", \n    "Host": "httpbin.org", \n    "Origin": "http://httpbin.org", \n    "Referer": "http://httpbin.org/", \n    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0", \n    "X-Amzn-Trace-Id": "Root=1-6762ea85-12e9e80340eecc317db2020b"\n  }, \n  "json": null, \n  "origin": "37.251.223.139", \n  "url": "http://httpbin.org/delete"\n}\n'}}
    
    # Extract data from the packet
    network_packet = packet.get('network_layer_packet', {})
    transport_packet = packet.get('transport_layer_packet', {})
    application_packet = packet.get('application_layer_packet', {})

    
    # Json Brute
    raw_body = '{\n  "args": {}, \n  "data": "", \n  "files": {}, \n  "form": {}, \n  "headers": {\n    "Accept": "application/json", \n    "Accept-Encoding": "gzip, deflate", \n    "Accept-Language": "en-US,en;q=0.9,ro;q=0.8", \n    "Host": "httpbin.org", \n    "Origin": "http://httpbin.org", \n    "Referer": "http://httpbin.org/", \n    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0", \n    "X-Amzn-Trace-Id": "Root=1-6762ea85-12e9e80340eecc317db2020b"\n  }, \n  "json": null, \n  "origin": "37.251.223.139", \n  "url": "http://httpbin.org/delete"\n}\n'


    # Decode JSON data
    decoded_body = json.loads(raw_body)
    print(decoded_body)
    
te()