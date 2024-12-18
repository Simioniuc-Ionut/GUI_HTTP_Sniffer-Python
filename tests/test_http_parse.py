def test_():
  packet_1 = b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nargs: {}"
  packet_2 = b" , response"
  packet_3 = b" part two"
  
  fragmented_packets = {}
  fragmented_packets[0] = {}
  
  fragmented_packets[0][2]=packet_2
  fragmented_packets[0][1]=packet_1
  fragmented_packets[0][3]=packet_3
  
  assembled_data = b''.join(
            fragmented_packets[0][seq]
            for seq in sorted(fragmented_packets[0])
        )
  # test 1
  print(fragmented_packets)
  print(assembled_data)
  http_data = {}
  http_data['Status Line'] = "HTTP/1.0 200"
  
  # test2
  print(http_data)
  print(int(http_data['Status Line'].split()[1]))
  
  #  Test3
  header = "Content-Type: application/json\r\nContent-Length: 50\r\nConnection: keep-alive"
  headers = dict(line.split(': ', 1) for line in header.split('\r\n') if ': ' in line)
  print(headers) # {'Content-Type': 'application/json', 'Content-Length': '50', 'Connection': 'keep-alive'}
  print(int(headers.get("Content-Length", 0)))
test_()