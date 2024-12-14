# GUI_HTTP_Sniffer-Python

Implementați o aplicație care implementează un sniffer de pachete HTTP. Aplicația ar
trebui să permită vizualizarea real-time a requesturilor, aplicarea de filtre pe traficul de
pachete (ex: requesturi venite de la o anumită adresă, requesturi de anumite tipuri:
GET/POST/DELETE s.a.m.d). Totodată, pentru un anume request, ar trebuie ca

userul să poată afla detalii despre requestul respectiv: headers, request mode,
payload, etc
Nu este necesar un GUI (datele se pot afișa și în consola).Trebuie sa fie totuși o
reprezentare clară a acestor date (sa se inteleaga ce anume reprezinta).
Traficul se capturează cu ajutorul bibliotecii socket iar decodarea pachetelor se va
face cu struct/ctypes

## Resources
### Socket - Library
-https://docs.python.org/3/library/socket.html#socket-families
### Ethernet Frame Format
-https://www.geeksforgeeks.org/ethernet-frame-format/
### OSI Model - 7 Layers
-https://www.geeksforgeeks.org/open-systems-interconnection-model-osi/
### TCP/IP Model - 4 Layers
-https://www.geeksforgeeks.org/tcp-ip-model/
### TCP/IP Format
-https://www.geeksforgeeks.org/tcp-ip-packet-format/
### Struct - Library
-https://docs.python.org/3/library/struct.html#struct.pack

[ Ethernet Frame ]
| Destination MAC Address (6 bytes) | Source MAC Address (6 bytes) | Protocol Type (2 bytes) |
|---------------------------------------------------------------------------|
|                 Payload (rest of the frame)                        |

[ IP Header ] 
| Version | IHL | Type of Service | Total Length | Identification | Flags | Fragment Offset |
| Time to Live | Protocol | Header Checksum | Source IP | Destination IP |

[ TCP Header ]
| Source Port | Destination Port | Sequence Number | Acknowledgment Number | Data Offset |
| Reserved | Flags | Window | Checksum | Urgent Pointer |

[ HTTP Request (Payload) ]
| Method (GET, POST, etc.) | URL | HTTP Version |
| Headers: Host, User-Agent, etc. |
| Body (if applicable) |


<img src = "imgs\Network-Layer-ipv4.png">
<img src = "imgs\Network-Layer-ipv6.png">
<img src = "imgs/Transport-TCP-Layer.png">
<img src = "imgs/Transport-UDP-Layer.png">
<img src = "imgs/Application-Layer.png">