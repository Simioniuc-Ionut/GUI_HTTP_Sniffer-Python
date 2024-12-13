import socket as socket
import struct as struct
import os
import ctypes
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

def main():
    # Create a IPV4 socket object
    s = socket.socket(
        socket.AF_INET,  # Address family
        socket.SOCK_RAW,
        socket.IPPROTO_IPV4)  # Use IPPROTO_TCP to capture TCP packets
    
    # Enable IP header include
    # s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    s.bind(('', 80))
    # Receive brute data
    while True:
        print("Received packet")
        packet, addr = s.recvfrom(65535)  # Use recvfrom to get data and address
        print(f"Received packet from {addr}")

if __name__ == '__main__':
    main2()

