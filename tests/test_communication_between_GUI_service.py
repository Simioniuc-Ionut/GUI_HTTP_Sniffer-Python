import time
from queue import Queue
import threading


packet_queue = Queue()


def anssemble_full_packet_and_send():
  """Capture artificial packets from the service"""
  packet_id = 0
  while True:
    packet = {
      "id": packet_id,
      "src_ip": f"192.168.0.{packet_id % 255}",
      "dst_ip": f"93.184.216.{packet_id % 255}",
      "protocol": "HTTP",
      "http_method": "GET",
      "timestamp": time.time(),
      "payload": "Sample payload data"
    }
    print(f"[Service] Captured packet: {packet}")
    packet_queue.put(packet)
    packet_id += 1
    time.sleep(1)  # Simulate time delay for packet capture

def sniffest_GUI_run():
  """Consume packets"""
  while True:
    try:
      packet = packet_queue.get(timeout=1)
      print(f"[GUI] Displaying packet: {packet}")
    except Queue.empty as e:
      print(f"[GUI] Waiting for packets...{e}")

# Create threads for packet production and consumption
producer_thread = threading.Thread(target=anssemble_full_packet_and_send)
consumer_thread = threading.Thread(target=sniffest_GUI_run)

# Start the threads
producer_thread.start()
consumer_thread.start()

# Join the threads to the main thread to keep the program running
producer_thread.join()
consumer_thread.join()
