import threading
import sniffest_service
import sniffest_GUI

# Here we share de packets between the GUI and the service
from shared_packets import packet_queue
from queue import Queue

def run_sniffest_service(packet_queue : Queue , stop_event : threading.Event):
    sniffest_service.sniffest_run(packet_queue, stop_event)

def run_sniffest_GUI(packet_queue : Queue, stop_event : threading.Event):
    sniffest_GUI.GUI_run(packet_queue, stop_event)

if __name__ == '__main__':
  
    # Create threads for sniffest_service and sniffest_GUI
    packet_queue = Queue()
    stop_event = threading.Event()
    
    service_thread = threading.Thread(target=run_sniffest_service , args = (packet_queue, stop_event, ))
    gui_thread = threading.Thread(target=run_sniffest_GUI, args = (packet_queue, stop_event,))

    # Start the threads
    service_thread.start()
    gui_thread.start()

    try:
      # Wait for both threads to complete
      service_thread.join()
      gui_thread.join()
    except Exception as e:
      print("Faild to stop threads " , e )
      