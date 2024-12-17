import threading
import sniffest_service
import sniffest_GUI

def run_sniffest_service():
    sniffest_service.sniffest_run()

def run_sniffest_GUI():
    sniffest_GUI.run()

if __name__ == '__main__':
    # Create threads for sniffest_service and sniffest_GUI
    service_thread = threading.Thread(target=run_sniffest_service)
    gui_thread = threading.Thread(target=run_sniffest_GUI)

    # Start the threads
    service_thread.start()
    gui_thread.start()

    # Wait for both threads to complete
    service_thread.join()
    gui_thread.join()