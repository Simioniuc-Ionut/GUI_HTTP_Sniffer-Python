import unittest
import sys
import os


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sniffest_service import cleanup_connection, find_http_status_line

fragmented_packets = {}

def process_tcp_segment(data: bytes, src_port: int, dst_port: int, seq_number: int):
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
    global fragmented_packets
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

    # Parse the header
    header = decoded_data[:header_end_index]
    body = decoded_data[header_end_index + 4:]

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


# Simiulate send data
class TestReasembleHTTPResponseLayer(unittest.TestCase):

    def simulate_data_transfer(self):
        src_port = 12345
        dst_port = 80
        response_fragments = [
            b"HTTP/1.1 200 OK\r\nDate: Tue, 17 Dec 2024 13:41:28 GMT\r\nContent-Type: application/json\r\nContent-Length: 62\r\nConnection: keep-alive\r\nServer: gunicorn/19.9.0\r\n\r\n",
            b'{"args": {}, "data": "", "files": {}, "form": {}, "headers": {'
        ]
        seq_num = 0
        for fragment in response_fragments:
            result = process_tcp_segment(fragment, src_port, dst_port, seq_num)
            print("result ", result)
            seq_num += 1

    def test_http_response_layer(self):
        global fragmented_packets
        fragmented_packets = {}

        # Simulate fragmented HTTP response
        packet_1 = b"HTTP/1.1 200 OK\r\nContent-Length: 28\r\n\r\nargs: {}"
        packet_2 = b" , response"
        packet_3 = b" part two"
        print("Total length", (len(packet_1) + len(packet_2) + len(packet_3)))
        # Inject packets in an incorrect order

        response_1 = process_tcp_segment(packet_1, 12345, 80, 1)
        response_2 = process_tcp_segment(packet_2, 12345, 80, 2)

        # Reassemble and return the final response
        final_response = process_tcp_segment(packet_3, 12345, 80, 3)
        print("Final Assembled Response:", final_response)

        # Test with corrupted body
        # packet_with_corruption = b"]>&sGP\x91nhargs: {}\r\nAnother-Key: Value\r\n\r\nBody content here."
        # corrupted_response = process_tcp_segment(packet_with_corruption, 54321, 80, 1)
        # print("Corrupted Response:", corrupted_response)

    def test_simulate_data_transfer(self):
        print("Test1--------------------------------")
        self.simulate_data_transfer()
        print("Test2-----")
        self.test_http_response_layer()
        # Add assertions here to validate the results


if __name__ == '__main__':
    print("size",len(b'{"args": {}, "data": "", "files": {}, "form": {}, "headers": {'))
    unittest.main()