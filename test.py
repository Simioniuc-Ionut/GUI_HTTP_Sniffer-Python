import unittest
import time
from main import parse_http_headers_and_body,find_http_status_line,find_http_method, HTTP_application_layer, HTTP_response_layer, cleanup_connection





class TestHTTPMethods(unittest.TestCase):
    def test_methods(self):
        methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'PATCH']
        for method in methods:
            with self.subTest(method=method):
                decoded_data = f"#<)P↑☻[{method} /path HTTP/1.1"
                result = find_http_method(decoded_data)
                self.assertNotIn("Error", result)
                self.assertTrue(result.startswith(method))
    def test_find_http_status_line(self):
        decoded_data = "Some random data HTTP/1.1 200 OK\r\nHeader: value\r\n\r\nBody content"
        result = find_http_status_line(decoded_data)
        self.assertNotIn("Error", result)
        self.assertTrue(result.startswith("HTTP"))

    def test_parse_http_headers_and_body(self):
        valid_http_data = "HTTP/1.1 200 OK\r\nHeader1: value1\r\nHeader2: value2\r\n\r\nBody content"
        result = parse_http_headers_and_body(valid_http_data)
        self.assertEqual(result['Status Line'], "HTTP/1.1 200 OK")
        self.assertEqual(result['Header1'], "value1")
        self.assertEqual(result['Header2'], "value2")
        self.assertEqual(result['Body'], "Body content")

class TestHTTPFragmentation(unittest.TestCase):
    def test_request_fragmentation(self):
        # Simulate a packeet fragmentation for a POST requests
        fragment1 = b"POST /post HTTP/1.1\r\nHost: httpbin.org\r\nConnection: keep-alive\r\n"
        fragment2 = b"Content-Length: 0\r\naccept: application/json\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        
        # Reassemble and parse
        result1 = HTTP_application_layer(fragment1, 12345, 80)
        result2 = HTTP_application_layer(fragment2, 12345, 80)
        
        # Verify if the request was reassembled correctly
        self.assertNotIn("Error", result1)
        self.assertNotIn("Error", result2)
        self.assertIn("Request Line", result2)
        self.assertEqual(result2["Request Line"], "POST /post HTTP/1.1")
        self.assertEqual(result2["Host"], "httpbin.org")
        self.assertEqual(result2["Content-Length"], "0")
        self.assertEqual(result2["accept"], "application/json")

    def test_response_fragmentation(self):
        # Simulate a packet fragmentation for a HTTP response
        fragment1 = b"HTTP/1.1 200 OK\r\nDate: Sun, 15 Dec 2024 18:07:32 GMT\r\nContent-Type: application/json\r\n"
        fragment2 = b"Content-Length: 642\r\nConnection: keep-alive\r\nServer: gunicorn/19.9.0\r\n\r\n"
        fragment3 = b'{"args": {}, "data": "", "files": {}, "form": {}, "headers": {"Accept": "application/json"}}'
        
        # Reasaemble and parse
        result1 = HTTP_response_layer(fragment1, 80, 12345)
        result2 = HTTP_response_layer(fragment2, 80, 12345)
        result3 = HTTP_response_layer(fragment3, 80, 12345)
        
        # Verify the response headers and body were reassembled correctly
        self.assertNotIn("Error", result1)
        self.assertNotIn("Error", result2)
        self.assertNotIn("Error", result3)
        self.assertIn("Status Line", result3)
        self.assertEqual(result3["Status Line"], "HTTP/1.1 200 OK")
        self.assertEqual(result3["Content-Length"], "642")
        self.assertEqual(result3["Server"], "gunicorn/19.9.0")
        self.assertIn("Body", result3)
        self.assertTrue(result3["Body"].startswith('{"args":'))
    def setUp(self):
        # Reset fragmented packets before each test
        global fragmented_packets
        fragmented_packets = {}

    def test_fragmentation_with_fin_flag(self):
        # Simulate fragmented packets for a POST request
        fragment1 = b"POST /post HTTP/1.1\r\nHost: httpbin.org\r\nConnection: keep-alive\r\n"
        fragment2 = b"Content-Length: 0\r\naccept: application/json\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        
        # Reassemble and parse
        result1 = HTTP_application_layer(fragment1, 12345, 80)
        result2 = HTTP_application_layer(fragment2, 12345, 80)
        
        # Verify if the request was reassembled correctly
        self.assertNotIn("Error", result1)
        self.assertNotIn("Error", result2)
        self.assertIn("Request Line", result2)
        self.assertEqual(result2["Request Line"], "POST /post HTTP/1.1")
        self.assertEqual(result2["Host"], "httpbin.org")
        self.assertEqual(result2["Content-Length"], "0")
        self.assertEqual(result2["accept"], "application/json")

        # Simulate receiving the FIN flag
        cleanup_connection(12345, 80)
        self.assertNotIn((12345, 80), fragmented_packets)

    def test_fragmentation_with_rst_flag(self):
        # Simulate fragmented packets for an HTTP response
        fragment1 = b"HTTP/1.1 200 OK\r\nDate: Sun, 15 Dec 2024 18:07:32 GMT\r\nContent-Type: application/json\r\n"
        fragment2 = b"Content-Length: 642\r\nConnection: keep-alive\r\nServer: gunicorn/19.9.0\r\n\r\n"
        fragment3 = b'{"args": {}, "data": "", "files": {}, "form": {}, "headers": {"Accept": "application/json"}}'
        
        # Reassemble and parse
        result1 = HTTP_response_layer(fragment1, 80, 12345)
        result2 = HTTP_response_layer(fragment2, 80, 12345)
        result3 = HTTP_response_layer(fragment3, 80, 12345)
        
        # Verify if the response was reassembled correctly
        self.assertNotIn("Error", result1)
        self.assertNotIn("Error", result2)
        self.assertNotIn("Error", result3)
        self.assertIn("Status Line", result3)
        self.assertEqual(result3["Status Line"], "HTTP/1.1 200 OK")
        self.assertEqual(result3["Content-Length"], "642")
        self.assertEqual(result3["Server"], "gunicorn/19.9.0")
        self.assertIn("Body", result3)
        self.assertTrue(result3["Body"].startswith('{"args":'))

        # Simulate receiving the RST flag
        cleanup_connection(80, 12345)
        self.assertNotIn((80, 12345), fragmented_packets)
    


if __name__ == "__main__":
    unittest.main()