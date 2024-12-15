import unittest

def find_http_method(decoded_data):
    """
    Finds the start index of the HTTP method in the decoded data.
    
    Args:
    decoded_data (str): The decoded HTTP request data.
    
    Returns:
    dict: A dictionary containing the valid HTTP data or an error message.
    """
    start_index = -1
    for i in range(len(decoded_data)):
        if decoded_data[i:i+3] in ('GET', 'POS', 'HEA', 'PUT', 'DEL', 'OPT', 'PAT'):
            start_index = i
            break
    if start_index == -1:
        return {"Error": "Failed to find a valid HTTP request line"}
    
    # Extract the valid HTTP data starting from the Request Line
    valid_http_data = decoded_data[start_index:]
    return {"Valid HTTP Data": valid_http_data}

def find_http_status_line(decoded_data):
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
        return {"Error": "Failed to find a valid HTTP status line"}
    
    # Extract the valid HTTP data starting from the Status Line
    valid_http_data = decoded_data[start_index:]
    return {"Valid HTTP Data": valid_http_data}

def parse_http_headers_and_body(valid_http_data):
    """
    Parses the HTTP headers and body from the valid HTTP data.
    
    Args:
    valid_http_data (str): The valid HTTP data starting from the status line.
    
    Returns:
    dict: A dictionary containing the HTTP headers and body.
    """
    lines = valid_http_data.split('\r\n')
    
    # Initialize the dictionary to store the parsed data
    http_data = {}
    
    # The first line is the Status Line
    status_line = lines[0]
    http_data['Status Line'] = status_line
    
    # The rest are Header Fields until an empty line is encountered
    headers_end_index = 1
    for line in lines[1:]:
        if line == '':
            break
        key, value = line.split(': ', 1)
        http_data[key] = value
        headers_end_index += 1
    
    # Extract the body of the response
    body = '\r\n'.join(lines[headers_end_index+1:])
    if body:
        http_data['Body'] = body
    
    return http_data


class TestHTTPMethods(unittest.TestCase):
    def test_methods(self):
        methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'PATCH']
        for method in methods:
            with self.subTest(method=method):
                decoded_data = f"#<)P↑☻[{method} /path HTTP/1.1"
                result = find_http_method(decoded_data)
                self.assertNotIn("Error", result)
                self.assertTrue(result["Valid HTTP Data"].startswith(method))
    def test_find_http_status_line(self):
        decoded_data = "Some random data HTTP/1.1 200 OK\r\nHeader: value\r\n\r\nBody content"
        result = find_http_status_line(decoded_data)
        self.assertNotIn("Error", result)
        self.assertTrue(result["Valid HTTP Data"].startswith("HTTP"))

    def test_parse_http_headers_and_body(self):
        valid_http_data = "HTTP/1.1 200 OK\r\nHeader1: value1\r\nHeader2: value2\r\n\r\nBody content"
        result = parse_http_headers_and_body(valid_http_data)
        self.assertEqual(result['Status Line'], "HTTP/1.1 200 OK")
        self.assertEqual(result['Header1'], "value1")
        self.assertEqual(result['Header2'], "value2")
        self.assertEqual(result['Body'], "Body content")

if __name__ == "__main__":
    unittest.main()