# Global dictionary to store fragments by connection
fragmented_packets = {}


def find_body(bod_data) -> bytes:
    """
    Finds the start index of the "{" from body in the decoded data.
    
    Args:
    bod_data (str): The decoded HTTP response data.
    
    Returns:
    bytes: The HTTP body data.
    """
    start_index = -1
    for i in range(len(bod_data)):
        if bod_data[i] == '{':
            start_index = i
            break
        if bod_data[i:i+2] == 'ar':
            # add "{" in front of the args: {}
            bod_data = '{ ' + bod_data[i:]
            # print(bod_data)
            return bod_data
    
    if start_index == -1:
        raise ValueError("Failed to find a valid HTTP body")
    
    # Extract the HTTP body starting from the double CRLF delimiter
    body_data = bod_data[i:]
    return body_data

def test1_find_body():
    body_data=" >↑P↑n+ args : {}, ...}"
    print(find_body(body_data))

def test2_find_body():
    body_data=" >↑P↑n+{ args : {}, ...}"
    print(find_body(body_data))

# Run the test

test1_find_body()
test2_find_body()