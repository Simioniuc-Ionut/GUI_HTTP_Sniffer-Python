import json

def parse_nested_dict(d):
    """
    Recursively parse nested dictionaries.
    """
    parsed_dict = {}
    for key, value in d.items():
        if isinstance(value, dict):
            parsed_dict[key] = parse_nested_dict(value)
        else:
            parsed_dict[key] = value.replace('\n', '')
    return parsed_dict

def format_body(body_str):
    """
    Format the body string to remove escape characters.
    """
    try:
        body_json = json.loads(body_str)
        formatted_body = json.dumps(body_json, indent=4)
        return formatted_body
    except json.JSONDecodeError:
        return body_str

# Exemplu de utilizare
response_layer_data = {
    "Status Line": "HTTP/1.1 200 OK",
    "Headers": {
        "Date": "Wed, 18 Dec 2024 16:26:13 GMT",
        "Content-Type": "application/json",
        "Content-Length": "641",
        "Connection": "keep-alive",
        "Server": "gunicorn/19.9.0",
        "Access-Control-Allow-Origin": "http://httpbin.org",
        "Access-Control-Allow-Credentials": "true"
    },
    "Body": '{\n  "args": {}, \n  "data": "", \n  "files": {}, \n  "form": {}, \n  "headers": {\n    "Accept": "application/json", \n    "Accept-Encoding": "gzip, deflate", \n    "Accept-Language": "en-US,en;q=0.9,ro;q=0.8", \n    "Content-Length": "0", \n    "Host": "httpbin.org", \n    "Origin": "http://httpbin.org", \n    "Referer": "http://httpbin.org/", \n    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0", \n    "X-Amzn-Trace-Id": "Root=1-6762fa56-478402bc250b17854b8fe2a5"\n  }, \n  "json": null, \n  "origin": "37.251.223.139", \n  "url": "http://httpbin.org/put"\n}\n'
}

# Parse nested dictionaries
application_layer_packet = parse_nested_dict(response_layer_data)

# Format the body to remove escape characters


print(application_layer_packet)