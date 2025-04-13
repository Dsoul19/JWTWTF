import base64
import json
import re
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time

JWT_REGEX = re.compile(r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+')

def base64url_decode(input_str):
    padding = '=' * (-len(input_str) % 4)  # pad to multiple of 4
    return base64.urlsafe_b64decode(input_str + padding)

def decode_jwt(jwt_token):
    try:
        header_b64, payload_b64, signature_b64 = jwt_token.split('.')
        header = json.loads(base64url_decode(header_b64).decode())
        payload = json.loads(base64url_decode(payload_b64).decode())

        return {
            'header': header,
            'payload': payload,
            'signature': signature_b64
        }
    except Exception as e:
        return {'error': f"Failed to decode JWT: {e}"}

def extract_jwt_selenium(url):
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    options.add_argument('--window-size=1920x1080')

    print("[*] Launching headless browser...")
    driver = webdriver.Chrome(options=options)
    print(f"[*] Visiting {url}")
    driver.get(url)

    time.sleep(5)  # Wait for JavaScript to load

    found_tokens = set()

    print("[*] Scanning page body...")
    page_text = driver.page_source
    body_matches = JWT_REGEX.findall(page_text)
    found_tokens.update(body_matches)

    print("[*] Scanning cookies...")
    cookies = driver.get_cookies()
    for cookie in cookies:
        if JWT_REGEX.match(cookie['value']):
            found_tokens.add(cookie['value'])

    print("[*] Scanning current URL...")
    if JWT_REGEX.search(driver.current_url):
        found_tokens.update(JWT_REGEX.findall(driver.current_url))

    driver.quit()
    return list(found_tokens)

def extract_jwt_requests_headers(url):
    try:
        print("[*] Checking headers using requests...")
        response = requests.get(url, timeout=10, verify=False)
        auth = response.headers.get("Authorization", "")
        if "Bearer " in auth:
            token = auth.split("Bearer ")[1]
            if JWT_REGEX.match(token):
                return [token]
    except Exception:
        pass
    return []

def pretty_print_json(obj):
    print(json.dumps(obj, indent=4, sort_keys=True))

if __name__ == "__main__":
    print("===[ Advanced JWT Extractor & Decoder ]===")
    target_url = input("Enter target URL: ").strip()

    all_tokens = set()

    # Extract via Selenium (Body, Cookies, URL)
    try:
        selenium_tokens = extract_jwt_selenium(target_url)
        all_tokens.update(selenium_tokens)
    except Exception as e:
        print(f"[!] Selenium extraction failed: {e}")

    # Extract from headers (requests)
    header_tokens = extract_jwt_requests_headers(target_url)
    all_tokens.update(header_tokens)

    if all_tokens:
        print(f"\n[+] Found {len(all_tokens)} JWT(s):\n")
        for idx, token in enumerate(all_tokens, 1):
            print(f"[{idx}] JWT: {token}")
            decoded = decode_jwt(token)
            if 'error' in decoded:
                print(f"    [-] Decode Error: {decoded['error']}")
            else:
                print("    [>] Header:")
                pretty_print_json(decoded['header'])
                print("    [>] Payload:")
                pretty_print_json(decoded['payload'])
                print("    [>] Signature (raw):", decoded['signature'][:20] + "...")
            print('-' * 60)
    else:
        print("[-] No JWT found in headers, cookies, body, or URL.")
