import requests
import argparse
from requests.exceptions import RequestException, ConnectionError, Timeout

# common SQL error signatures to look for
SQL_ERROR_SIGNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax",
    "mysql",
    "syntax error",
    "odbc",
    "psql",
    "sqlite3"
]

def is_sql_error(body_text):
    t = body_text.lower()
    for sig in SQL_ERROR_SIGNS:
        if sig in t:
            return True
    return False

def test_xss(url, param, timeout=6):
    payload = "<script>alert(1)</script>"
    try:
        r = requests.get(url, params={param: payload}, timeout=timeout)
        print(f"[DEBUG] GET {r.url} -> {r.status_code}")
        if r.status_code != 200:
            print(f"[WARN] Received status {r.status_code} for {r.url}")
        if payload in r.text:
            print(f"[!] Possible REFLECTED XSS at: {r.url}")
        else:
            print(f"[-] No reflected XSS detected at: {r.url}")
    except ConnectionError:
        print(f"[ERROR] Could not connect to {url}. Is the webapp running and is the URL/port correct?")
    except Timeout:
        print(f"[ERROR] Request to {url} timed out after {timeout}s.")
    except RequestException as e:
        print(f"[ERROR] Request failed: {e}")

def test_sqli(url, param, timeout=6):
    payload = "' OR '1'='1"
    try:
        r = requests.get(url, params={param: payload}, timeout=timeout)
        print(f"[DEBUG] GET {r.url} -> {r.status_code}")
        if r.status_code != 200:
            print(f"[WARN] Received status {r.status_code} for {r.url}")
        body = r.text

        if is_sql_error(body):
            print(f"[!] Possible SQLi (DB error signature) at: {r.url}")
            return

        try:
            r2 = requests.get(url, params={param: ""}, timeout=timeout)
            if abs(len(r.text) - len(r2.text)) > 200:  
                print(f"[!] Possible SQLi (response length difference) at: {r.url}")
                return
        except Exception:
            pass

        print(f"[-] No obvious SQLi detected at: {r.url}")
    except ConnectionError:
        print(f"[ERROR] Could not connect to {url}. Is the webapp running and is the URL/port correct?")
    except Timeout:
        print(f"[ERROR] Request to {url} timed out after {timeout}s.")
    except RequestException as e:
        print(f"[ERROR] Request failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Simple vuln scanner: XSS + basic SQLi checks")
    parser.add_argument("url", help="Target base URL (e.g. http://127.0.0.1:3000/page.php)")
    parser.add_argument("param", help="Parameter name to inject (e.g. id or q)")
    parser.add_argument("--timeout", type=int, default=6, help="Request timeout in seconds")
    args = parser.parse_args()

    print("[*] Testing for Reflected XSS...")
    test_xss(args.url, args.param, timeout=args.timeout)

    print("[*] Testing for SQL Injection...")
    test_sqli(args.url, args.param, timeout=args.timeout)

if __name__ == "__main__":
    main()
