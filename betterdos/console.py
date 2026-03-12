"""Interactive tools console (DSTAT, INFO, PING, CHECK, CFIP, DNS, etc.)."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from ipaddress import ip_address, ip_network
from socket import AF_INET, IPPROTO_TCP, SOCK_RAW, gethostbyname, gethostname, socket
from time import sleep
from typing import Dict, List, Set, Tuple

from dns import resolver
from icmplib import ping
from psutil import cpu_percent, net_io_counters, process_iter, virtual_memory
from requests import get

from betterdos.core import Tools, bcolors, exit, logger


class ToolsConsole:
    METHODS = {"INFO", "TSSRV", "CFIP", "DNS", "PING", "CHECK", "DSTAT"}

    @staticmethod
    def checkRawSocket():
        with suppress(OSError):
            with socket(AF_INET, SOCK_RAW, IPPROTO_TCP):
                return True
        return False

    @staticmethod
    def runConsole(initial_args=None):
        """Launch the interactive tools console.

        Args:
            initial_args: Optional list like ["CFIP", "example.com"] to run
                          a single tool directly and then exit.
        """
        cons = "tools> "

        # If called with arguments (e.g. start.py TOOLS CFIP example.com),
        # run that single command and return instead of looping.
        if initial_args:
            cmd = initial_args[0].upper()
            args = " ".join(initial_args[1:]) if len(initial_args) > 1 else ""
            if cmd in ToolsConsole.METHODS:
                ToolsConsole._run_tool(cmd, args)
            else:
                print(f"Unknown tool: {cmd}")
                print("Available: " + ", ".join(sorted(ToolsConsole.METHODS)))
            return

        print("BetterDoS Tools Console")
        print("  Available tools: " + ", ".join(sorted(ToolsConsole.METHODS)))
        print("  Type a tool name, or TOOL <domain/ip> to run directly.")
        print("  Type HELP, CLEAR, or EXIT.")
        print()

        while 1:
            cmd = input(cons).strip()
            if not cmd:
                continue
            args = ""
            if " " in cmd:
                cmd, args = cmd.split(" ", 1)

            cmd = cmd.upper()
            if cmd == "HELP":
                print("Available tools: " + ", ".join(sorted(ToolsConsole.METHODS)))
                print("Usage: <TOOL> [domain/ip]  — e.g. CFIP example.com")
                print("Commands: HELP, CLEAR, EXIT")
                continue

            if {cmd} & {"E", "EXIT", "Q", "QUIT", "LOGOUT", "CLOSE", "BACK"}:
                return

            if cmd == "CLEAR":
                print("\033c")
                continue

            if cmd not in ToolsConsole.METHODS:
                print(f"{cmd}: not found. Type HELP to list tools.")
                continue

            if cmd == "DSTAT":
                with suppress(KeyboardInterrupt):
                    ld = net_io_counters(pernic=False)
                    while True:
                        sleep(1)
                        od = ld
                        ld = net_io_counters(pernic=False)
                        t = [(last - now) for now, last in zip(od, ld)]
                        logger.info(
                            ("Bytes Sent %s\n"
                             "Bytes Received %s\n"
                             "Packets Sent %s\n"
                             "Packets Received %s\n"
                             "ErrIn %s\n"
                             "ErrOut %s\n"
                             "DropIn %s\n"
                             "DropOut %s\n"
                             "Cpu Usage %s\n"
                             "Memory %s\n") %
                            (Tools.humanbytes(t[0]), Tools.humanbytes(t[1]),
                             Tools.humanformat(t[2]), Tools.humanformat(t[3]),
                             t[4], t[5], t[6], t[7], str(cpu_percent()) + "%",
                             str(virtual_memory().percent) + "%"))

            ToolsConsole._run_tool(cmd, args)

    @staticmethod
    def _run_tool(cmd, args=""):
        """Execute a single tool command. If *args* is provided, run once;
        otherwise enter an interactive loop for that tool."""

        def _get_input(prompt):
            """Read from the interactive sub-prompt, handling BACK/EXIT."""
            while True:
                val = input(prompt).strip()
                if not val:
                    continue
                if val.upper() in {"BACK", "B"}:
                    return None
                if val.upper() in {"E", "EXIT", "Q", "QUIT"}:
                    return None
                if val.upper() == "CLEAR":
                    print("\033c")
                    continue
                return val

        def _clean_domain(d):
            d = d.replace('https://', '').replace('http://', '')
            if '/' in d:
                d = d.split('/')[0]
            return d

        if cmd == "DSTAT":
            with suppress(KeyboardInterrupt):
                ld = net_io_counters(pernic=False)
                while True:
                    sleep(1)
                    od = ld
                    ld = net_io_counters(pernic=False)
                    t = [(last - now) for now, last in zip(od, ld)]
                    logger.info(
                        ("Bytes Sent %s\n"
                         "Bytes Received %s\n"
                         "Packets Sent %s\n"
                         "Packets Received %s\n"
                         "ErrIn %s\n"
                         "ErrOut %s\n"
                         "DropIn %s\n"
                         "DropOut %s\n"
                         "Cpu Usage %s\n"
                         "Memory %s\n") %
                        (Tools.humanbytes(t[0]), Tools.humanbytes(t[1]),
                         Tools.humanformat(t[2]), Tools.humanformat(t[3]),
                         t[4], t[5], t[6], t[7], str(cpu_percent()) + "%",
                         str(virtual_memory().percent) + "%"))
            return

        if cmd == "CFIP":
            targets = [_clean_domain(args)] if args else []
            while True:
                domain = targets.pop(0) if targets else _get_input("cfip> domain: ")
                if domain is None:
                    break
                domain = _clean_domain(domain)
                logger.info("Scanning for origin IP behind Cloudflare ...")
                results = CloudflareScanner.find_origin(domain)
                CloudflareScanner.print_results(domain, results)
                if args:
                    break

        elif cmd == "DNS":
            targets = [_clean_domain(args)] if args else []
            while True:
                domain = targets.pop(0) if targets else _get_input("dns> domain: ")
                if domain is None:
                    break
                domain = _clean_domain(domain)
                logger.info("Querying DNS records ...")
                ToolsConsole.dns_lookup(domain)
                if args:
                    break

        elif cmd == "CHECK":
            targets = [args] if args else []
            while True:
                url = targets.pop(0) if targets else _get_input("check> url: ")
                if url is None:
                    break
                with suppress(Exception):
                    if '/' not in url:
                        url = 'http://' + url
                    with get(url, timeout=20) as r:
                        status = "ONLINE" if r.status_code <= 500 else "OFFLINE"
                        logger.info(f"status_code: {r.status_code}\nstatus: {status}")
                if args:
                    break

        elif cmd == "INFO":
            targets = [_clean_domain(args)] if args else []
            while True:
                domain = targets.pop(0) if targets else _get_input("info> ip/domain: ")
                if domain is None:
                    break
                domain = _clean_domain(domain)
                print('please wait ...', end="\r")
                info = ToolsConsole.info(domain)
                if not info["success"]:
                    print("Error!")
                else:
                    logger.info(("Country: %s\n"
                                 "City: %s\n"
                                 "Org: %s\n"
                                 "Isp: %s\n"
                                 "Region: %s\n") %
                                (info["country"], info["city"], info["org"],
                                 info["isp"], info["region"]))
                if args:
                    break

        elif cmd == "TSSRV":
            targets = [_clean_domain(args)] if args else []
            while True:
                domain = targets.pop(0) if targets else _get_input("tssrv> domain: ")
                if domain is None:
                    break
                domain = _clean_domain(domain)
                print('please wait ...', end="\r")
                info = ToolsConsole.ts_srv(domain)
                logger.info(f"TCP: {(info['_tsdns._tcp.'])}\n")
                logger.info(f"UDP: {(info['_ts3._udp.'])}\n")
                if args:
                    break

        elif cmd == "PING":
            targets = [_clean_domain(args)] if args else []
            while True:
                domain = targets.pop(0) if targets else _get_input("ping> ip/domain: ")
                if domain is None:
                    break
                domain = _clean_domain(domain)
                logger.info("please wait ...")
                r = ping(domain, count=5, interval=0.2)
                logger.info(('Address: %s\n'
                             'Ping: %d\n'
                             'Accepted Packets: %d/%d\n'
                             'status: %s\n') %
                            (r.address, r.avg_rtt, r.packets_received,
                             r.packets_sent,
                             "ONLINE" if r.is_alive else "OFFLINE"))
                if args:
                    break

    @staticmethod
    def stop():
        print('All Attacks has been Stopped !')
        for proc in process_iter():
            if proc.name() == "python.exe":
                proc.kill()

    @staticmethod
    def ts_srv(domain):
        records = ['_ts3._udp.', '_tsdns._tcp.']
        DnsResolver = resolver.Resolver()
        DnsResolver.timeout = 1
        DnsResolver.lifetime = 1
        Info = {}
        for rec in records:
            try:
                srv_records = resolver.resolve(rec + domain, 'SRV')
                for srv in srv_records:
                    Info[rec] = str(srv.target).rstrip('.') + ':' + str(srv.port)
            except Exception:
                Info[rec] = 'Not found'
        return Info

    @staticmethod
    def info(domain):
        with suppress(Exception), get(f"https://ipwhois.app/json/{domain}/") as s:
            return s.json()
        return {"success": False}

    @staticmethod
    def dns_lookup(domain):
        """Query and display common DNS record types for a domain."""
        C, R, Y, B = bcolors.OKCYAN, bcolors.RESET, bcolors.WARNING, bcolors.OKBLUE
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
        res = resolver.Resolver()
        res.timeout = 3
        res.lifetime = 3
        for rtype in record_types:
            with suppress(Exception):
                answers = res.resolve(domain, rtype)
                for rdata in answers:
                    print(f"  {C}{rtype:<8}{R} {B}{rdata.to_text()}{R}")


# ── Cloudflare IP ranges (used for detection) ────────────────────────────
# https://www.cloudflare.com/ips-v4/  +  https://www.cloudflare.com/ips-v6/
_CF_RANGES = [
    # IPv4
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # IPv6
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
    "2c0f:f248::/32",
]
_CF_NETWORKS = [ip_network(r) for r in _CF_RANGES]


def _is_cloudflare_ip(ip_str: str) -> bool:
    """Return True if the IP belongs to a known Cloudflare range."""
    with suppress(ValueError):
        addr = ip_address(ip_str)
        return any(addr in net for net in _CF_NETWORKS)
    return False


class CloudflareScanner:
    """Discover origin IPs behind Cloudflare via DNS enumeration.

    Techniques:
    1. Direct A/AAAA resolution - check if the apex is even on CF.
    2. Common subdomain enumeration - many subdomains (mail, ftp, cpanel,
       direct, etc.) are not proxied through CF and expose the origin.
    3. MX record inspection - mail servers often point at the origin.
    4. SPF/TXT record parsing - SPF includes may leak origin IPs.
    5. NS record check - some self-hosted NS reveal origin.
    """

    # Subdomains commonly left outside of CF proxy
    PROBE_SUBDOMAINS = [
        "direct", "origin", "mail", "webmail", "email", "smtp", "pop",
        "pop3", "imap", "ftp", "cpanel", "whm", "webdisk", "autodiscover",
        "autoconfig", "staging", "stage", "dev", "api", "m", "mobile",
        "old", "legacy", "test", "admin", "panel", "cms", "blog",
        "shop", "store", "vpn", "remote", "ssh", "ns1", "ns2",
        "dns", "dns1", "dns2", "mx", "mx1", "mx2", "server",
        "host", "gateway", "backend", "internal", "intranet",
        "db", "database", "media", "static", "cdn", "assets",
        "img", "images", "files", "download", "uploads",
    ]

    @staticmethod
    def find_origin(domain: str) -> Dict[str, List[Tuple[str, str]]]:
        """Run all enumeration techniques and return categorized results.

        Returns dict with keys: 'apex', 'subdomains', 'mx', 'spf'
        Each value is a list of (source_label, ip) tuples.
        """
        results: Dict[str, List[Tuple[str, str]]] = {
            "apex": [],
            "subdomains": [],
            "mx": [],
            "spf": [],
        }
        res = resolver.Resolver()
        res.timeout = 3
        res.lifetime = 3

        # 1. Apex A records
        with suppress(Exception):
            for rdata in res.resolve(domain, "A"):
                ip = rdata.to_text()
                results["apex"].append((domain, ip))

        # 2. MX records -> resolve to IPs
        with suppress(Exception):
            for rdata in res.resolve(domain, "MX"):
                mx_host = str(rdata.exchange).rstrip(".")
                with suppress(Exception):
                    mx_ip = gethostbyname(mx_host)
                    results["mx"].append((mx_host, mx_ip))

        # 3. SPF / TXT records -> extract ip4: and include: directives
        with suppress(Exception):
            for rdata in res.resolve(domain, "TXT"):
                txt = rdata.to_text().strip('"')
                if "v=spf1" in txt.lower():
                    for token in txt.split():
                        if token.lower().startswith("ip4:"):
                            ip_part = token[4:]
                            if "/" in ip_part:
                                results["spf"].append(("SPF ip4 range", ip_part))
                            else:
                                results["spf"].append(("SPF ip4", ip_part))
                        elif token.lower().startswith("include:"):
                            inc_domain = token[8:]
                            with suppress(Exception):
                                inc_ip = gethostbyname(inc_domain)
                                results["spf"].append((f"SPF include:{inc_domain}", inc_ip))

        # 4. Subdomain enumeration (parallel)
        def _probe_sub(sub: str):
            fqdn = f"{sub}.{domain}"
            with suppress(Exception):
                ip = gethostbyname(fqdn)
                if not _is_cloudflare_ip(ip):
                    return (fqdn, ip)
            return None

        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {pool.submit(_probe_sub, s): s
                       for s in CloudflareScanner.PROBE_SUBDOMAINS}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    results["subdomains"].append(result)

        return results

    @staticmethod
    def is_behind_cloudflare(domain: str) -> bool:
        """Quick check: does the domain A record resolve to a CF IP?"""
        with suppress(Exception):
            ip = gethostbyname(domain)
            return _is_cloudflare_ip(ip)
        return False

    @staticmethod
    def print_results(domain: str, results: Dict[str, List[Tuple[str, str]]]):
        """Pretty-print CFIP scan results."""
        C = bcolors.OKCYAN
        B = bcolors.OKBLUE
        R = bcolors.RESET
        Y = bcolors.WARNING
        G = bcolors.OKGREEN
        F = bcolors.FAIL
        U = bcolors.BOLD

        apex_ips = [ip for _, ip in results["apex"]]
        on_cf = any(_is_cloudflare_ip(ip) for ip in apex_ips)

        cf_label = (F + "YES" + R) if on_cf else (G + "NO" + R)
        apex_str = (C + ", ".join(apex_ips) + R) if apex_ips else "none"

        print()
        print(U + "\u250c\u2500\u2500\u2500 CFIP Results "
              "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
              "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
              "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
              "\u2500\u2500\u2500\u2500\u2510" + R)
        print(f"{Y}\u2502{R} Domain     : {B}{domain}{R}")
        print(f"{Y}\u2502{R} Apex IPs   : {apex_str}")
        print(f"{Y}\u2502{R} Cloudflare : {cf_label}")
        print(f"{Y}\u2502{R}")

        # Non-CF IPs found
        origin_candidates: Set[str] = set()

        for category, label in [("subdomains", "Subdomain Enumeration"),
                                ("mx", "MX Records"),
                                ("spf", "SPF / TXT Records")]:
            entries = results[category]
            if entries:
                print(f"{Y}\u2502{R} {U}{label}:{R}")
                for source, ip in entries:
                    is_cf = _is_cloudflare_ip(ip)
                    if is_cf:
                        tag = F + "[CF]" + R
                    else:
                        tag = G + "[ORIGIN?]" + R
                    print(f"{Y}\u2502{R}   {C}{source:<40}{R} \u2192 {B}{ip:<16}{R} {tag}")
                    if not is_cf:
                        origin_candidates.add(ip)
                print(f"{Y}\u2502{R}")

        if origin_candidates:
            print(f"{Y}\u2502{R} {U}{G}Candidate origin IPs:{R}")
            for ip in sorted(origin_candidates):
                print(f"{Y}\u2502{R}   {G}{ip}{R}")
        elif on_cf:
            print(f"{Y}\u2502{R} {F}No non-Cloudflare IPs found via enumeration.{R}")
            print(f"{Y}\u2502{R} {Y}Try historical DNS databases or certificate transparency logs.{R}")
        else:
            print(f"{Y}\u2502{R} {G}Domain does not appear to be behind Cloudflare.{R}")

        print(U + "\u2514" + "\u2500" * 51 + "\u2518" + R)
