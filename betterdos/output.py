"""Pretty-printed output — banner, tables, progress bars."""

import shutil

from betterdos.core import Methods, Tools, bcolors, logger, RUN_ID

# ── Method descriptions (shared by help and docs) ────────────────────────
L7_DESCRIPTIONS = {
    "GET":        "HTTP GET flood",
    "POST":       "HTTP POST flood with JSON body",
    "HEAD":       "HTTP HEAD request flood",
    "PPS":        "Minimal GET — max packets-per-second",
    "EVEN":       "GET flood with recv() back-pressure",
    "OVH":        "OVH-optimized GET flood (short burst)",
    "STRESS":     "Large-body POST flood (512 B payload)",
    "COOKIE":     "Random cookie header flood",
    "NULL":       "Null User-Agent flood",
    "DYN":        "Random subdomain generation flood",
    "RHEX":       "Random hex path flood",
    "STOMP":      "chk_captcha path + hex host flood",
    "DOWNLOADER": "Slow data-read (drains server TX)",
    "SLOW":       "Slowloris — hold connections open",
    "BOT":        "Search-engine bot impersonation",
    "GSB":        "Google Project Shield bypass",
    "DGB":        "DDoS-Guard cookie bypass",
    "AVB":        "ArvanCloud rate-limit bypass",
    "CFB":        "Cloudflare JS-challenge bypass",
    "CFBUAM":     "Cloudflare Under-Attack-Mode bypass",
    "BYPASS":     "Generic anti-DDoS session bypass",
    "APACHE":     "Apache Range header exploit",
    "XMLRPC":     "WordPress XML-RPC pingback exploit",
    "BOMB":       "Bombardier-based high-concurrency flood",
    "KILLER":     "Recursive thread-spawn flood",
    "TOR":        "Onion site flood via tor2web gateways",
}

L4_DESCRIPTIONS = {
    "TCP":          "Raw TCP byte flood",
    "UDP":          "Raw UDP byte flood",
    "SYN":          "TCP SYN flood (raw socket)",
    "ICMP":         "ICMP echo-request flood (raw socket)",
    "OVH-UDP":      "OVH/WAF bypass crafted UDP flood",
    "CPS":          "Connections-per-second (open/close)",
    "CONNECTION":    "Keep-alive connection hold",
    "VSE":          "Valve Source Engine query flood",
    "TS3":          "TeamSpeak 3 status ping flood",
    "FIVEM":        "FiveM getinfo query flood",
    "FIVEM-TOKEN":  "FiveM token flood",
    "MINECRAFT":    "Minecraft status ping flood",
    "MCPE":         "Minecraft PE status flood",
    "MCBOT":        "Minecraft bot login flood",
    "MEM":          "Memcached amplification",
    "NTP":          "NTP monlist amplification",
    "DNS":          "DNS ANY amplification",
    "CHAR":         "Chargen amplification",
    "CLDAP":        "CLDAP amplification",
    "ARD":          "Apple Remote Desktop amplification",
    "RDP":          "RDP amplification",
}

TOOL_DESCRIPTIONS = {
    "INFO":   "WHOIS / GeoIP target lookup",
    "CFIP":   "Discover origin IP behind Cloudflare",
    "DNS":    "DNS record lookup",
    "TSSRV":  "TeamSpeak SRV record resolver",
    "PING":   "ICMP ping check",
    "CHECK":  "HTTP status check",
    "DSTAT":  "Live network I/O + CPU/RAM monitor",
}


def _term_width() -> int:
    return min(shutil.get_terminal_size((80, 24)).columns, 100)


def banner():
    """Print startup banner."""
    n_methods = len(Methods.ALL_METHODS)
    print(f"""
{bcolors.OKCYAN}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   {bcolors.BOLD}BetterDoS{bcolors.RESET}{bcolors.OKCYAN}  ·  Network Resilience Testing Framework          ║
║   v3.0  ·  {n_methods} attack methods  ·  7 tools  ·  5 commands     ║
║                                                              ║
║   {bcolors.RESET}{bcolors.WARNING}Research use only — authorized targets in lab environments{bcolors.RESET}{bcolors.OKCYAN}  ║
╚══════════════════════════════════════════════════════════════╝{bcolors.RESET}
""")


def usage(script_name: str = "start.py"):
    """Print structured help with method descriptions."""
    W = _term_width()
    C, B, R, Y, G, U = (bcolors.OKCYAN, bcolors.OKBLUE, bcolors.RESET,
                         bcolors.WARNING, bcolors.OKGREEN, bcolors.BOLD)
    hr = f"{Y}{'─' * W}{R}"

    print(f"""
{U}USAGE{R}
{hr}

  {G}Research commands{R}
    python3 {script_name} ADVISE  <url|ip:port>                  Fingerprint target, recommend methods
    python3 {script_name} AUTO    <url|ip:port> [options]         Benchmark all candidates, rank by PPS

  {G}Layer 7 (HTTP){R}
    python3 {script_name} <method> <url> <proxy_type> <threads> <proxy_file> <rpc> <duration>

  {G}Layer 4 (Transport){R}
    python3 {script_name} <method> <ip:port> <threads> <duration>
    python3 {script_name} <method> <ip:port> <threads> <duration> <proxy_type> <proxy_file>

  {G}Amplification (L4){R}      {Y}requires raw sockets & reflector file{R}
    python3 {script_name} <method> <ip:port> <threads> <duration> <reflector_file>

  {G}Utility{R}
    python3 {script_name} HELP              Show this help screen
    python3 {script_name} TOOLS             Interactive reconnaissance console
    python3 {script_name} STOP              Kill all running attack processes
""")

    # AUTO options detail
    print(f"""{U}AUTO OPTIONS{R}
{hr}
    python3 {script_name} AUTO <target> [threads] [probe_sec] [rpc] [proxy_type] [proxy_file]

    {C}threads{R}      Worker threads per method probe           (default: 5)
    {C}probe_sec{R}    Seconds to run each method probe          (default: 10)
    {C}rpc{R}          Requests per connection per probe          (default: 5)
    {C}proxy_type{R}   0=all  1=HTTP  4=SOCKS4  5=SOCKS5  6=rand (default: 0)
    {C}proxy_file{R}   Filename inside files/proxies/             (optional)
""")

    # Proxy types
    print(f"""{U}PROXY TYPES{R}
{hr}
    {C}0{R}  All from config.json       {C}4{R}  SOCKS4
    {C}1{R}  HTTP                        {C}5{R}  SOCKS5
    {C}6{R}  Random (4/5/1)
""")

    # L7 methods table
    print(f"{U}LAYER 7 METHODS ({len(L7_DESCRIPTIONS)}){R}")
    print(hr)
    for name in sorted(L7_DESCRIPTIONS):
        desc = L7_DESCRIPTIONS[name]
        print(f"    {C}{name:<14}{R} {desc}")
    print()

    # L4 methods table
    print(f"{U}LAYER 4 METHODS ({len(L4_DESCRIPTIONS)}){R}")
    print(hr)
    for name in sorted(L4_DESCRIPTIONS):
        desc = L4_DESCRIPTIONS[name]
        tag = ""
        if name in Methods.LAYER4_AMP:
            tag = f"  {Y}(amplification){R}"
        elif name in {"SYN", "ICMP"}:
            tag = f"  {Y}(raw socket){R}"
        print(f"    {C}{name:<14}{R} {desc}{tag}")
    print()

    # Tools table
    print(f"{U}TOOLS (interactive console){R}")
    print(hr)
    for name in sorted(TOOL_DESCRIPTIONS):
        desc = TOOL_DESCRIPTIONS[name]
        print(f"    {C}{name:<14}{R} {desc}")
    print()

    # Examples
    print(f"""{U}EXAMPLES{R}
{hr}
    {G}# Fingerprint a target and get method recommendations{R}
    python3 {script_name} ADVISE https://lab-target.local

    {G}# Auto-benchmark all methods (5 threads, 10s probe, RPC 5){R}
    python3 {script_name} AUTO https://lab-target.local

    {G}# L7 GET flood: 100 threads, HTTP proxies, 100 RPC, 2 min{R}
    python3 {script_name} GET https://lab-target.local 1 100 http.txt 100 120

    {G}# L4 TCP flood: 100 threads, 2 min{R}
    python3 {script_name} TCP 10.0.0.5:80 100 120

    {G}# L4 with SOCKS5 proxies{R}
    python3 {script_name} TCP 10.0.0.5:80 100 120 5 socks5.txt

    {G}# NTP amplification with reflector list{R}
    python3 {script_name} NTP 10.0.0.5:80 100 120 reflectors.txt
""")


def print_advise(host, ip, port, tcp, status, url, candidates, reasons):
    """Pretty-print ADVISE results."""
    l7 = [c for c in candidates if c in Methods.LAYER7_METHODS]
    l4 = [c for c in candidates if c in Methods.LAYER4_METHODS]

    print(f"""
{bcolors.BOLD}┌─── ADVISE Results ────────────────────────────┐{bcolors.RESET}
{bcolors.WARNING}│{bcolors.RESET} Run ID   : {bcolors.OKCYAN}{RUN_ID}{bcolors.RESET}
{bcolors.WARNING}│{bcolors.RESET} Target   : {bcolors.OKBLUE}{host}{bcolors.RESET}:{bcolors.OKBLUE}{port}{bcolors.RESET}
{bcolors.WARNING}│{bcolors.RESET} IP       : {ip}
{bcolors.WARNING}│{bcolors.RESET} TCP      : {bcolors.OKGREEN + 'open' + bcolors.RESET if tcp else bcolors.FAIL + 'closed' + bcolors.RESET}
{bcolors.WARNING}│{bcolors.RESET} HTTP     : {status}
{bcolors.WARNING}│{bcolors.RESET} URL      : {url}
{bcolors.WARNING}│{bcolors.RESET}
{bcolors.WARNING}│{bcolors.RESET} {bcolors.BOLD}L7 Candidates ({len(l7)}):{bcolors.RESET}
{bcolors.WARNING}│{bcolors.RESET}   {bcolors.OKCYAN}{', '.join(l7) if l7 else '(none)'}{bcolors.RESET}
{bcolors.WARNING}│{bcolors.RESET}
{bcolors.WARNING}│{bcolors.RESET} {bcolors.BOLD}L4 Candidates ({len(l4)}):{bcolors.RESET}
{bcolors.WARNING}│{bcolors.RESET}   {bcolors.OKCYAN}{', '.join(l4) if l4 else '(none)'}{bcolors.RESET}
{bcolors.WARNING}│{bcolors.RESET}
{bcolors.WARNING}│{bcolors.RESET} {bcolors.BOLD}Rationale:{bcolors.RESET}""")
    for r in reasons:
        print(f"{bcolors.WARNING}│{bcolors.RESET}   • {r}")
    print(f"{bcolors.BOLD}└───────────────────────────────────────────────┘{bcolors.RESET}")


def print_auto_results(results):
    """Pretty-print AUTO results as a ranked table."""
    worked = [r for r in results if r["pps"] > 0]
    failed = [r for r in results if r["pps"] == 0]
    worked.sort(key=lambda r: r["pps"], reverse=True)

    print(f"""
{bcolors.BOLD}╔══════════════════════════════════════════════════════════════╗
║                     AUTO RESULTS                             ║
╠══════════════╤════════╤════════════╤══════════════╤══════════╣
║ Method       │ Layer  │        PPS │          BPS │ Status   ║
╠══════════════╪════════╪════════════╪══════════════╪══════════╣{bcolors.RESET}""")

    for rank, r in enumerate(worked, 1):
        pps = Tools.humanformat(r["pps"])
        bps = Tools.humanbytes(r["bps"])
        status = f"{bcolors.OKGREEN}#{rank}{bcolors.RESET}"
        print(f"║ {bcolors.OKCYAN}{r['method']:<12}{bcolors.RESET} "
              f"│ L{r['layer']:<5} "
              f"│ {str(pps):>10} "
              f"│ {str(bps):>12} "
              f"│ {status:<18} ║")

    for r in failed:
        pps = Tools.humanformat(r["pps"])
        bps = Tools.humanbytes(r["bps"])
        status = f"{bcolors.FAIL}FAILED{bcolors.RESET}"
        print(f"║ {r['method']:<12} "
              f"│ L{r['layer']:<5} "
              f"│ {str(pps):>10} "
              f"│ {str(bps):>12} "
              f"│ {status:<18} ║")

    print(f"{bcolors.BOLD}╚══════════════╧════════╧════════════╧══════════════╧══════════╝{bcolors.RESET}")
    print(f"\n{bcolors.WARNING}{len(worked)}/{len(results)} methods produced traffic{bcolors.RESET}")

    if worked:
        best = worked[0]
        print(f"\n{bcolors.OKGREEN}{bcolors.BOLD}RECOMMENDATION:{bcolors.RESET} "
              f"Use method {bcolors.OKCYAN}{best['method']}{bcolors.RESET} "
              f"(L{best['layer']}) — highest throughput at "
              f"{bcolors.OKCYAN}{Tools.humanformat(best['pps'])}{bcolors.RESET} pps / "
              f"{bcolors.OKCYAN}{Tools.humanbytes(best['bps'])}{bcolors.RESET}\n")
    else:
        print(f"\n{bcolors.FAIL}NO methods produced traffic. "
              f"Target may be unreachable, or all methods were blocked.{bcolors.RESET}\n")


def progress_bar(elapsed, total, width=20):
    """Return a text progress bar string."""
    pct = min(1.0, elapsed / total) if total > 0 else 0
    filled = int(width * pct)
    bar = '█' * filled + '░' * (width - filled)
    return bar, pct * 100


def print_attack_status(target, port, method, pps, bps, elapsed, total):
    """Print a single-line in-place attack progress update."""
    bar, pct = progress_bar(elapsed, total)
    remaining = max(0, int(total - elapsed))
    print(f'\r{bcolors.WARNING}[{method}]{bcolors.RESET} '
          f'{bcolors.OKBLUE}{target}:{port}{bcolors.RESET} '
          f'PPS: {bcolors.OKCYAN}{Tools.humanformat(pps)}{bcolors.RESET} '
          f'BPS: {bcolors.OKCYAN}{Tools.humanbytes(bps)}{bcolors.RESET} '
          f'{bar} {pct:.0f}% [{remaining}s]  ', end='', flush=True)
