#!/usr/bin/python3.7
import argparse
import os
import ipaddress
import subprocess
import asyncio


def expandRange(cidr: str) -> list:
    if cidr[0].isalpha():
        return [cidr]
    else:
        return [str(ip) for ip in ipaddress.IPv4Network(cidr)]


def stripScheme(target: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(target)
    return parsed.hostname if parsed.hostname is not None else parsed.path


def parseTargets(fileName: str) -> set:
    targets = set()
    with open(fileName, 'r') as f:
        from itertools import chain
        targets = [expandRange(stripScheme(x.strip()))
                   for x in f.read().split()]
        targets = chain.from_iterable(targets)
    return set(targets)


def resolveTarget(target):
    import socket
    import sys
    try:
        result = socket.gethostbyname(target)
    except socket.error:
        print("[!] Error resolving target: {}, exiting".format(target))
        sys.exit(1)
    return result


def parseMasscan(target, result) -> list:
    final = [target]
    ports = set()
    result = str(result).split('\\r')
    for r in result:
        if "Discovered" in r:
            for dis in r.split('\\n'):
                dis = dis.split()
                try:
                    ports.add(dis[3].split('/')[0])
                except:
                    pass
    final.append(ports)
    return final


async def performMasscan(target: str, interface: str, flags: list) -> list:
    if target[0].isalpha():
        target = resolveTarget(target)
    cmd = " ".join(["sudo", "masscan"] + flags.split() +
                   ["-i", interface, target])
    print(f"[+] {cmd}")

    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    result, _ = await proc.communicate()

    return parseMasscan(target, result)


def parseNmap(target, result) -> list:
    final = []
    result = str(result).split('\\n')
    for r in result:
        if "Ports:" in r:
            r = r.split('\\t')[1]  # ports
            r = r.split(',')
            firstRun = True
            for port in r:
                port = port.lstrip("Ports: ").split('/')
                first = ".."
                if firstRun:
                    first = target
                    firstRun = False
                if "Site" in port[0]:  # edge case for ldap servers
                    final[-1] += f"/ {port[0]}"
                else:
                    final.append(",".join([first, port[0], port[4], port[6]]))
    return final


async def performNmap(target: str, ports: list, flags: str) -> dict:
    cmd = " ".join(["nmap"] + flags.split() +
                   ["-p", ",".join(ports), "-oG", "-", target])
    print(f"[+] {cmd}")

    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    result, _ = await proc.communicate()

    return parseNmap(target, result)


async def main(targets, interface, nmapFlags, masscanFlags, outFile):
    ips = []
    if os.path.isfile(targets):
        print(f"[-] Parsing scope file '{targets}'")
        ips = parseTargets(targets)
    else:
        ips = expandRange(stripScheme(targets))

    from subprocess import check_output
    check_output(["sudo", "-v"])  # cache creds

    args = ((ip, interface, masscanFlags) for ip in ips)

    # Do masscan synchronously to get consistent results
    print("[-] Performing Masscan(s)...")
    results = []
    for x in args:
        results.append(await performMasscan(*x))

    print("[-] Performing Nmap(s)...")
    results = await asyncio.gather(*[performNmap(target, ports, nmapFlags)
                                     for target, ports in results
                                     if len(ports) > 0])

    print(f"[-] Writing {len(results)} Result(s)")
    with open(outFile, 'w') as f:
        f.write("Host,Port,Service,Version\n")
        for result in results:
            for line in result:
                f.write(f"{line}\n")

    print(f"[+] Results written to {outFile}")


if __name__ == "__main__":
    print("*** It's like a finger pointing away to the moon.")
    print("Don't concentrate on the finger")
    print("or you will miss all that heavenly glory. ***\n")

    parser = argparse.ArgumentParser(
        "Performs masscan and passes the output to Nmap version scan")
    parser.add_argument("-t", "--target", required=True,
                        help="Single IP/Hostname/CIDR/Scope file of target(s)\
                             to scan")
    parser.add_argument("-i", "--interface", required=True,
                        help="Network interface to use")
    parser.add_argument(
        "-n", "--nmap-flags",
        default="-Pn -sV -T5 --min-rate 1500",
        help="Flags for Nmap")
    parser.add_argument("-m", "--masscan-flags",
                        default="-p1-65535 --rate=20000 --wait=1",
                        help="Flags for masscan")
    parser.add_argument("-o", "--out-file",
                        default="heaven.csv", help="Final result output")

    args = parser.parse_args()

    asyncio.run(main(args.target, args.interface, args.nmap_flags,
                     args.masscan_flags, args.out_file))
