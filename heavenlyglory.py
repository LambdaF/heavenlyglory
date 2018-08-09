#!/bin/python3
import argparse,os,sys,socket,tempfile,shutil

def performMasscan(flags,interface,targets,tempDir):
    for t in targets:
        cmd = "sudo masscan {flags} -i {interface} -oG {tempDir}/mass.scan --append-output {target}".format(flags=flags,interface=interface,tempDir=tempDir,target=t)
        print("[+] {}".format(cmd))
        os.system(cmd)
    return "{}/mass.scan".format(tempDir)

def parseMasscan(scanInput):
    results = {}
    with open(scanInput, 'r') as f:
        for line in f:
            line = line.strip()
            splits = line.split()
            if splits[0] == "#":
                continue
            ip = splits[1]
            ports = []
            for i in range(4,len(splits)):
                index = splits[i].index('/')
                ports.append(splits[i][:index])
            ports = ','.join(ports)
            if ip in results:
                results[ip] += ",{}".format(ports)
            else:
                results[ip] = ports
    return results

def performNmap(targets, flags, tempDir):
    for k,v in targets.items():
            cmd = "sudo nmap {flags} -p {ports} -oA {tempDir}/{ip}-{ports} {ip}".format(flags=flags,ports=v,tempDir=tempDir,ip=k)
            print("\n[+] " + cmd)
            os.system(cmd)

def resolveTarget(target):
    if target.find("/") > -1:
        if target[target.find("/") + 1] == '/':
            print("[-] Attempting to strip URI in {}".format(target))
            target = target.replace('/','')
            target = target[target.find(":")+1:]
        else: #assume it's a range
            return target
    try:
        result = socket.gethostbyname(target)
    except socket.error:
        print("[!] Error resolving target: {}, exiting".format(target))
        sys.exit(1)
    return result

def parseTargets(targetFile):
    targets = []
    with open(targetFile, 'r') as f:
        targets = f.read()
        if targets.find(',') > - 1:
            print("[-] Found comma in targets file, assuming comma seperated")
            targets = targets.split(',')
        else:
            targets = targets.split()
    for i in range(len(targets)):
        targets[i] = targets[i].strip()
        targets[i] = resolveTarget(targets[i])
    return set(targets)

if __name__ == "__main__":
    print("It's like a finger pointing away to the moon. Don't concentrate on the finger or you will miss all that heavenly glory.")
    parser = argparse.ArgumentParser("Passes masscan output to Nmap version scan")
    parser.add_argument("-t", "--target", help="Single IP/Hostname or CIDR range of target to scan")
    parser.add_argument("-tf", "--target-file", help="List of targets to scan. Comma or newline seperated")
    parser.add_argument("-n", "--nmap-flags", default="-Pn -sV -T5 --min-rate 1500", help="Flags for Nmap")
    parser.add_argument("-m", "--masscan-flags", default="-p1-65535 --rate=20000 --wait 0", help="Flags for masscan")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("-o", "--out-file", default="heaven.out", help="Final result output")
    parser.add_argument("-k", "--keep-temp", default="", help="Directory to keep temporary scan files in. Files will be removed if not specified")

    args = parser.parse_args()

    if (args.target is None and args.target_file is None) or args.interface is None:
        print("[!] Interface and/or Target(s) are required")
        parser.print_help()
        sys.exit(1)

    targets = []
    if args.target_file:
        targets = parseTargets(args.target_file)
    else:
        targets.append(resolveTarget(args.target))
        
    with tempfile.TemporaryDirectory() as tempDir:
        print("[+] Using Temporary Directory {}".format(tempDir))
        print("[+] Performing masscan")
        resultFile = performMasscan(args.masscan_flags, args.interface, targets, tempDir)
        results = parseMasscan(resultFile)

        print("[+] Performing Nmap")
        performNmap(results, args.nmap_flags, tempDir)
        os.system("cat " + tempDir + "/*.gnmap | awk '/Ports/{print $0}' > " + args.out_file)
        print("[+] Output written to {}".format(args.out_file))
        if args.keep_temp != "":
            shutil.copytree(tempDir, args.keep_temp)
            print("[-] Stored temporary files in {}".format(args.keep_temp))
