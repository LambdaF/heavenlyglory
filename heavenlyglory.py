#!/bin/python3
import argparse, os, sys, socket, tempfile, shutil, xmltodict

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
            cmd = "sudo nmap {flags} -p {ports} -oA {tempDir}/{ip} {ip}".format(flags=flags,ports=v,tempDir=tempDir,ip=k)
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

def parseOutput(indir):
    result = []
    writeFirst = False
    for file in os.listdir(indir):
        if file.endswith(".xml"):
            tempResult = {}
            obj = None
            with open(os.path.join(indir,file), 'r') as f:
                obj = xmltodict.parse(f.read())

            # workaround, because who wants consistent output? thanks xmltodict
            try:
                tempResult["ip"] = obj["nmaprun"]["host"]["address"]["@addr"]
            except:
                tempResult["ip"] = obj["nmaprun"]["host"]["address"][0]["@addr"]

            tempResult["ports"] = []
            ports = None

            # see previous comment
            if isinstance(obj["nmaprun"]["host"]["ports"]["port"], dict):
                ports = [obj["nmaprun"]["host"]["ports"]["port"]]
            else:
                ports = obj["nmaprun"]["host"]["ports"]["port"]

            for port in ports:
                tempDict = {}
                tempDict["portNumber"] = port["@portid"]
                tempDict["serviceName"] = port["service"]["@name"]
                try:
                    tempDict["serviceProduct"] = port["service"]["@product"]
                    tempDict["serviceVersion"] = port["service"]["@version"]
                    tempDict["serviceExtra"] = port["service"]["@extrainfo"]
                except:
                    pass
                tempResult["ports"].append(tempDict)
            result.append(tempResult)
    return result

def writeCSV(parsed, outfile):
    with open(outfile, 'w') as f:
        f.write("Host,Port,Service,Detail\n")
        for host in parsed:
            ip = host["ip"]
            for port in host["ports"]:
                f.write("{},".format(ip))
                ip = ".."
                f.write("{},{},\"".format(port["portNumber"], port["serviceName"]))
                try:
                    f.write("{}".format(port["serviceProduct"]))
                    f.write(" : {}".format(port["serviceVersion"]))
                    f.write(" : {}".format(port["serviceExtra"]))
                except:
                    pass
                f.write("\"\n")
    print("[+] Output written to {}".format(outfile))

if __name__ == "__main__":
    print("It's like a finger pointing away to the moon. Don't concentrate on the finger or you will miss all that heavenly glory.")

    parser = argparse.ArgumentParser("Passes masscan output to Nmap version scan")
    parser.add_argument("-t", "--target", required=True, help="Single IP/Hostname/CIDR/Scope file of target(s) to scan")
    parser.add_argument("-n", "--nmap-flags", default="-Pn -sV -T5 --min-rate 1500", help="Flags for Nmap")
    parser.add_argument("-m", "--masscan-flags", default="-p1-65535 --rate=20000 --wait 0", help="Flags for masscan")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use")
    parser.add_argument("-o", "--out-file", default="heaven.csv", help="Final result output")
    parser.add_argument("-k", "--keep-temp", default="", help="Directory to keep temporary scan files in. Files will be removed if not specified")

    args = parser.parse_args()

    targets = []
    if os.path.isfile(args.target):
        print("[-] Parsing scope file {}".format(args.target))
        targets = parseTargets(args.target)
    else:
        targets.append(resolveTarget(args.target))

    with tempfile.TemporaryDirectory() as tempDir:
        print("[+] Using Temporary Directory {}".format(tempDir))

        print("[+] Performing masscan")
        resultFile = performMasscan(args.masscan_flags, args.interface, targets, tempDir)
        results = parseMasscan(resultFile)
        if not results:
            print("[!] masscan failed to find any open ports")
            sys.exit(1)

        print("[+] Performing Nmap")
        performNmap(results, args.nmap_flags, tempDir)

        parsed = parseOutput(tempDir)
        writeCSV(parsed, args.out_file)

        if args.keep_temp != "":
            shutil.copytree(tempDir, args.keep_temp)
            print("[-] Stored temporary files in {}".format(args.keep_temp))
