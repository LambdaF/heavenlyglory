# heavenlyglory
## masscan a target(s) and pass the output to Nmap version scanning

usage: Passes masscan output to Nmap version scan [-h] [-t TARGET]
                                                  [-tf TARGET_FILE]
                                                  [-n NMAP_FLAGS]
                                                  [-m MASSSCAN_FLAGS]
                                                  [-i INTERFACE] [-o OUT_FILE]
                                                  [-k KEEP_TEMP]

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Single IP/Hostname or CIDR range of target to scan
  -tf TARGET_FILE, --target-file TARGET_FILE
                        List of targets to scan. Comma or newline seperated
  -n NMAP_FLAGS, --nmap-flags NMAP_FLAGS
                        Flags for Nmap
  -m MASSSCAN_FLAGS, --masscan-flags MASSCAN_FLAGS
                        Flags for MassScan
  -i INTERFACE, --interface INTERFACE
                        Network interface to use
  -o OUT_FILE, --out-file OUT_FILE
                        Final result output
  -k KEEP_TEMP, --keep-temp KEEP_TEMP
                        Directory to keep temporary scan files in. Files will
                        be removed if not specified
