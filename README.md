# heavenlyglory
## masscan target(s) and pass the output to Nmap version scanning
Requires masscan, nmap and python 3 with "xmltodict" installed

### args
```
-h, --help                                          show this help message and exit
-t TARGET, --target TARGET                          Single IP/Hostname/CIDR/Scope file of target(s) to scan
-n NMAP_FLAGS, --nmap-flags NMAP_FLAGS              Flags for Nmap
-m MASSSCAN_FLAGS, --masscan-flags MASSCAN_FLAGS    Flags for MassScan
-i INTERFACE, --interface INTERFACE                 Network interface to use
-o OUT_FILE, --out-file OUT_FILE                    Final result output
-k KEEP_TEMP, --keep-temp KEEP_TEMP                 Directory to keep temporary scan files in. Files will be removed if not specified
```

### Info
Most arguments have sensible defaults, only target(s) and network interface are required.

Output is written to heaven.csv in the current working directory by default.

### Usage Examples

#### Single target
```heavenlyglory.py -t 127.0.0.1 -i eth0```

#### Targets from file
```heavenlyglory.py -t ~/projects/targets.file -i eth0```

#### Single range, keep temporary files, custom nmap flags
```heavenlyglory.py -t 192.168.0.0/24 -i eth0 -k ~/projects/tempscanfiles/ --nmap-flags "-sCV -T3"```
