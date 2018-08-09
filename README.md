# heavenlyglory
## masscan target(s) and pass the output to Nmap version scanning
Requires masscan, nmap and python3

### args
```
-h, --help                                          show this help message and exit
-t TARGET, --target TARGET                          Single IP/Hostname or CIDR range of target to scan
-tf TARGET_FILE, --target-file TARGET_FILE          List of targets to scan. Comma or newline seperated
-n NMAP_FLAGS, --nmap-flags NMAP_FLAGS              Flags for Nmap
-m MASSSCAN_FLAGS, --masscan-flags MASSCAN_FLAGS    Flags for MassScan
-i INTERFACE, --interface INTERFACE                 Network interface to use
-o OUT_FILE, --out-file OUT_FILE                    Final result output
-k KEEP_TEMP, --keep-temp KEEP_TEMP                 Directory to keep temporary scan files in. Files will be removed if not specified
```

### Info
Most arguments have sensible defaults, only target(s) and network interface are required.

Output is written to heaven.out in the current working directory by default

### Usage Examples

#### Single target
```heavenlyglory.py -t 127.0.0.1 -i eth0```

#### targets from file
```heavenlyglory.py -tf targets.file -i eth0```

#### single range, keep temporary files, custom nmap flags
```heavenlyglory.py -t 192.168.0.0/24 -i eth0 -k ~/projects/tempscanfiles/ --nmap-flags "-sCV -T3"```
