# heavenlyglory
## masscan target(s) and pass the output to Nmap version scanning
Requires masscan, nmap and python 3.7

### Args
```
optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Single target or file of newline seperated target(s)
                        to scan
  -i INTERFACE, --interface INTERFACE
                        Network interface to use
  -n NMAP_FLAGS, --nmap-flags NMAP_FLAGS
                        Flags for Nmap
  -m MASSCAN_FLAGS, --masscan-flags MASSCAN_FLAGS
                        Flags for masscan
  -o OUT_FILE, --out-file OUT_FILE
                        Final result output
```

### Info
Most arguments have sensible defaults, only target(s) and network interface are required.

Output is written to heaven.csv in the current working directory by default.

### Usage Examples

#### Single target
```heavenlyglory.py -t 127.0.0.1 -i eth0```

#### Targets from file
```heavenlyglory.py -t ~/projects/targets.file -i eth0```

#### Single range, custom nmap flags
```heavenlyglory.py -t 192.168.0.0/24 -i eth0 --nmap-flags "-sCV -T3"```

### Installing in pipenv
```
pipenv install
pipenv shell
```

### Running Tests
```
pipenv shell
tox
```
