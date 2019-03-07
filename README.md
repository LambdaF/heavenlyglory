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
  -n NMAP_FLAGS, --nmap-flags NMAP_FLAGS
                        Flags for Nmap
  -m MASSCAN_FLAGS, --masscan-flags MASSCAN_FLAGS
                        Flags for masscan
  -o OUT_FILE, --out-file OUT_FILE
                        Final result output
  -p TASK_POOL_SIZE, --task-pool-size TASK_POOL_SIZE
                        Set the maximum number of concurrent scans
```

### Info
Most arguments have sensible defaults, only target(s) are required.

The default flags to each application are:
#### masscan
```
-p1-65535 --rate=20000 --wait=1
```

#### nmap
```
-Pn -sV -T5 --min-rate 1500
```

Custom arguments to nmap and masscan can be supplied via the -m and -n arguments respectively,
these will overwrite the defaults.

Output is written to heaven.csv in the current working directory by default.

### Usage Examples

#### Single target
```
heavenlyglory.py -t 127.0.0.1
```

#### Targets from file
```
heavenlyglory.py -t ~/projects/targets.file
```

#### Single range, custom nmap flags
```
heavenlyglory.py -t 192.168.0.0/24 --nmap-flags "-sCV -T3"
```

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

### Building docker
```
docker build -t heavenlyglory .
```

### Running in docker

#### Scanning specific ports and getting outfile
```
docker run -v $(pwd):/heavenlyGlory/out --rm -it heavenlyglory -t 127.0.0.1 -m "-p 80,443,445" -o out/heaven.csv
```

#### Using scope file
```
docker run -v $(pwd):/heavenlyGlory/out -v ~/test.scope:/heavenlyGlory/test.scope --rm -it heavenlyglory -t test.scope -o out/heaven.csv
```
