# Spotter - Targeted Payload Execution

Spotter is a tool to wrap payloads in environmentally-keyed, AES256-encrypted launchers. These keyed launchers provide a way to ensure your payload is running on its intended target, as well as provide a level of protection for the launcher itself.

![spotter](https://media.defense.gov/2011/Jul/28/2000234038/-1/-1/0/110727-F-OK556-004.JPG)

## Use:
```
python3 spotter.py --help
usage: spotter.py [-h] {ps,cs-process,cs-inject} ...

This script will build an AES256-encrypted payload launcher using
environmental keys.

positional arguments:
  {ps,cs-process,cs-inject}
                        Payload method help
    ps                  PowerShell help
    cs-process          C# Process help
    cs-inject           C# PE Injection help

optional arguments:
  -h, --help            show this help message and exit
```
PowerShell Example:
```
python3 spotter.py ps --payload_file payload.txt --outfile spotter.ps1 --domain ACME.CORP --osver win7 --vm --ip 192.168.82
```
C# Process Creation:
```
python3 spotter.py cs-process -d ACME.CORP -x calc.exe
```
C# Injection:
```
python3 spotter.py cs-inject -d ACME.CORP --payload_file evilDotNet.exe
```

<sub><sup>Released at aRcTicCON '18</sup></sub>
