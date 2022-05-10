# BIG-IP Scanner

Determine the running software version of a remote F5 BIG-IP management interface.

Developed with ❤️ by the Bishop Fox Cosmos team.

## Getting started

### Install

```
git clone https://github.com/bishopfox/bigip-scanner.git && cd bigip-scanner
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -U pip
python3 -m pip install -r requirements.txt
```

### Usage

```
$ python3 bigip-scanner.py -h
usage: bigip-scanner.py [-h] -t TARGET [-v VERSION_TABLE] [-a] [-d]

Determine the running software version of a remote F5 BIG-IP management interface.
Developed with ❤️ by the Bishop Fox Cosmos team.

optional arguments:
  -h, --help        show this help message and exit
  -t TARGET         https://example.com
  -v VERSION_TABLE  version-table.csv
  -a                request all resources; don't stop after an exact match
  -d                debug mode
```

In the following example, `https://example.com/tmui/tmui/login/images/logo_f5.png` has an HTTP response header that indicates that it's running BIG-IP version `15.1.5.1-0.0.14`.

```
$ python3 bigip-scanner.py -t https://example.com | jq
[
  {
    "version": "15.1.5.1-0.0.14",
    "precision": "exact",
    "modification_time": "2022-03-28T06:04:20Z",
    "release_number": "15.1.5.1",
    "release_type": "Point",
    "image_name": "BIGIP-15.1.5.1-0.0.14",
    "release_date": "04/06/2022",
    "target": "https://example.com",
    "resource": "/tmui/tmui/login/images/logo_f5.png",
    "header_name": "ETag",
    "header_value": "1fe7-5db411548c100"
  }
]
```

## Back matter

### Legal disclaimer

Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

### See also

- [K33062581: Software Release Date Information](https://support.f5.com/csp/article/K33062581)
- [K9412: The BIG-IP release matrix](https://support.f5.com/csp/article/K9412)
- [K55879220: Overview of F5 vulnerabilities](https://support.f5.com/csp/article/K55879220)
- [POC for CVE-2022-1388](https://github.com/horizon3ai/CVE-2022-1388)
- [PAN-OS scanner](https://github.com/noperator/panos-scanner)

### License

This project is licensed under the [MIT License](LICENSE.md).
