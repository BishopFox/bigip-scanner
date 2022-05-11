# BIG-IP Scanner

Determine the running software version of a remote F5 BIG-IP management interface. Developed with ❤️ by the [Bishop Fox Cosmos team](https://bishopfox.com/platform).

<div align="center">
    <img src="https://s3.us-east-2.amazonaws.com/s3.bishopfox.com/prod-1437/Images/channels/blog/tiles/Bishop-Fox-BIG-IP-scanner-tool-F.png" width="400px" />
</div>


## Description

CVE-2022-1388, a critical vulnerability in the F5 BIG-IP management interface, allows an attacker to bypass authentication and remotely execute arbitrary system commands. Bishop Fox developed a BIG-IP scanner that you can use to determine:
- Which software version is running on a remote F5 BIG-IP management interface
- Whether a specific appliance is affected by any known vulnerabilities, including CVE-2022-1388—all without sending any malicious traffic to the server (i.e., risking being blocked by a WAF)

See [full write-up](https://bishopfox.com/blog/big-ip-scanner-cve-2022-1388) for this tool at the Bishop Fox blog, including a complete walkthrough of the methodology behind building the version table.

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

In the following example, `https://example.com/tmui/tmui/login/images/logo_f5.png` has an HTTP response header that indicates that it's running BIG-IP version `16.1.2-0.0.18` which, according to [F5's security advisory](https://support.f5.com/csp/article/K23605346), is in the _vulnerable_ range for CVE-2022-1388.

```
$ python3 bigip-scanner.py -t https://example.com | jq
[
  {
    "version": "16.1.2-0.0.18",
    "precision": "exact",
    "modification_time": "2021-10-23T21:06:13Z",
    "release_number": "16.1.2",
    "release_type": "Maintenance",
    "image_name": "BIGIP-16.1.2-0.0.18",
    "release_date": "11/02/2021",
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

- [CVE-2022-1388: Scan BIG-IP for Exact Release Versions](https://bishopfox.com/blog/big-ip-scanner-cve-2022-1388)
- [K33062581: Software Release Date Information](https://support.f5.com/csp/article/K33062581)
- [K9412: The BIG-IP release matrix](https://support.f5.com/csp/article/K9412)
- [K23605346: BIG-IP iControl REST vulnerability CVE-2022-1388](https://support.f5.com/csp/article/K23605346)
- [POC for CVE-2022-1388](https://github.com/horizon3ai/CVE-2022-1388)
- [PAN-OS scanner](https://github.com/noperator/panos-scanner)

### License

This project is licensed under the [MIT License](LICENSE.md).
