#!/usr/bin/env python3

import argparse
import datetime
import json
import logging
import re
import sys
import time
import urllib.parse
import urllib3
import urllib3.exceptions

import pandas as pd
import requests
import requests.exceptions


# Disable some warnings.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
pd.options.mode.chained_assignment = None

# Support older SSL ciphers.
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = "ALL:@SECLEVEL=1"

# Set up logging.
logging.basicConfig(
    format="%(asctime)s %(levelname)-8s [%(funcName)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logging.Formatter.converter = time.gmtime


class BIGIPScanner:
    def __init__(self, version_table: str):

        # Load version table.
        versions = pd.DataFrame(pd.read_csv(version_table))
        versions["modification_time"] = pd.to_datetime(
            versions["modification_time"], utc=True
        )
        self.versions = versions

    # These are the static resources whose modification times (reflected in
    # ETag or Last-Modified header values) imply a specific version of BIG-IP.
    static_resources = [
        "/tmui/tmui/login/images/logo_f5.png",
        "/tmui/tmui/login/images/logo_f5_new.png",
    ]

    # The keys in this dictionary represent HTTP response headers that we're
    # looking for. Each of those headers maps to a function in this namespace
    # that knows how to decode that header value into a datetime.
    mtime_headers = {
        "ETag": "etag_to_datetime",
        "Last-Modified": "last_modified_to_datetime",
    }

    # Parse an ETag value into a datetime.
    @staticmethod
    def etag_to_datetime(etag: str) -> datetime.datetime:

        # ETag: "1fe7-5db411548c100"
        if re.match(r"^[0-9a-f]{4}-[0-9a-f]{13}$", etag):
            timestamp = int(str(int(etag.split("-")[1], 16))[:-6])

        # ETag: "6e1862414fe4"
        elif re.match(r"^[0-9a-f]{12}$", etag):
            timestamp = int(etag[-8:], 16)

        # Unknown format.
        else:
            timestamp = 0

        return datetime.datetime.utcfromtimestamp(timestamp)

    # Parse a Last-Modified value into a datetime.
    @staticmethod
    def last_modified_to_datetime(last_modified: str) -> datetime.datetime:

        # Last-Modified: Mon, 28 Mar 2022 06:04:20 GMT
        return datetime.datetime.strptime(last_modified[:-4], "%a, %d %b %Y %X")

    # Be sneaky.
    request_headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36",
    }

    def get_mtime_headers(self, target: str, resource: str) -> dict:

        url = urllib.parse.urljoin(target, resource)
        logger.debug(f"requesting {url}")
        try:
            resp = requests.get(
                url,
                headers=self.request_headers,
                timeout=5,
                verify=False,
                allow_redirects=True,
            )
            resp.raise_for_status()
            return {
                header_name: resp.headers[header_name].strip('"')
                for header_name in self.mtime_headers
                if header_name in resp.headers
            }

        # These errors are indicative of target-level issues. Don't continue
        # requesting other resources when encountering these; instead, bail.
        except (
            requests.exceptions.ConnectTimeout,
            requests.exceptions.SSLError,
            requests.exceptions.ConnectionError,
        ) as e:
            logger.error(f"could not connect to target: {type(e).__name__}")
            sys.exit(1)

        # Otherwise, if the resource simply doesn't exist, keep moving.
        except (requests.exceptions.HTTPError, requests.exceptions.ReadTimeout) as e:
            logger.warning(type(e).__name__)
            return {}

    # Check target for the presence of each static resource.
    def scan_target(self, target: str, request_all: bool = False) -> pd.DataFrame:
        logger.debug(f"scanning target: {target}")
        matches = pd.DataFrame()
        for resource in self.static_resources:

            # Search the resource for relevant mtime-related HTTP response
            # headers.
            resp_headers = self.get_mtime_headers(
                target=target,
                resource=resource,
            )

            for header_name, header_value in resp_headers.items():

                # Convert header value to datetime.
                header_parser = getattr(self, self.mtime_headers[header_name])
                mtime = pd.Timestamp(header_parser(header_value), tz="UTC")

                # Get exact matches.
                exact = self.versions[self.versions["modification_time"] == mtime]
                exact["precision"] = "exact"
                results = exact

                if request_all or exact.empty:

                    # Get approximate matches.
                    delta = datetime.timedelta(hours=27)
                    approx = self.versions[
                        (self.versions["modification_time"] != mtime)
                        & (self.versions["modification_time"] >= mtime - delta)
                        & (self.versions["modification_time"] <= mtime + delta)
                    ]
                    approx["precision"] = "approximate"

                    # Combine results.
                    results = (
                        pd.concat([exact, approx]).reset_index().drop("index", axis=1)
                    )

                results["target"] = target
                results["resource"] = resource
                results["header_name"] = header_name
                results["header_value"] = header_value

                # Append and optionally immediately return matches.
                matches = pd.concat([matches, results])
                if not exact.empty and not request_all:
                    matches["modification_time"] = matches[
                        "modification_time"
                    ].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                    return matches.reset_index().drop("index", axis=1)

        if "modification_time" in matches:
            matches["modification_time"] = matches["modification_time"].dt.strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        return matches.reset_index().drop("index", axis=1)


def main():

    # Parse arguments.
    parser = argparse.ArgumentParser(
        description="""
            Determine the software version of a remote BIG-IP management interface.
            Developed with ❤ by the Bishop Fox Cosmos team.
        """
    )
    parser.add_argument("-t", dest="target", help="https://example.com")
    parser.add_argument("-f", "--file", dest="file", help="File with a list of IP addresses")
    parser.add_argument(
        "-v",
        dest="version_table",
        default="version-table.csv",
        help="version-table.csv",
    )
    parser.add_argument(
        "-a",
        dest="request_all",
        action="store_true",
        help="request all resources; don't stop after an exact match",
    )
    parser.add_argument("-d", dest="debug", action="store_true", help="debug mode")
    args = parser.parse_args()

    if not args.target and not args.file:
        print("You must provide either a target (-t) or a file (-f) with IP addresses.")
        sys.exit(1)

    if args.debug:
        logger.setLevel(logging.DEBUG)

    scanner = BIGIPScanner(version_table=args.version_table)

    # Check if -t or -f was provided and set targets accordingly.
    if args.target:
        targets = [args.target]
    elif args.file:
        with open(args.file, 'r') as file:
            targets = [line.strip() for line in file.readlines()]

    # Loop through each target.
    for target in targets:
        print(f"Scanning target: {target}")
        matches = scanner.scan_target(target=target, request_all=args.request_all)
        if not matches.empty:
            print(
                json.dumps(
                    matches.groupby(["version", "precision"])
                    .first()
                    .sort_values(
                        ["precision"], key=lambda x: x.map({"exact": 0, "approximate": 1})
                    )
                    .reset_index()
                    .to_dict("records")
                )
            )
        else:
            print("[]")

if __name__ == "__main__":
    main()
