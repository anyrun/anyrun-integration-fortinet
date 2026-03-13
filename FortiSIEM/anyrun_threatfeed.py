#!/usr/bin/env python3.9
# Generic STIX2.1 Threatfeed Integration for ANY.RUN
import re
import argparse
from urllib.parse import urlsplit

from fsiem_utils.threatfeed_integration import (
    ThreatfeedIntegration,
    IP_entry,
    URL_entry,
    Domain_entry,
)

DEFAULT_TAXII_URLS = {
    "ip": "https://api.any.run/v1/feeds/taxii2/api1/collections/55cda200-e261-5908-b910-f0e18909ef3d/objects",
    "url": "https://api.any.run/v1/feeds/taxii2/api1/collections/05bfa343-e79f-57ec-8677-3122ca33d352/objects",
    "site": "https://api.any.run/v1/feeds/taxii2/api1/collections/2e0aa90a-5526-5a43-84ad-3db6f4549a09/objects",
}

def resolve_tf_url(tf_type):
    tf_url = DEFAULT_TAXII_URLS.get(tf_type)
    if tf_url:
        return tf_url

    print(f"No hardcoded tfURL found for tfType={tf_type}. Update DEFAULT_TAXII_URLS.")
    exit(1)


class AnyRunThreatFeed(ThreatfeedIntegration):
    # Supported FortiSIEM types in this script: ip, url, site (domain)
    def getThreatFeedData(self):
        if self.threatfeed_type not in {"ip", "url", "site"}:
            print("Unsupported tfType for this script. Use only: ip, url, domain")
            exit(1)

        # Specify max age of data in days to retrieve
        self.total_loaded_indicators = 0
        self.getTAXIIFeed(90)
        print(f"[ANY.RUN] Successfully loaded {self.total_loaded_indicators} indicators")

    def handleRequest(self, url, method="get", headers=None, params=None,
                      auth=None, data=None, verify=True):
        if headers is None:
            headers = {}
        else:
            headers = dict(headers)

        threatfeed_host = urlsplit(self.threatfeed_url).netloc
        request_host = urlsplit(url).netloc
        if threatfeed_host and request_host == threatfeed_host:
            headers.setdefault("x-anyrun-connector", "FortiSIEM:1.0.0")

        return super().handleRequest(url=url, method=method, headers=headers, params=params,
                                     auth=auth, data=data, verify=verify)
    
    # _base_url is kept for compatibility with parent method signature
    def getTaxii_v21Data(self, _base_url):
        headers = {
            "Accept": "application/taxii+json;version=2.1"
        }

        limit = 500
        params = {
            "limit": limit
        }

        if self.addedAfterTimeStamp is not None:
            params['modified_after'] = self.addedAfterTimeStamp

        obj_response = self.handleRequest(self.objects_url, headers=headers, params=params,
                                          auth=self.threatfeed_basic_auth)
        if obj_response.status_code == 301:
            print(f"Getting objects URL {self.objects_url} failed -  requires redirection, exiting")
            exit(1)
        if obj_response.status_code != 200:
            print(f"Error in getting objects from URL {self.objects_url} - Status Code: {obj_response.status_code}")
            exit(1)
        data = obj_response.json()
        objects = data.get('objects')
        if objects is None or len(objects) == 0:
            print("No threat entries found for the given URL")
            exit()

        self.processSTIXObjects(objects, self.taxii_collection)
        has_more = data.get('more', False)
        next_data = data.get('next')

        while has_more is True and next_data is not None:
            params['next'] = next_data

            obj_response = self.handleRequest(self.objects_url, headers=headers, params=params,
                                              auth=self.threatfeed_basic_auth)
            if obj_response.status_code != 200:
                print(f"Error in getting objects from page URL {self.objects_url}")
                exit(1)

            data = obj_response.json()
            objects = data.get('objects')
            if objects is None or len(objects) == 0:
                print("No threat entries found for the given URL")
                exit()

            has_more = data.get('more', False)
            next_data_updated = data.get('next', None)
            self.processSTIXObjects(objects, self.taxii_collection)
            if next_data == next_data_updated:
                break
            next_data = next_data_updated

    # lastSeen is derived from STIX object.modified
    def processSTIXObjects(self, objects, title):
        if objects is None or len(objects) == 0:
            print("Collection ", title, " has no threat entries")
            return

        url_pat = re.compile(r"^.*\[url:value = '(\S+)'.*\].*$")
        ipv4_pat = re.compile(r"^.*\[ipv4-addr:value = '(\S+)'.*\].*$")
        ipv6_pat = re.compile(r"^.*\[ipv6-addr:value = '(\S+)'.*\].*$")
        domain_pat = re.compile(r"^.*\[domain-name:value = '(\S+)'.*\].*$")

        parsed_data = []
        for obj in objects:
            pattern = obj.get('pattern')
            if pattern is None:
                continue

            created = obj.get('created')
            name = obj.get('name')
            description = obj.get('description')
            labels = obj.get('labels')
            confidence = obj.get('confidence')
            threat_types = obj.get('threatTypes', [])
            threat_type_values = [t for t in threat_types if t]
            last_seen_time = self.parse_timestamp(obj.get('modified'))

            if description is not None and '\n' in description:
                description = description.replace('\n', ' ')

            if labels:
                threat_type_values.extend([label for label in labels if label])

            threat_type_str = ",".join(threat_type_values) if threat_type_values else None

            if created is not None:
                created = self.parse_timestamp(created)

            if self.threatfeed_type == "ip":
                match = ipv4_pat.match(pattern)
                if match:
                    ip = match.group(1)
                    if not ip:
                        continue
                    if name is None:
                        name = ip

                    parsed_data.append(
                        IP_entry(
                            name=name,
                            low_ip=ip,
                            high_ip=ip,
                            description=description,
                            malware_type=threat_type_str,
                            confidence=confidence,
                            lastSeen=last_seen_time,
                            date_found=created,
                        ).get_dict()
                    )
                else:
                    match = ipv6_pat.match(pattern)
                    if match:
                        ip = match.group(1)
                        parsed_data.append(
                            IP_entry(
                                name=name,
                                low_ip=ip,
                                high_ip=ip,
                                description=description,
                                malware_type=threat_type_str,
                                confidence=confidence,
                                lastSeen=last_seen_time,
                                date_found=created,
                            ).get_dict()
                        )
            elif self.threatfeed_type == "url":
                match = url_pat.match(pattern)
                if match:
                    url = match.group(1)
                    parsed_data.append(
                        URL_entry(
                        url=url,
                        malware_type=threat_type_str,
                        confidence=confidence,
                        lastSeen=last_seen_time,
                    ).get_dict()
                    )
            elif self.threatfeed_type == "site":
                match = domain_pat.match(pattern)
                if match:
                    domain = match.group(1)
                    parsed_data.append(
                        Domain_entry(
                            domainName=domain,
                            description=description,
                            malware_type=threat_type_str,
                            confidence=confidence,
                            lastSeen=last_seen_time,
                            date_found=created,
                        ).get_dict()
                    )

        if len(parsed_data) > 0:
            valid_entries = [entry for entry in parsed_data if entry is not None]
            if len(valid_entries) > 0:
                self.total_loaded_indicators += len(valid_entries)
                self.saveThreatFeedData(valid_entries)


    def stripTAXIIURL(self, url: str) -> str:
        parts = urlsplit(url)
        self.taxii_params = {}
        base_no_params = f"{parts.scheme}://{parts.netloc}{parts.path}"
        pat = re.compile(
            r'^(?P<scheme>https?)://(?P<host>[^/]+)'
            r'(?P<base>/.*?)/collections/(?P<collection>[^/]+)'
            r'(?:/objects(?:/(?P<object>[^/?#]+))?)?/?$'
        )

        m = pat.match(base_no_params.rstrip('/'))
        if not m:
            raise ValueError(f"URL does not look like TAXII collections/objects: {url}")

        self.taxii_proto = m.group("scheme")
        self.taxii_server_hostname = m.group("host")
        self.taxii_server_baseuri = m.group("base").lstrip('/')
        self.taxii_collection = m.group("collection")
        self.taxii_objectid = m.group("object")
        self.objects_url = f"{self.taxii_proto}://{self.taxii_server_hostname}/{self.taxii_server_baseuri}/collections/{self.taxii_collection}/objects/"

        discovery_url = f"{self.taxii_proto}://{self.taxii_server_hostname}/taxii2/"
        match = re.match(r"(.*?/taxii2/)", url)
        if match:
            discovery_url = match.group(1)

        return discovery_url


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description='threatfeed integration')
    arg_parser.add_argument('-updateType', default='full', action='store', type=str)
    arg_parser.add_argument('-appUser', default=None, action='store', type=str)
    arg_parser.add_argument('-appPW', default=None, action='store', type=str)
    arg_parser.add_argument('-appHost', default='https://127.0.0.1', action='store', type=str)
    arg_parser.add_argument('-naturalId', required=True, action='store', type=str)
    arg_parser.add_argument(
        '-tfType',
        required=True,
        action='store',
        type=str,
        choices=['ip', 'url', 'site'],
        help='Indicator type: ip, url, site (site = domain)',
    )
    # Kept for backward compatibility with existing launch templates; ignored by this script.
    arg_parser.add_argument('-tfURL', required=False, default=None, action='store', type=str)
    arg_parser.add_argument('-tfUser', action='store', type=str)
    arg_parser.add_argument('-tfPW', action='store', type=str)
    arg_parser.add_argument('-sslVerify', default="true", action='store', type=str)
    args = arg_parser.parse_args()
    tf_url = resolve_tf_url(args.tfType)

    if args.appUser and args.appPW:
        threatfeed = AnyRunThreatFeed(
            updateType=args.updateType,
            naturalId=args.naturalId,
            tfType=args.tfType,
            tfURL=tf_url,
            tfUser=args.tfUser,
            tfPW=args.tfPW,
            appUser=args.appUser,
            appPW=args.appPW,
            appHost=args.appHost,
            sslVerify=args.sslVerify,
        )
    else:
        threatfeed = AnyRunThreatFeed(
            updateType=args.updateType,
            naturalId=args.naturalId,
            tfType=args.tfType,
            tfURL=tf_url,
            tfUser=args.tfUser,
            tfPW=args.tfPW,
            appHost=args.appHost,
            sslVerify=args.sslVerify,
        )

    threatfeed.getThreatFeedData()
