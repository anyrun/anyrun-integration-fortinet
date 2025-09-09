#!/usr/bin/env python3.9
# ANY.RUN Threatfeed Integration
import argparse
import traceback
from datetime import datetime, timedelta
from typing import Union

from utils.threatfeed_integration import (
    ThreatfeedIntegration,
    IP_entry,
    Domain_entry,
    URL_entry
)
from anyrun.connectors import FeedsConnector
from anyrun.iterators import FeedsIterator
from anyrun import RunTimeException


class AnyRunThreatFeed(ThreatfeedIntegration):
    """ Provides some methods to load ANY.RUN indicators to FortiSIEM """
    def getThreatFeedData(self) -> None:
        """ The connector entrypoint """
        if self.threatfeed_username or not self.threatfeed_password:
            print(
                '[ANY.RUN] You must specify ANY.RUN TI Feeds Basic token in the password field. '
                'Username is not required.'
            )
            exit(1)

        with FeedsConnector(f'Basic {self.threatfeed_password}', integration='FortiSIEM:1.0.0') as connector:
            try:
                connector.check_authorization()
                self._get_feeds(connector, {'url': 'url', 'ip': 'ip', 'site': 'domain'}.get(self.threatfeed_type))
            except RunTimeException as exception:
                print(str(exception))
                exit(1)
            except Exception:
                print(f'Unspecified exception: {traceback.format_exc()}')
                exit(1)

    def _get_feeds(self, connector: FeedsConnector, feed_collection: str) -> None:
        """
        Loads ANY.RUN TI Feeds for the specified period. Then loads them to the FortiSIEM

        :param connector: ANY.RUN connector
        :param feed_collection: TAXII STIX collection ID
        """
        if not feed_collection:
            print(f"[ANY.RUN] Received invalid feed type: {self.threatfeed_type}. Use IP, URL, Domain.")
            exit(1)

        feeds: list[Union[IP_entry, Domain_entry, URL_entry]] = []
        for chunk in FeedsIterator.taxii_stix(
            connector,
            chunk_size=10000,
            limit=10000,
            match_revoked=False,
            modified_after=(datetime.now() - timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            match_version='all',
            collection=feed_collection
        ):
            for feed in chunk:
                if feed_collection == 'url':
                    feeds.append(
                        URL_entry(
                            url=self._get_feed_value(feed),
                            description=','.join(feed.get('labels')) if feed.get('labels') else '',
                            lastSeen=feed.get('modified_after'),
                            confidence=feed.get('confidence')
                        ).get_dict()
                    )
                if feed_collection == 'ip':
                    feeds.append(
                        IP_entry(
                            name=self._get_feed_value(feed),
                            low_ip=self._get_feed_value(feed),
                            description=','.join(feed.get('labels')) if feed.get('labels') else '',
                            lastSeen=feed.get('modified_after'),
                            date_found=datetime.strptime(feed.get('created'), '%Y-%m-%dT%H:%M:%S.%fZ'),
                            confidence=feed.get('confidence')
                        ).get_dict()
                    )
                if feed_collection == 'domain':
                    feeds.append(
                        Domain_entry(
                            domainName=self._get_feed_value(feed),
                            description=','.join(feed.get('labels')) if feed.get('labels') else '',
                            lastSeen=feed.get('modified_after'),
                            date_found=datetime.strptime(feed.get('created'), '%Y-%m-%dT%H:%M:%S.%fZ'),
                            confidence=feed.get('confidence')
                        ).get_dict()
                    )

            self.saveThreatFeedData(feeds)
            print(f'[ANY.RUN] Successfully loaded {len(feeds)} indicators')
            feeds.clear()

        if 'chunk' not in locals():
            print("[ANY.RUN] No feeds found in the last 90 days.")


    @staticmethod
    def _get_feed_value(feed: dict) -> str:
        """
        Extracts indicator value from the pattern field

        :param feed: ANY.RUN indicator
        :return: Indicator value
        """
        pattern = feed.get("pattern")
        return pattern.split(" = '")[1][:-2]


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description='Threatfeed integration')
    arg_parser.add_argument('-updateType', required=True, action='store', type=str)
    arg_parser.add_argument('-appUser', default=None, action='store', type=str)
    arg_parser.add_argument('-appPW', default=None, action='store', type=str)
    arg_parser.add_argument('-appHost', default='https://127.0.0.1', action='store', type=str)
    arg_parser.add_argument('-naturalId', required=True, action='store', type=str)
    arg_parser.add_argument('-tfType', required=True, action='store', type=str)
    arg_parser.add_argument('-tfURL', required=True, action='store', type=str)
    arg_parser.add_argument('-tfUser', action='store', type=str)
    arg_parser.add_argument('-tfPW', action='store', type=str)
    arg_parser.add_argument('-sslVerify', default="true", action='store', type=str)
    args = arg_parser.parse_args()

    # Creating an instance of the AnyRunThreatFeed
    threatfeed = AnyRunThreatFeed(
        updateType=args.updateType,
        naturalId=args.naturalId,
        tfType=args.tfType,
        tfURL=args.tfURL,
        tfUser=args.tfUser,
        tfPW=args.tfPW,
        appUser=args.appUser,
        appPW=args.appPW,
        appHost=args.appHost,
        sslVerify=args.sslVerify
    )

    threatfeed.getThreatFeedData()
