import copy
import datetime
import json
import logging
import os
import re
import subprocess
import time

import requests
from certbot import errors
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for NGENIX
    This Authenticator uses the NGENIX Remote REST API to fulfill a dns-01 challenge.
    """

    description = "DNS Authenticator for NGENIX"

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=0
        )
        add('customer-id', help='Customer ID at NGENIX.')
        add('name', help='NGENIX name')
        add('token', help='NGENIX token')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using NGENIX API.'

    def _setup_credentials(self):
        return

    def _perform(self, domain, validation_name, validation):
        self._get_ngenix_client().add_txt_record(
            domain, validation_name, validation
        )

    def _cleanup(self, domain, validation_name, validation):
        self._get_ngenix_client().delete_txt_record(
            domain, validation_name, validation
        )

    def _get_ngenix_client(self):
        return _NGENIXClient(
            self.conf('customer-id'),
            self.conf('name'),
            self.conf('token'),
        )


class _NGENIXClient(object):
    """
    Encapsulates all communication with NGENIX Remote REST API.
    """

    headers = {
        'Content-Type': 'application/json',
        'accept': 'application/json'
    }
    ngenix_api_host = 'https://api.ngenix.net/api/v3'

    def __init__(self, customer_id, ngenix_name, ngenix_token):
        logger.debug("creating ngenix client")
        self.params = {
            'customerId': customer_id
        }
        self.auth = (f'{ngenix_name}/token', ngenix_token)
        self.session = requests.Session()

    def add_txt_record(self, domain, record_name, record_content):
        """
        Add a TXT record using the supplied information.
        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with NGENIX API
        """
        try:
            regex = r'(.*)'
            for i in range(4):
                if i != 0:
                    regex = rf'.*?\.{regex}'
                try:
                    domain_zone = re.search(regex, domain).group(1)  # matches domain zone
                    dns_zone_id = self._get_dns_zone_id(domain_zone)
                    break
                except Exception:
                    if i == 3:
                        raise errors.PluginError(
                            f'Error occurred while trying to get domain zone name.\n'
                        )
                    continue
            dns_zone_records = self._get_dns_zone_records(dns_zone_id)
            logger.info(f'Creating backup file with DNS zone records for domain zone {domain_zone} before adding the new record.')
            self._create_backup_file(dns_zone_id, domain_zone, dns_zone_records, 'before')
            new_record_name = re.sub(rf'\.{domain_zone}$', '', record_name)
            new_dns_zone_records = self._add_txt_record(new_record_name, record_content, dns_zone_records)
            logger.info(f'Adding TXT record {new_record_name} into domain zone {domain_zone}.')
            self._update_dns_zone_records(dns_zone_id, new_dns_zone_records)
            self._wait_for_record_propagation(record_name, record_content)
        except Exception as e:
            raise errors.PluginError(
                f'Error occurred while trying to add TXT record.\n'
                f'Error text: {str(e)}.\n'
            )

    def delete_txt_record(self, domain, record_name, record_content):
        """
        Delete a TXT record using the supplied information.
        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with NGENIX API
        """
        try:
            regex = r'(.*)'
            for i in range(4):
                if i != 0:
                    regex = rf'.*?\.{regex}'
                try:
                    domain_zone = re.search(regex, domain).group(1)  # matches domain zone
                    dns_zone_id = self._get_dns_zone_id(domain_zone)
                    break
                except Exception as e:
                    if i == 3:
                        raise errors.PluginError(
                            f'Error occurred while trying to get domain zone name and id.\n'
                            f'Error text: {str(e)}.\n'
                        )
                    continue
            dns_zone_records = self._get_dns_zone_records(dns_zone_id)
            new_record_name = re.sub(rf'\.{domain_zone}$', '', record_name)
            logger.info(f'Deleting TXT record {new_record_name} from domain zone {domain_zone}.')
            new_dns_zone_records = self._delete_txt_record(new_record_name, record_content, dns_zone_records)
            self._update_dns_zone_records(dns_zone_id, new_dns_zone_records)
            logger.info(f'Creating backup file with DNS zone records for domain zone {domain_zone} after deleting the new record.')
            self._create_backup_file(dns_zone_id, domain_zone, dns_zone_records, 'after')
        except Exception as e:
            raise errors.PluginError(
                f'Error occurred while trying to delete TXT record.\n'
                f'Error text: {str(e)}.\n'
            )

    def _create_backup_file(self, dns_zone_id, domain, dns_zone_records, tag=None):
        current_time = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        file_name = f'{domain}.{current_time}.{tag}.json' if tag else f'{domain}.{current_time}.json'
        file_path = os.path.join(os.sep, 'tmp', 'ngenix-dns-zone', file_name)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w') as file:
            file.write(f'{dns_zone_id}\n')
            file.write(json.dumps(dns_zone_records))
        return file_path

    def _add_txt_record(self, record_name, record_data, dns_zone_records):
        new_dns_zone_records = copy.deepcopy(dns_zone_records)
        new_record = {'data': record_data, 'name': record_name, 'type': 'TXT'}
        new_dns_zone_records.append(new_record)
        return new_dns_zone_records

    def _delete_txt_record(self, record_name, record_data, dns_zone_records):
        new_dns_zone_records = copy.deepcopy(dns_zone_records)
        deleted_record = {'data': record_data, 'name': record_name, 'type': 'TXT'}
        new_dns_zone_records = [record for record in dns_zone_records if record != deleted_record]
        return new_dns_zone_records

    def _update_dns_zone_records(self, dns_zone_id, new_dns_zone_records):
        for record in new_dns_zone_records:
            if 'configRef' in record:
                ref = 'configRef'
            elif 'targetGroupRef' in record:
                ref = 'targetGroupRef'
            else:
                continue
            record[ref].pop('link', None)

        try:
            new_records = {'records': new_dns_zone_records}
            update_dns_zone_records_res = requests.patch(f'{self.ngenix_api_host}/dns-zone/{dns_zone_id}',
                                                         headers=self.headers, auth=self.auth, data=json.dumps(new_records), timeout=5)
            updated_dns_zone_records = update_dns_zone_records_res.json()['records']
        except Exception:
            raise errors.PluginError(
                f'Error occurred while trying to update records in dns zone {dns_zone_id}.\n'
                f'Error status code: {update_dns_zone_records_res.status_code}.\n'
                f'Error text: {update_dns_zone_records_res.text}.\n'
            )

        return updated_dns_zone_records

    def _get_dns_zone_id(self, domain):
        try:
            dns_zones_res = requests.get(f'{self.ngenix_api_host}/dns-zone',
                                         headers=self.headers, params=self.params, auth=self.auth, timeout=3)
            dns_zones = dns_zones_res.json()['elements']
        except Exception:
            raise errors.PluginError(
                f'Error occurred while trying to get a list of dns zones for customer {self.params["customerId"]}.\n'
                f'Error status code: {dns_zones_res.status_code}.\n'
                f'Error text: {dns_zones_res.text}.\n'
            )

        try:
            dns_zone_info = [dns_zone for dns_zone in dns_zones if dns_zone['name'] == domain][0]
            dns_zone_id = dns_zone_info['id']
        except Exception:
            raise errors.PluginError(
                f'Error occurred while trying to get dns zone id for domain {domain}.\n'
            )

        return dns_zone_id

    def _get_dns_zone_records(self, dns_zone_id):
        try:
            dns_zone_res = requests.get(f'{self.ngenix_api_host}/dns-zone/{dns_zone_id}',
                                        headers=self.headers, auth=self.auth, timeout=3)
            dns_zone = dns_zone_res.json()
            dns_zone_records = dns_zone['records']
        except Exception:
            raise errors.PluginError(
                f'Error occurred while trying to get dns zone {dns_zone_id}.\n'
                f'Error status code: {dns_zone_res.status_code}.\n'
                f'Error text: {dns_zone_res.text}.\n'
            )

        return dns_zone_records

    def _wait_for_record_propagation(self, record_name, record_data):
        dig_txt = f'dig @8.8.8.8 -t TXT {record_name} +short'
        logger.info(f'Waiting for {record_name} propagation.')
        txt_records = [txt_record[1:-1] for txt_record in subprocess.check_output(dig_txt.split()).decode('utf-8').splitlines()]
        counter = 15
        while record_data not in txt_records:
            txt_records = [txt_record[1:-1] for txt_record in subprocess.check_output(dig_txt.split()).decode('utf-8').splitlines()]
            counter -= 1
            if counter == 0:
                raise errors.PluginError(
                    f'Maximum amount of retries reached while trying to get new TXT record {record_name}.\n'
                )
            logger.info(f'Waiting for {counter} more minute(s) till {record_name} propagation.')
            time.sleep(60)
