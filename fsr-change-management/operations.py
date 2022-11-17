"""
Copyright start
Copyright (C) 2008 - 2022 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""
import os
import hashlib
import hmac
import json
import base64
from datetime import datetime

import requests
from connectors.core.connector import get_logger, ConnectorError
from django.conf import settings

try:
    from connectors.cyops_utilities.builtins import download_file_from_cyops
except:
    pass
DEFAULT_ALGORITHM = "sha256"
logger = get_logger('fsr-change-management')


class ChnageManagement(object):
    def __init__(self, config):
        self.cert_file_iri = config.get('cert_file', {}).get('@id')
        self.verify_ssl = config.get('verify_ssl', False)


def __get_headers(full_uri, data, private_key, public_key, verb='POST'):
    payload = data.encode('utf-8')
    digest_method = hashlib.new(DEFAULT_ALGORITHM)
    digest_method.update(payload)
    hashed_payload = digest_method.hexdigest()
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    raw_fingerprint = "{0}.{1}.{2}.{3}.{4}".format(DEFAULT_ALGORITHM,
                                                   verb,
                                                   timestamp,
                                                   full_uri,
                                                   hashed_payload)
    hashed = hmac.new(
        bytes(private_key, encoding='utf8') if isinstance(private_key, str) else private_key,
        raw_fingerprint.encode(),
        hashlib.sha256)
    hashedFingerprint = hashed.hexdigest()
    header = base64.b64encode(
        '{0};{1};{2};{3}'.format(DEFAULT_ALGORITHM, timestamp, public_key,
                                 hashedFingerprint).encode())
    return 'CS {}'.format(header.decode())


def read_config_file(config, *args, **kwargs):
    cr = ChnageManagement(config)
    metadata = download_file_from_cyops(cr.cert_file_iri, None, *args, **kwargs)
    file_name = metadata.get('cyops_file_path', None)
    file_path = os.path.join(settings.TMP_FILE_ROOT, file_name)
    with open(file_path, 'rb') as attachment:
        file_data = attachment.read()
    if isinstance(file_data, bytes):
        file_data = file_data.decode("utf-8")
        return json.loads(file_data)


def sync_change_request(config, params, *args, **kwargs):
    try:
        file_data = read_config_file(config, *args, **kwargs)
        public_key = file_data.get('public_key', '')
        private_key = file_data.get('private_key', '')
        api_endpoint = file_data.get('api_endpoint', '')
        full_url = api_endpoint
        method = 'POST'
        payload = params.get('cr_payload')
        data = json.dumps(payload)
        auth_header = __get_headers(full_url, data, private_key, public_key)
        headers = {'Authorization': auth_header}
        response = requests.request(method, full_url, headers=headers, data=data, verify=False)
        return response.json()
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def _check_health(config, *args, **kwargs):
    try:
        file_data = read_config_file(config, *args, **kwargs)
        keys = ["public_key", 'private_key', 'api_endpoint', 'server_type']
        present = False
        for key in keys:
            if key in file_data:
                present = True
            else:
                present = False
                break
        if present:
            logger.info("connector available")
            return True
        else:
            raise Exception("Not Valid Specification File")
    except Exception as e:
        logger.error("Health check failed.")
        raise ConnectorError(e)


operations = {
    'sync_change_request': sync_change_request,
}
