import json
import base64
import random
import hashlib
import logging
from functools import cached_property

import requests
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

log = logging.getLogger(__name__)


class DahuaDevice:
    def __init__(self, host):
        self.host = host
        self.uri = f'http://{self.host}/RPC2'
        self.login_uri = f'http://{self.host}/RPC2_Login'
        self.last_request_id = 0
        self.session_id = None
        self.key = None
        self.username = None
        self.password = None

    def request(self, method, params, uri=None, raise_for_result=True):
        if uri is None:
            uri = self.uri

        self.last_request_id += 1

        body = {
            'method': method,
            'params': params,
            'id': self.last_request_id,
        }

        headers={}

        if self.session_id:
            body['session'] = self.session_id

        resp = requests.post(uri, data=json.dumps(body), headers=headers)
        resp.raise_for_status()
        resp_body = resp.json()
        self.session_id = resp_body.get('session')

        if raise_for_result and not resp_body['result']:
            err = DahuaError(resp_body['error']['code'], resp_body['error']['message'])
            if err.code == 287637505:
                log.error('Session error: %s', err.message)
                log.info('Relogging...')
                self.login(self.username, self.password)
                return self.request(method, params, uri=uri, raise_for_result=raise_for_result)
            else:
                raise err

        return resp_body

    def login(self, username, password):
        self.username = username
        self.password = password

        dahua_json = self.request('global.login', {
            "userName": "admin",
            "password": "",
            "clientType": "Dahua3.0-Web3.0"
        }, uri=self.login_uri, raise_for_result=False)

        encryption = dahua_json['params']['encryption']

        if encryption == 'Default':
            self.key = dahua_md5_hash(dahua_json['params']['random'], dahua_json['params']['realm'], username, password)
        elif encryption == 'OldDigest':
            self.key = sofia_hash(password)
        else:
            raise Exception('Unknown encryption', encryption)

        resp = self.request('global.login', {
            "userName": username,
            "password": self.key,
            "clientType": "Dahua3.0-Web3.0",
            "authorityType": "Default",
            "passwordType": "Default"
        }, uri=self.login_uri)

        return resp

    def logout(self):
        if not self.session_id:
            return

        self.request('global.logout', '')
        self.last_request_id = 0
        self.session_id = None
        del self.rsa_pub_key

    @cached_property
    def rsa_pub_key(self):
        encrypt_info = self.request('Security.getEncryptInfo', '')
        pub_key = {p[0]: p[1] for p in (p.split(':') for p in encrypt_info['params']['pub'].split(','))}
        return RSA.construct((int(pub_key['N'], 16), int(pub_key['E'], 16)))

    def secure_request(self, method, params, raise_for_result=True):
        def gen_password(ln):
            if ln > 16:
                ln = 16
            rnd = str(random.random())
            if rnd[len(rnd)-ln: 1] == '0':
                return gen_password(ln)
            else:
                return rnd[len(rnd)-ln:]

        def pad(data):
            block_size = 16
            bytes_to_add = block_size - ((len(data) % block_size) or block_size)
            return data + (b'\0' * bytes_to_add)

        def unpad(data):
            while data[-1] == 0:
                data = data[:-1]
            return data

        password = gen_password(16).encode('utf-8')

        cipher = PKCS1_v1_5.new(self.rsa_pub_key)
        salt = cipher.encrypt(password).hex()

        cipher = AES.new(password, AES.MODE_ECB)
        body = pad(json.dumps(params).encode('utf-8'))

        content = base64.b64encode(cipher.encrypt(body)).decode('ascii')

        ret = self.request(method, {
            'salt': salt,
            'cipher': 'AES-128',
            'content': content,
        }, raise_for_result=raise_for_result)

        content = base64.b64decode(ret['params']['content'])
        body = unpad(cipher.decrypt(content))

        params = json.loads(body)
        ret['params'] = params

        return ret


def dahua_md5_hash(dahua_random, dahua_realm, username, password):
    str1 = username + ':' + dahua_realm + ':' + password
    hash1 = hashlib.md5(str1.encode()).hexdigest().upper()
    str2 = username + ':' + dahua_random + ':' + hash1
    hash2 = hashlib.md5(str2.encode()).hexdigest().upper()
    return hash2


# From: https://github.com/tothi/pwn-hisilicon-dvr
# Xiongmaitech and Dahua share same 48bit password hash
def sofia_hash(msg):
    h = ""
    m = hashlib.md5()
    m.update(msg)
    msg_md5 = m.digest()
    for i in range(8):
        n = (ord(msg_md5[2*i]) + ord(msg_md5[2*i+1])) % 0x3e
        if n > 9:
            if n > 35:
                n += 61
            else:
                n += 55
        else:
            n += 0x30
        h += chr(n)
    return h


class DahuaError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(code, message)
        self.code = code
        self.message = message
