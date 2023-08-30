#!/usr/bin/env python3
#
# Generate a C-friend policy.h and policy.c file from a given policy.json,
# this results in a set of static declarations that contains the necessary
# policy info for the veracruz-mcu-client. For more info see vc.c.
#
# ## Authors
#
# The Veracruz Development Team.
#
# ## Licensing and copyright notice
#
# See the `LICENSE.md` file in the Veracruz root directory for
# information on licensing and copyright.
#

import argparse
import base64
import hashlib
import json
import sys

# list of support certificates
# TODO fully populate this?
CIPHERSUITES = {
    'TLS1_3_CHACHA20_POLY1305_SHA256': 'MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256',
    'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256': 'MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
}

# convert from a base64 encoded string (.pem) to raw bytes (.der)
def pem_to_der(pem):
    lines = pem.strip().split('\n')
    lines = ''.join(line.strip() for line in lines[1:-1])
    return base64.b64decode(lines)

def main(args):
    print('loading policy %s' % args.policy)
    with open(args.policy) as f:
        policy_raw = f.read()
        policy_hash = hashlib.sha256(policy_raw.encode('utf-8')).hexdigest()
        policy = json.loads(policy_raw)

        # go ahead and grab CA cert
        ca_cert_der = pem_to_der(policy['proxy_service_cert'])
        ca_cert_hash = hashlib.sha256(ca_cert_der).hexdigest()

        # grab hashes
        runtime_hashes = [v for k, v in policy.items()
            if k.startswith('runtime_manager_hash_')
            if v]

    if args.identity:
        print('loading identity %s' % args.identity)
        with open(args.identity) as f:
            identity_pem = f.read()
            identity_der = pem_to_der(identity_pem)
            identity_hash = hashlib.sha256(identity_der).hexdigest()

        # sanity check that identity is in policy
        assert any(
            identity['certificate'].replace('\n', '')
                == identity_pem.replace('\n', '')
            for identity in policy['identities'])

    if args.key:
        print('loading key %s' % args.key)
        with open(args.key) as f:
            key_pem = f.read()
            key_der = pem_to_der(key_pem)

    if args.header:
        print('generating %s for policy %s' % (args.header, policy_hash))
        with open(args.header, 'w') as f:
            _write = f.write
            def write(s='', **args):
                _write(s % args)
            def writeln(s='', **args):
                _write(s % args)
                _write('\n')
            f.write = write
            f.writeln = writeln

            f.writeln('//// AUTOGENERATED ////')
            f.writeln('#ifndef VC_POLICY_H')
            f.writeln('#define VC_POLICY_H')
            f.writeln()
            f.writeln('#include <stdint.h>')
            f.writeln('#include <mbedtls/ssl_ciphersuites.h>')
            f.writeln()
            f.writeln('// general policy things')
            f.writeln('extern const uint8_t _VC_POLICY_HASH[32];')
            f.writeln('#define VC_POLICY_HASH _VC_POLICY_HASH')
            f.writeln()
            f.writeln('// various hashes')
            f.writeln('extern const uint8_t _VC_RUNTIME_HASHES[%(count)d][32];',
                count=len(runtime_hashes))
            f.writeln('#define VC_RUNTIME_HASHES _VC_RUNTIME_HASHES')
            f.writeln()
            f.writeln('// server info')
            f.writeln('#define VC_SERVER_HOST "%(host)s"',
                host=policy['veracruz_server_url'].split(':')[0])
            f.writeln('#define VC_SERVER_PORT %(port)s',
                port=policy['veracruz_server_url'].split(':')[1])
            f.writeln('#define VC_PAS_HOST "%(host)s"',
                host=policy['proxy_attestation_server_url'].split(':')[0])
            f.writeln('#define VC_PAS_PORT %(port)s',
                port=policy['proxy_attestation_server_url'].split(':')[1])
            f.writeln()
            f.writeln('// CA cert')
            f.writeln('extern const uint8_t _VC_CA_CERT_DER[%(len)d];',
                len=len(ca_cert_der))
            f.writeln('#define VC_CA_CERT_DER _VC_CA_CERT_DER')
            f.writeln('extern const uint8_t _VC_CA_CERT_HASH[32];')
            f.writeln('#define VC_CA_CERT_HASH _VC_CA_CERT_HASH')
            f.writeln()
            f.writeln('// ciphersuite requested by the policy, as both a constant')
            f.writeln('// and mbedtls-friendly null-terminated array')
            f.writeln('#define VC_CIPHERSUITE %(ciphersuite)s',
                ciphersuite=CIPHERSUITES[policy['ciphersuite']])
            f.writeln('extern const int _VC_CIPHERSUITES[2];')
            f.writeln('#define VC_CIPHERSUITES _VC_CIPHERSUITES')
            f.writeln()
            f.writeln('// client cert/key')
            if args.identity:
                f.writeln('extern const uint8_t _VC_CLIENT_CERT_DER[%(len)d];',
                    len=len(identity_der))
                f.writeln('#define VC_CLIENT_CERT_DER _VC_CLIENT_CERT_DER')
                f.writeln('extern const uint8_t _VC_CLIENT_CERT_HASH[32];')
                f.writeln('#define VC_CLIENT_CERT_HASH _VC_CLIENT_CERT_HASH')
            if args.key:
                f.writeln('extern const uint8_t _VC_CLIENT_KEY_DER[%(len)d];',
                    len=len(key_der))
                f.writeln('#define VC_CLIENT_KEY_DER _VC_CLIENT_KEY_DER')
            f.writeln()
            f.writeln('#endif')

    if args.source:
        print('generating %s for policy %s' % (args.source, policy_hash))
        with open(args.source, 'w') as f:
            _write = f.write
            def write(s='', **args):
                _write(s % args)
            def writeln(s='', **args):
                _write(s % args)
                _write('\n')
            f.write = write
            f.writeln = writeln

            f.writeln('//// AUTOGENERATED ////')
            f.writeln()
            f.writeln('#include <stdint.h>')
            f.writeln('#include <mbedtls/ssl_ciphersuites.h>')
            f.writeln()
            f.writeln('const uint8_t _VC_POLICY_HASH[32] = {')
            for i in range(0, len(policy_hash)//2, 8):
                f.writeln('    %(hash)s',
                    hash=' '.join('0x%02x,' % int(policy_hash[2*j:2*j+2], 16)
                        for j in range(i, min(i+8, len(policy_hash)//2))))
            f.writeln('};')
            f.writeln()
            f.writeln('const uint8_t _VC_RUNTIME_HASHES[%(count)d][32] = {',
                count=len(runtime_hashes))
            for runtime_hash in runtime_hashes:
                f.writeln('    {')
                for i in range(0, len(runtime_hash)//2, 8):
                    f.writeln('        %(hash)s',
                        hash=' '.join('0x%02x,' % int(runtime_hash[2*j:2*j+2], 16)
                            for j in range(i, min(i+8, len(runtime_hash)//2))))
                f.writeln('    },')
            f.writeln('};')
            f.writeln()
            f.writeln('const uint8_t _VC_CA_CERT_DER[%(len)d] = {',
                len=len(ca_cert_der))
            for i in range(0, len(ca_cert_der), 8):
                f.writeln('    %(der)s',
                    der=' '.join('0x%02x,' % ca_cert_der[j]
                        for j in range(i, min(i+8, len(ca_cert_der)))))
            f.writeln('};')
            f.writeln()
            f.writeln('const uint8_t _VC_CA_CERT_HASH[32] = {')
            for i in range(0, len(ca_cert_hash)//2, 8):
                f.writeln('    %(der)s',
                    der=' '.join('0x%02x,' % int(ca_cert_hash[2*j:2*j+2], 16)
                        for j in range(i, min(i+8, len(ca_cert_hash)//2))))
            f.writeln('};')
            f.writeln()
            f.writeln('const int _VC_CIPHERSUITES[2] = {')
            f.writeln('    %(ciphersuite)s,',
                ciphersuite=CIPHERSUITES[policy['ciphersuite']])
            f.writeln('    0,')
            f.writeln('};')
            f.writeln()
            if args.identity:
                f.writeln('const uint8_t _VC_CLIENT_CERT_DER[%(len)d] = {',
                    len=len(identity_der))
                for i in range(0, len(identity_der), 8):
                    f.writeln('    %(der)s',
                        der=' '.join('0x%02x,' % identity_der[j]
                            for j in range(i, min(i+8, len(identity_der)))))
                f.writeln('};')
                f.writeln()
                f.writeln('const uint8_t _VC_CLIENT_CERT_HASH[32] = {')
                for i in range(0, len(identity_hash)//2, 8):
                    f.writeln('    %(der)s',
                        der=' '.join('0x%02x,' % int(identity_hash[2*j:2*j+2], 16)
                            for j in range(i, min(i+8, len(identity_hash)//2))))
                f.writeln('};')
                f.writeln()
            if args.key:
                f.writeln('const uint8_t _VC_CLIENT_KEY_DER[%(len)d] = {',
                    len=len(key_der))
                for i in range(0, len(key_der), 8):
                    f.writeln('    %(der)s',
                        der=' '.join('0x%02x,' % key_der[j]
                            for j in range(i, min(i+8, len(key_der)))))
                f.writeln('};')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Generate header file from Veracruz policy')
    parser.add_argument('policy',
        help='Veracruz policy file (.json)')
    parser.add_argument('--header',
        help='Output header file (.h)')
    parser.add_argument('--source',
        help='Output source file (.c)')
    parser.add_argument('--identity',
        help='Identity of client (.pem)')
    parser.add_argument('--key',
        help='Private key of client (.pem)')
    args = parser.parse_args()
    main(args)