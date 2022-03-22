#!/usr/bin/python3

from bigrest.bigip import BIGIP
import json
import logging
import os
import requests
import sys

requests.packages.urllib3.disable_warnings()


def get_credentials():
    return {'host': os.getenv('F5_HOST'), 'user': os.getenv('F5_USER'), 'pass': os.getenv('F5_PASS')}


def instantiate_bigip(credentials):
    return BIGIP(credentials.get('host'), credentials.get('user'), credentials.get('pass'))


def alter_template(token_info):
    with open('challenge.irule', 'r') as f2:
        new_challenge = ''
        for line in f2:
            new_line = line.rstrip()
            new_line = new_line.replace('TOKENFILE', token_info[0])
            new_line = new_line.replace('TOKENVALUE', token_info[1])
            new_challenge += f'{new_line}\n'
    return new_challenge


def deploy_challenge(args):
    new_irule = alter_template(args[1:])
    br = instantiate_bigip(get_credentials())
    if br.exist('/mgmt/tm/ltm/rule/le_challenge_rule'):
        rule = br.load('/mgmt/tm/ltm/rule/le_challenge_rule')
        rule.properties['apiAnonymous'] = new_irule
        br.save(rule)
        vip = br.load('/mgmt/tm/ltm/virtual/external_http_test')
        if vip.properties.get('rules') is None:
            vip.properties['rules'] = ['le_challenge_rule']
        else:
            vip.properties['rules'].append('le_challenge_rule')
        br.save(vip)
    else:
        ltm_rule_object = {'name': 'le_challenge_rule', '': new_irule}
        br.create('/mgmt/tm/ltm/rule', ltm_rule_object)
        if br.exist('/mgmt/tm/ltm/rule/le_challenge_rule'):
            vip = br.load('/mgmt/tm/ltm/virtual/external_http_test')
            vip.properties['rules'].append('le_challenge_rule')
            br.save(vip)
    logger.info(' + (hook) Challenge rule added to virtual.')


def invalid_challenge(args):
    logger.info(f' + (hook) Invalid Challenge Args: {args}')


def clean_challenge(args):
    br = instantiate_bigip(get_credentials())
    vip = br.load('/mgmt/tm/ltm/virtual/external_http_test')
    vip.properties['rules'].remove('/Common/le_challenge_rule')
    br.save(vip)
    logger.info(' + (hook) Challenge rule removed from virtual.')


def deploy_cert(args):
    br = instantiate_bigip(get_credentials())
    br.upload('/mgmt/shared/file-transfer/uploads', args[1])
    br.upload('/mgmt/shared/file-transfer/uploads', args[2])
    br.upload('/mgmt/shared/file-transfer/uploads', args[4])
    key_status = br.exist(f'/mgmt/tm/sys/file/ssl-key/le_auto_{args[0]}.key')
    cert_status = br.exist(f'/mgmt/tm/sys/file/ssl-cert/le_auto_{args[0]}.crt')
    chain_status = br.exist(f'/mgmt/tm/sys/file/ssl-cert/le_auto_chain.crt')

    if key_status and cert_status and chain_status:
        with br as transaction:
            modkey = br.load(f'/mgmt/tm/sys/file/ssl-key/le_auto_{args[0]}.key')
            modkey.properties['sourcePath'] = f'file:/var/config/rest/downloads/{args[1].split("/")[-1]}'
            br.save(modkey)
            modcert = br.load(f'/mgmt/tm/sys/file/ssl-cert/le_auto_{args[0]}.crt')
            modcert.properties['sourcePath'] = f'file:/var/config/rest/downloads/{args[2].split("/")[-1]}'
            br.save(modcert)
            modchain = br.load(f'/mgmt/tm/sys/file/ssl-cert/le_auto_chain.crt')
            modchain.properties['sourcePath'] = f'file:/var/config/rest/downloads/{args[4].split("/")[-1]}'
            br.save(modchain)
            logger.info(' + (hook) Existing Cert/Key updated in transaction.')
    else:
        keydata = {'name': f'le_auto_{args[0]}.key', 'sourcePath': f'file:/var/config/rest/downloads/{args[1].split("/")[-1]}'}
        certdata = {'name': f'le_auto_{args[0]}.crt', 'sourcePath': f'file:/var/config/rest/downloads/{args[2].split("/")[-1]}'}
        chaindata = {'name': f'le_auto_chain.crt', 'sourcePath': f'file:/var/config/rest/downloads/{args[4].split("/")[-1]}'}
        br.create('/mgmt/tm/sys/file/ssl-key', keydata)
        br.create('/mgmt/tm/sys/file/ssl-cert', certdata)
        br.create('/mgmt/tm/sys/file/ssl-cert', chaindata)
        logger.info(' + (hook) New Certificate/Key/Chain created.')


def unchanged_cert(args):
    logger.info(f' + (hook) No changes necessary.')


if __name__ == '__main__':
    # Logging
    logger = logging.getLogger(__name__)
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.INFO)

    if len(sys.argv) > 2:
        hook = sys.argv[1]
    else:
        hook = ''
    if hook == 'deploy_challenge':
        logger.info(' + (hook) Deploying Challenge')
        deploy_challenge(sys.argv[2:])
    elif hook == 'invalid_challenge':
        logger.info(' + (hook) Invalid Challenge')
        invalid_challenge(sys.argv[2:])
    elif hook == 'clean_challenge':
        logger.info(' + (hook) Cleaning Challenge')
        clean_challenge(sys.argv[2:])
    elif hook == 'deploy_cert':
        logger.info(' + (hook) Deploying Certs')
        deploy_cert(sys.argv[2:])
    elif hook == 'unchanged_cert':
        logger.info(' + (hook) Unchanged Certs')
        unchanged_cert(sys.argv[2:])
