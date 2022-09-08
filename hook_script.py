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

def deploy_challenge(args):
    br = instantiate_bigip(get_credentials())
    f = open('rule_le_challenge.iRule')
    irule = f.read()
    f.close()
    if not br.exist('/mgmt/tm/ltm/rule/rule_le_challenge'):
        rule = {'name': 'rule_le_challenge', 'apiAnonymous': irule}
        br.create('/mgmt/tm/ltm/rule', rule)
        logger.info(' + (hook) irule rule_le_challenge added.')
    if not br.exist('/mgmt/tm/ltm/data-group/internal/dg_le_challenge'):
        dg = {'name': 'dg_le_challenge', 'type': 'string', 'records': [{'name':'name','data':'data'}]}
        br.create('/mgmt/tm/ltm/data-group/internal', dg)
        logger.info(' + (hook) datagroup dg_le_challenge added.')
    if br.exist('/mgmt/tm/ltm/rule/rule_le_challenge'):
        vip = br.load(f'/mgmt/tm/ltm/virtual/{f5_http}')
        if '/Common/rule_le_challenge' not in vip.properties['rules']:
            if vip.properties.get('rules') is None:
                vip.properties['rules'] = ['rule_le_challenge']
            elif not '/mgmt/tm/ltm/rule/rule_le_challenge' in vip.properties['rules']:
                vip.properties['rules'].insert(0,'rule_le_challenge')
            br.save(vip)
            logger.info(f' + (hook) Challenge rule added to virtual {f5_http}.')
    dg = br.load('/mgmt/tm/ltm/data-group/internal/dg_le_challenge')
    dg.properties['records'].append({'name':args[1],'data':args[2]})
    br.save(dg)
    logger.info(f' + (hook) Challenge added to datagroup dg_le_challenge for {args[0]}.')

def invalid_challenge(args):
    logger.info(f' + (hook) Invalid Challenge Args: {args}')
    sys.exit(-1)

def clean_challenge(args):
    br = instantiate_bigip(get_credentials())
    vip = br.load(f'/mgmt/tm/ltm/virtual/{f5_http}')
    if '/Common/rule_le_challenge' in vip.properties['rules']:
        vip.properties['rules'].remove('/Common/rule_le_challenge')
        br.save(vip)
        logger.info(f' + (hook) Challenge rule rule_le_challenge removed from virtual {f5_http}.')
    if br.exist('/mgmt/tm/ltm/rule/rule_le_challenge'):
        br.delete('/mgmt/tm/ltm/rule/rule_le_challenge')
        logger.info(f' + (hook) irule rule_le_challenge removed.')
    if br.exist('/mgmt/tm/ltm/data-group/internal/dg_le_challenge'):
        br.delete('/mgmt/tm/ltm/data-group/internal/dg_le_challenge')
        logger.info(' + (hook) datagroup dg_le_challenge removed.')

def deploy_cert(args):
    br = instantiate_bigip(get_credentials())
    br.upload('/mgmt/shared/file-transfer/uploads', args[1])
    br.upload('/mgmt/shared/file-transfer/uploads', args[3])
    key_status = br.exist(f'/mgmt/tm/sys/file/ssl-key/auto_le_{args[0]}.key')
    cert_status = br.exist(f'/mgmt/tm/sys/file/ssl-cert/auto_le_{args[0]}.crt')

    if key_status and cert_status:
        with br as transaction:
            modkey = br.load(f'/mgmt/tm/sys/file/ssl-key/auto_le_{args[0]}.key')
            modkey.properties['sourcePath'] = f'file:/var/config/rest/downloads/{args[1].split("/")[-1]}'
            br.save(modkey)
            modcert = br.load(f'/mgmt/tm/sys/file/ssl-cert/auto_le_{args[0]}.crt')
            modcert.properties['sourcePath'] = f'file:/var/config/rest/downloads/{args[3].split("/")[-1]}'
            br.save(modcert)
            logger.info(f' + (hook) Cert/Key {args[0]} updated in transaction.')
    else:
        keydata = {'name': f'auto_le_{args[0]}.key', 'sourcePath': f'file:/var/config/rest/downloads/{args[1].split("/")[-1]}'}
        certdata = {'name': f'auto_le_{args[0]}.crt', 'sourcePath': f'file:/var/config/rest/downloads/{args[3].split("/")[-1]}'}
        br.create('/mgmt/tm/sys/file/ssl-key', keydata)
        br.create('/mgmt/tm/sys/file/ssl-cert', certdata)
        logger.info(f' + (hook) Cert/Key {args[0]} created.')
    if not br.exist(f'/mgmt/tm/ltm/profile/client-ssl/auto_le_{args[0]}'):
        sslprof = {
            'name' : f'auto_le_{args[0]}',
            'defaultsFrom': '/Common/clientssl',
            'certKeyChain': [{
                'name': f'{args[0]}_0',
                'cert': f'/Common/auto_le_{args[0]}.crt',
                'key': f'/Common/auto_le_{args[0]}.key'
            }]
        }
        logger.info(sslprof)
        br.create('/mgmt/tm/ltm/profile/client-ssl', sslprof)
        logger.info(f' + (hook) client-ssl profile created auto_le_{args[0]}.')
    #profiles = br.load(f'/mgmt/tm/ltm/virtual/{f5_https}/profiles')
    #logger.info(profiles)

def unchanged_cert(args):
    logger.info(f' + (hook) No changes necessary.')

if __name__ == '__main__':
    # Logging
    logger = logging.getLogger(__name__)
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.INFO)

    # get virtualserver names from environment
    f5_http = os.getenv('F5_HTTP')
    f5_https = os.getenv('F5_HTTPS')

    if len(sys.argv) > 2:
        hook = sys.argv[1]
    else:
        hook = ''
    if hook == 'deploy_challenge':
        logger.info(f' + (hook) Deploying Challenge {sys.argv[2]}')
        deploy_challenge(sys.argv[2:])
    elif hook == 'invalid_challenge':
        logger.info(f' + (hook) Invalid Challenge {sys.argv[2]}')
        invalid_challenge(sys.argv[2:])
    elif hook == 'clean_challenge':
        logger.info(f' + (hook) Cleaning Challenge {sys.argv[2]}')
        clean_challenge(sys.argv[2:])
    elif hook == 'deploy_cert':
        logger.info(f' + (hook) Deploying Certs {sys.argv[2]}')
        deploy_cert(sys.argv[2:])
    elif hook == 'unchanged_cert':
        logger.info(f' + (hook) Unchanged Certs {sys.argv[2]}')
        unchanged_cert(sys.argv[2:])
