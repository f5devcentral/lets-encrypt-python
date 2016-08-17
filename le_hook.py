#!/usr/bin/python

import requests
import json
import logging
import dns.resolver
from tldextract import extract
from f5.bigip import ManagementRoot
import os
import sys
import time

requests.packages.urllib3.disable_warnings()

# slurp credentials
with open('config/creds.json', 'r') as f:
    config = json.load(f)
f.close()

api_host = config['dnshost']
api_acct = config['dnsacct']
api_token = config['apitoken']
f5_host = config['f5host']
f5_user = config['f5acct']
f5_password = config['f5pw']

# Logging
logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

# Name.com Nameservers
dns_servers = []
for ns in range(1, 5):
    dns_servers.append('ns%d.name.com' % ns)

# Resolve IPs for nameservers
resolver = dns.resolver.Resolver()
namedotcom_dns_servers = [item.address for server in dns_servers
                          for item in resolver.query(server)]


def _has_dns_propagated(name, token):
    successes = 0
    for dns_server in namedotcom_dns_servers:
        resolver.nameservers = [dns_server]

        try:
            dns_response = resolver.query(name, 'txt')
        except dns.exception.DNSException as error:
            return False

        text_records = [record.strings[0] for record in dns_response]
        for text_record in text_records:
            if text_record == token:
                successes += 1

    if successes == 4:
        logger.info(" + (hook) All challenge records found!")
        return True
    else:
        return False


def create_txt_record(args):
    """
    Create a TXT DNS record via name.com's DNS API
    """
    domain_name, token = args[0], args[2]
    fqdn_tuple = extract(domain_name)
    base_domain_name = ".".join([fqdn_tuple.domain, fqdn_tuple.suffix])

    if fqdn_tuple.subdomain is '':
        txtrecord = u'_acme-challenge'
    else:
        txtrecord = u'_acme-challenge.{0}'.format(fqdn_tuple.subdomain)
    name = "{0}.{1}".format(txtrecord,base_domain_name)
    record = {
        'hostname' : txtrecord,
        'type' : u'TXT',
        'content': token,
        'ttl': u'300',
        'priority': u'10'
    }

    b = requests.session()
    b.verify = False
    b.headers.update({u'Content-Type': u'application/json',
                     u'Api-Username': api_acct,
                     u'Api-Token': api_token})
    url = u'https://{0}/api/dns/create/{1}'.format(api_host, base_domain_name)
    create_record = b.post(url, json.dumps(record)).json()
    logger.info(" + (hook) TXT record created: {0}.{1} => {2}".format(
        txtrecord, base_domain_name, token))
    logger.info(" + (hook) Result: {0}".format(create_record['result']))
    logger.info(" + (hook) Settling down for 10s...")
    time.sleep(10)

    while not _has_dns_propagated(name, token):
        logger.info(" + (hook) DNS not propagated, waiting 30s...")
        time.sleep(30)


def delete_txt_record(args):
    """
    Delete the TXT DNS challenge record via name.com's DNS API
    """
    domain_name = args[0]
    fqdn_tuple = extract(domain_name)
    base_domain_name = ".".join([fqdn_tuple.domain, fqdn_tuple.suffix])

    b = requests.session()
    b.verify = False
    b.headers.update({u'Content-Type': u'application/json',
                      u'Api-Username': api_acct,
                      u'Api-Token': api_token})
    url = u'https://{0}/api/dns/list/{1}'.format(api_host, base_domain_name)

    records = b.get(url).json()

    for record in records['records']:
        if record['type'] == 'TXT' and u'_acme-challenge' in record['name']:
            record_id = record['record_id']

    record_payload = {u'record_id': record_id}
    url = u'https://{0}/api/dns/delete/{1}'.format(api_host, base_domain_name)

    delete_record = b.post(url, json.dumps(record_payload)).json()

    logger.info(" + (hook) TXT record deleted: {0}".format(record_id))
    logger.info(" + (hook) Result: {0}".format(delete_record['result']))


def deploy_cert(args):
    domain = args[0]
    key = args[1]
    cert = args[2]
    chain = args[4]

    b = ManagementRoot(f5_host, f5_user, f5_password)

    # Upload files
    b.shared.file_transfer.uploads.upload_file(key)
    b.shared.file_transfer.uploads.upload_file(cert)
    b.shared.file_transfer.uploads.upload_file(chain)

    # Map files to Certificate Objects
    keyparams = {
        'sourcePath': 'file:/var/config/rest/downloads/{0}'.format(
            os.path.basename(key)), 'name': domain}
    certparams = {'sourcePath': 'file:/var/config/rest/downloads/{0}'.format(
        os.path.basename(cert)), 'name': domain}
    chainparams = {'sourcePath': 'file:/var/config/rest/downloads/{0}'.format(
        os.path.basename(chain)), 'name': 'le-chain'}

    # use different instantiation for sys/file extensions;
    # not yet supported in f5-common-python
    btx = requests.session()
    btx.auth = (f5_user, f5_password)
    btx.verify = False
    btx.headers.update({'Content-Type':'application/json'})
    urlb = 'https://{0}/mgmt/tm'.format(f5_host)

    try:
        key = btx.get('{0}/sys/file/ssl-key/~Common~{1}'.format(urlb, domain))
        cert = btx.get('{0}/sys/file/ssl-cert/~Common~{1}'.format(urlb, domain))
        chain = btx.get('{0}/sys/file/ssl-cert/~Common~{1}'.format(urlb,
                                                                   'le-chain'))
        
        if (key.status_code == 200) and (cert.status_code == 200) \
                and (chain.status_code == 200):

            # use a transaction ; not supported in library yet
            txid = btx.post('{0}/transaction'.format(urlb),
                            json.dumps({})).json()['transId']
            btx.headers.update({'X-F5-REST-Coordination-Id': txid})
        
            modkey = btx.put('{0}/sys/file/ssl-key/~Common~{1}'.format(
                urlb, domain), json.dumps(keyparams))
            modcert = btx.put('{0}/sys/file/ssl-cert/~Common~{1}'.format(
                urlb, domain), json.dumps(certparams))
            modchain = btx.put('{0}/sys/file/ssl-cert/~Common~{1}'.format(
                urlb, 'le-chain'), json.dumps(chainparams))
            
            # remove header and patch to commit the transaction
            del btx.headers['X-F5-REST-Coordination-Id']
            cresult = btx.patch('{0}/transaction/{1}'.format(urlb, txid),
                                json.dumps({'state':'VALIDATING'})).json()
            logger.info(" + (hook) Existing Cert/Key updated in transaction.")

        else:
            newkey = btx.post('{0}/sys/file/ssl-key'.format(urlb),
                              json.dumps(keyparams)).json()
            newcert = btx.post('{0}/sys/file/ssl-cert'.format(urlb),
                               json.dumps(certparams)).json()
            newchain = btx.post('{0}/sys/file/ssl-cert'.format(urlb),
                                json.dumps(chainparams)).json()
            logger.info(" + (hook) New Certificate/Key created.")
            
    except Exception, e:
        print e

    # Create SSL Profile if necessary
    if not b.tm.ltm.profile.client_ssls.client_ssl.exists(
            name='cssl.{0}'.format(domain), partition='Common'):
        cssl_profile = {
                'name': '/Common/cssl.{0}'.format(domain),
                'cert': '/Common/{0}'.format(domain),
                'key': '/Common/{0}'.format(domain),
                'chain': '/Common/le-chain',
                'defaultsFrom': '/Common/clientssl'
                }
        b.tm.ltm.profile.client_ssls.client_ssl.create(**cssl_profile)


def unchanged_cert(args):
    logger.info(" + (hook) No changes necessary. ")


def main(argv):
    """
    The main logic of the hook.
    letsencrypt.sh will pass different arguments for different types of
    operations. The hook calls different functions based on the arguments
    passed.
    """
    ops = {
        'deploy_challenge': create_txt_record,
        'clean_challenge': delete_txt_record,
        'deploy_cert': deploy_cert,
        'unchanged_cert': unchanged_cert,
    }
    logger.info(" + (hook) executing: {0}".format(argv[0]))
    ops[argv[0]](argv[1:])


if __name__ == '__main__':
    main(sys.argv[1:])
