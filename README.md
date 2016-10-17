## Synopsis

This project uses Lukas2511's letsencrypt.sh shell script as the basis for deploying certificates to an F5 BIG-IP.

It utilizes the DNS challenge and reaches out to name.com's API (currently beta) for the challenge setup and teardown. Major (below reference) has example for Rackspace DNS that this is based on.

It utilizes F5's iControl REST interface to upload and configure the certificates into a clientssl profile for SSL offloading capability.

## Usage

./letsencrypt.sh -c -f /var/tmp/le/config/config.sh

where the configuration options are defined as appropriate in config.sh

## Contributors

Much of this project is based on the work of these projects:

* https://devcentral.f5.com/codeshare/lets-encrypt-on-a-big-ip
* https://github.com/lukas2511/letsencrypt.sh
* https://github.com/sporky/letsencrypt-dns
* https://github.com/major/letsencrypt-rackspace-hook

## Additional setup
### 11.5.1
- SSH to F5
- `mkdir -p /var/config/rest/downloads/tmp`  

## Docker

- Set your `CONTACT_EMAIL` in [config/config.sh](./config/config.sh)
```
...
# E-mail to use during the registration (default: <unset>)
CONTACT_EMAIL=you@yourdomain.tld
...
```

- Add your desired domains/subdomains to [config/domains.txt](./config/domains.txt)
```
mydomain.com server1.mydomain.com
example.com www.example.com server1.example.com
```

- Set up your variables in your `.envdocker` file
```
LE_UDNS_USERNAME="udnsadmin"
LE_UDNS_PASSWORD="udnsadmin"
LE_F5_HOSTNAME="172.16.0.10"
LE_F5_USERNAME="f5user"
LE_F5_PASSWORD="f5password"
```

- Build the container 
```
cd lets-encrypt-python
docker build -t le .
```

- Run the container in ad-hoc mode (Script will execute immediately with no recurring no cron job)
```
cd lets-encrypt-python
docker run -it -v $(pwd):/opt/le --env-file .envdocker le /opt/le/letsencrypt.sh --cron -f /opt/le/config/config.sh 
```

- Run the container in cron mode (Script will run once at 5AM daily)
```
cd lets-encrypt-python
docker run -d -v $(pwd):/opt/le --env-file .envdocker le
```