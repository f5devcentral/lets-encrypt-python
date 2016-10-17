FROM ubuntu:latest
MAINTAINER docker@ekito.fr

RUN apt-get update && apt-get -y install cron python python-pip git curl openssl

RUN apt-get clean
RUN rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN mkdir -p /opt/le
WORKDIR /opt/le 
ADD requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

# dnspython cannot be installed with pip natively, so we hack it like dis
RUN pip install git+https://github.com/rthalley/dnspython

# Add crontab file in the cron directory
ADD crontab /etc/cron.d/letsencrypt

# Give execution rights on the cron job
RUN chmod 0644 /etc/cron.d/letsencrypt

# Create the log file to be able to run tail
RUN touch /var/log/cron.log

# Run the command on container startup
CMD cron && tail -f /var/log/cron.log