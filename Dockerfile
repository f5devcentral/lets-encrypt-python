FROM ubuntu:latest
MAINTAINER docker@ekito.fr

RUN apt-get update && apt-get -y install cron python python-pip git

RUN apt-get clean
RUN rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN mkdir -p /opt/le
WORKDIR /opt/le 
ADD . /opt/le/

RUN pip install -r requirements.txt

# dnspython cannot be installed with pip natively, so we hack it like dis
RUN pip install git+https://github.com/rthalley/dnspython

# Add crontab file in the cron directory
ADD crontab /etc/cron.d/hello-cron

# Give execution rights on the cron job
RUN chmod 0644 /etc/cron.d/hello-cron

# Create the log file to be able to run tail
RUN touch /var/log/cron.log

# Run the command on container startup
# CMD cron && tail -f /var/log/cron.log