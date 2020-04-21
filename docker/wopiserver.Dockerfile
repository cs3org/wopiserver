# Dockerfile for WOPI Server
#
# Please, build and run via docker-compose file: wopiserver.yaml

#FROM python:3  # this will eventually be the default, but for now we need the yum infrastructure to install xrootd
FROM cern/cc7-base:latest

LABEL maintainer="cernbox-admins@cern.ch" name="The ScienceMesh IOP WOPI server" version="1.0"

MAINTAINER Giuseppe Lo Presti <lopresti@cern.ch>

ADD cernbox-wopi*rpm /tmp
RUN yum -y install \
        sudo \
        python36 \
        python36-pip \
        python36-devel \
        openssl-devel \
        xrootd-client \
        python3-xrootd \
        /tmp/cernbox-wopi*rpm

RUN pip3 install flask pyOpenSSL PyJWT requests

ADD ./etc/*secret /etc/wopi/
ADD ./etc/wopiserver.conf /etc/wopi
RUN mkdir /etc/certs
#ADD ./etc/*.pem /etc/certs/   if certificates shall be added
RUN chmod 777 /var/log/wopi

#CMD /scripts/entrypoint
CMD ["python3", "/usr/bin/wopiserver.py"]

