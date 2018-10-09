# Dockerfile for Wopi Server
#
# Please, build and run via docker-compose file: wopiserver.yaml

FROM fedora:29

LABEL maintainer="cernbox-admins@cern.ch" name="wopiserver: The CERNBox WOPI server" version="1.0"

MAINTAINER Michael D'Silva <md@aarnet.edu.au>, Giuseppe Lo Presti <lopresti@cern.ch>

COPY scripts/* /scripts/
COPY wopiserver.d/repos/xrootd.repo /etc/yum.repos.d/
#if you are missing some repos
#COPY wopiserver.d/repos/*repo /etc/yum.repos.d/

ADD cernbox-wopi*rpm /tmp

RUN dnf -v -y install \
	sudo \
	python3-flask \
	python3-jwt \
	python3-pyOpenSSL

RUN dnf -v -y install --disablerepo=epel \
	xrootd-client \
	python3-xrootd \
    /tmp/cernbox-wopi*rpm

COPY wopiserver.d/* /etc/wopi/
RUN mkdir /etc/certs
ADD ./etc/*.pem /etc/certs/
VOLUME ['/var/log/wopi']

#CMD /scripts/entrypoint
CMD ["python3", "/usr/bin/wopiserver.py"]
