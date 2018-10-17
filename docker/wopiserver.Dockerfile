# Dockerfile for Wopi Server
#
# Please, build and run via docker-compose file: wopiserver.yaml

FROM fedora:29

LABEL maintainer="cernbox-admins@cern.ch" name="wopiserver: The CERNBox WOPI server" version="1.0"

MAINTAINER Michael D'Silva <md@aarnet.edu.au>, Giuseppe Lo Presti <lopresti@cern.ch>

COPY scripts/* /scripts/

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

ADD ./etc/*secret /etc/wopi/
ADD ./etc/wopiserver.conf /etc/wopi
RUN mkdir /etc/certs
ADD ./etc/*.pem /etc/certs/
VOLUME ['/var/log/wopi']

#CMD /scripts/entrypoint
CMD ["python3", "/usr/bin/wopiserver.py"]
