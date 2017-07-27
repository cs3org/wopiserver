FROM cern/cc7-base
#FROM your-own-custom-rhel7:latest
LABEL maintainer="cernbox-admins@cern.ch" name="wopiserver: The CERNBox WOPI server" version="1.0"
MAINTAINER Michael D'Silva <md@aarnet.edu.au>

COPY scripts/* /scripts/

#if you are missing some repos
#COPY yum.repos.d/* /etc/yum.repos.d/

ADD cernbox-wopi*rpm /tmp
RUN yum -y update && \
    yum -y install sudo xrootd-client xrootd-python python-flask python-jwt /tmp/cernbox-wopi*rpm && \
    yum clean all && \
    mkdir /etc/certs && \
    setcap 'cap_net_bind_service=+ep' /usr/bin/python2.7

VOLUME ['/var/log/wopi']

CMD /scripts/entrypoint
