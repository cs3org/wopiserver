FROM cern/cc7-base
LABEL maintainer="cernbox-admins@cern.ch" name="wopiserver: The CERNBox WOPI server" version="1.0"

ADD cernbox-wopi*rpm /tmp
RUN yum clean all && yum -y update && \
    yum -y install lsof net-tools openssh-clients less psmisc bind-utils telnet \
                   /tmp/cernbox-wopi*rpm && \
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1 > /etc/wopi/wopisecret && \
    mkdir /etc/certs
ADD ocsecret /etc/wopi/ocsecret
ADD wopiserver.conf /etc/wopi/wopiserver.conf

CMD ["/usr/bin/wopiserver.py"]
