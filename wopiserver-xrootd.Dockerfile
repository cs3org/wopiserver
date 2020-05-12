# Dockerfile for WOPI Server
#
# Please, build and run via docker-compose file: wopiserver.yaml

FROM cern/cc7-base:latest

LABEL maintainer="cernbox-admins@cern.ch" name="The CERNBox WOPI server" version="1.0"

# prerequisites: until we need to support xrootd, yum install is way easier than pip3 install (where xrootd would need to be compiled from sources)
RUN yum -y install \
        sudo \
        python36 \
        python36-pip \
        python36-devel \
        openssl-devel \
        xrootd-client \
        python3-xrootd

RUN pip3 install flask pyOpenSSL PyJWT requests

# install software
RUN mkdir -p /app /etc/wopi /var/log/wopi /var/wopi_local_storage
ADD ./src/* ./docker/entrypoint /app/
ADD wopiserver.conf /etc/wopi/wopiserver.defaults.conf

# add basic custom configuration; need to contextualize
ADD ./docker/etc/*secret  ./docker/etc/wopiserver.conf /etc/wopi/
#RUN mkdir /etc/certs
#ADD ./etc/*.pem /etc/certs/   if certificates shall be added

#CMD /app/entrypoint
CMD ["python3", "/app/wopiserver.py"]
