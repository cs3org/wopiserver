# Dockerfile for WOPI Server
#
# Build: WOPI_DOCKER_TYPE=-xrootd docker-compose -f wopiserver.yaml build --build-arg VERSION=`git describe | sed 's/^v//'` wopiserver
# Run: docker-compose -f wopiserver.yaml up -d

FROM cern/cc7-base:latest

ARG VERSION=latest

LABEL maintainer="cernbox-admins@cern.ch" \
  org.opencontainers.image.title="The CERNBox WOPI server" \
  org.opencontainers.image.version="$VERSION"

# prerequisites: until we need to support xrootd, yum install is way easier than pip3 install (where xrootd would need to be compiled from sources)
RUN yum -y install \
        sudo \
        python36 \
        python36-pip \
        python36-devel \
        openssl-devel \
        xrootd-client \
        python3-xrootd

RUN pip3 install flask pyOpenSSL PyJWT requests prometheus-flask-exporter

# install software
RUN mkdir -p /app /test /etc/wopi /var/log/wopi
ADD ./src/* ./tools/* /app/
RUN sed -i "s/WOPISERVERVERSION = 'git'/WOPISERVERVERSION = '$VERSION'/" /app/wopiserver.py
RUN grep 'WOPISERVERVERSION =' /app/wopiserver.py
ADD wopiserver.conf /etc/wopi/wopiserver.defaults.conf
ADD test/*py test/*conf /test/

# add basic custom configuration; need to contextualize
ADD ./docker/etc/*secret  ./docker/etc/wopiserver.conf /etc/wopi/
#RUN mkdir /etc/certs
#ADD ./etc/*.pem /etc/certs/   if certificates shall be added

#CMD /app/entrypoint
CMD ["python3", "/app/wopiserver.py"]
