# Dockerfile for WOPI Server
#
# Build: WOPI_DOCKER_TYPE=-xrootd docker-compose -f wopiserver.yaml build --build-arg VERSION=`git describe | sed 's/^v//'` wopiserver
# Run: docker-compose -f wopiserver.yaml up -d

FROM cern/cs9-base:latest

ARG VERSION=latest

LABEL maintainer="cernbox-admins@cern.ch" \
  org.opencontainers.image.title="The CERNBox/IOP WOPI server" \
  org.opencontainers.image.version="$VERSION"

ADD ./docker/etc/epel9.repo /etc/yum.repos.d/

# prerequisites: until we need to support xrootd (even on C8), we have some EPEL dependencies, easier to install via yum/dnf;
# the rest is actually installed via pip, including the xrootd python bindings
# (note that attempting to install python38 fails here as it gets mixed with the default 3.6 version; we'd need to use
# a pure python image and install dependencies with apt)
RUN yum clean all && yum -y install \
        sudo \
        python3-pip \
        python3-devel \
        openssl-devel \
        zlib-devel \
        xrootd-client \
        xrootd-devel \
        libuuid-devel \
        cmake \
        make \
        gcc \
        gcc-c++

RUN pip3 install --upgrade pip setuptools && \
    pip3 install --upgrade flask pyOpenSSL PyJWT requests more_itertools prometheus-flask-exporter wheel
RUN pip3 --default-timeout=900 install xrootd

# install software
RUN mkdir -p /app/core /app/bridge /test /etc/wopi /var/log/wopi
ADD ./src/* ./tools/* /app/
ADD ./src/core/* /app/core/
ADD ./src/bridge/* /app/bridge/
RUN sed -i "s/WOPISERVERVERSION = 'git'/WOPISERVERVERSION = '$VERSION'/" /app/wopiserver.py
RUN grep 'WOPISERVERVERSION =' /app/wopiserver.py
ADD wopiserver.conf /etc/wopi/wopiserver.defaults.conf
ADD test/*py test/*conf /test/

# add basic custom configuration; need to contextualize
ADD ./docker/etc/*secret  ./docker/etc/wopiserver.conf /etc/wopi/
#RUN mkdir /etc/certs
#ADD ./etc/*.pem /etc/certs/   if certificates shall be added

CMD ["python3", "/app/wopiserver.py"]

