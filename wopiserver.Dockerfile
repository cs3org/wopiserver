# Dockerfile for WOPI Server
#
# Build: make docker or docker-compose -f wopiserver.yaml build --build-arg VERSION=`git describe | sed 's/^v//'` BASEIMAGE=... wopiserver

ARG BASEIMAGE=python:3.14.3-alpine
FROM $BASEIMAGE

ARG VERSION=latest

LABEL maintainer="cernbox-admins@cern.ch" \
  org.opencontainers.image.title="The ScienceMesh IOP WOPI server" \
  org.opencontainers.image.version="$VERSION"

# prerequisites: we explicitly install g++ as it is required by grpcio but missing from its dependencies
WORKDIR /app
COPY requirements.txt .
RUN command -v apk && apk add curl g++ || true
RUN command -v apt && apt update && apt -y install curl g++ || true
RUN pip3 install --upgrade pip setuptools && \
    pip3 install --no-cache-dir --upgrade -r requirements.txt

# install software
RUN mkdir -p /app/core /app/bridge /test /etc/wopi /var/log/wopi /var/wopi_local_storage
COPY ./src/*py ./tools/* /app/
COPY ./src/core/* /app/core/
COPY ./src/bridge/* /app/bridge/
RUN sed -i "s/WOPISERVERVERSION = 'git'/WOPISERVERVERSION = '$VERSION'/" /app/wopiserver.py && \
    grep 'WOPISERVERVERSION =' /app/wopiserver.py
COPY wopiserver.conf /etc/wopi/wopiserver.defaults.conf
COPY test/*py test/*conf /test/

# add basic custom configuration; need to contextualize
COPY ./docker/etc/*secret  ./docker/etc/wopiserver.conf /etc/wopi/

ENTRYPOINT ["/app/wopiserver.py"]
