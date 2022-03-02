# Dockerfile for WOPI Server
#
# Build: make docker or docker-compose -f wopiserver.yaml build --build-arg VERSION=`git describe | sed 's/^v//'` wopiserver

FROM python:3.10

ARG VERSION=latest

LABEL maintainer="cernbox-admins@cern.ch" \
  org.opencontainers.image.title="The ScienceMesh IOP WOPI server" \
  org.opencontainers.image.version="$VERSION"

# prerequisites
WORKDIR /app
COPY requirements.txt .
RUN pip3 install --upgrade pip setuptools && \
    pip3 install --no-cache-dir --upgrade -r requirements.txt

# install software
RUN mkdir -p /app/core /app/bridge /test /etc/wopi /var/log/wopi /var/wopi_local_storage
ADD ./src/* ./tools/* /app/
ADD ./src/core/* /app/core/
ADD ./src/bridge/* /app/bridge/
RUN sed -i "s/WOPISERVERVERSION = 'git'/WOPISERVERVERSION = '$VERSION'/" /app/wopiserver.py && \
    grep 'WOPISERVERVERSION =' /app/wopiserver.py
ADD wopiserver.conf /etc/wopi/wopiserver.defaults.conf
ADD test/*py test/*conf /test/

# add basic custom configuration; need to contextualize
ADD ./docker/etc/*secret  ./docker/etc/wopiserver.conf /etc/wopi/

ENTRYPOINT ["/app/wopiserver.py"]
