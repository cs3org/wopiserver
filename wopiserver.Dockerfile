# Dockerfile for WOPI Server
#
# Build: make docker or docker-compose -f wopiserver.yaml build --build-arg VERSION=`./getbuildversion.sh` wopiserver
# Run: docker-compose -f wopiserver.yaml up -d

FROM python:3

ARG VERSION=latest

LABEL maintainer="cernbox-admins@cern.ch" \
  org.opencontainers.image.title="The ScienceMesh IOP WOPI server" \
  org.opencontainers.image.version="$VERSION"

# prerequisites
WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir --upgrade -r requirements.txt

# install software
RUN mkdir -p /app /test /etc/wopi /var/log/wopi /var/wopi_local_storage
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
ENTRYPOINT ["/app/wopiserver.py"]
