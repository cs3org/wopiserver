# Dockerfile for WOPI Server
#
# Please, build and run via docker-compose file: wopiserver.yaml
FROM python:3

LABEL maintainer="cernbox-admins@cern.ch" \
  org.opencontainers.image.title="The ScienceMesh IOP WOPI server" \
  org.opencontainers.image.version="1.0"

# prerequisites
WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir --upgrade -r requirements.txt

# install software
RUN mkdir -p /var/log/wopi /var/wopi_local_storage
ADD ./src/* ./tools/* ./docker/entrypoint /app/
ADD wopiserver.conf /etc/wopi/wopiserver.defaults.conf

# add basic custom configuration; need to contextualize
ADD ./docker/etc/*secret  ./docker/etc/wopiserver.conf /etc/wopi/
#RUN mkdir /etc/certs
#ADD ./etc/*.pem /etc/certs/   if certificates shall be added

#CMD /app/entrypoint
ENTRYPOINT ["/app/wopiserver.py"]
