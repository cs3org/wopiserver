# Dockerfile for OnlyOffice
#
# Please, build and run via docker-compose file: onlyoffice.yaml


FROM docker.io/onlyoffice/documentserver:latest
#FROM gitlab-registry.cern.ch/cernbox/docker-image/onlyoffice:cern

MAINTAINER Enrico Bocchi <enrico.bocchi@cern.ch>

# Copy TLS certificate and key
ADD ./etc/hostcert.pem /var/www/onlyoffice/Data/certs/onlyoffice.crt
ADD ./etc/hostkey.pem /var/www/onlyoffice/Data/certs/onlyoffice.key
RUN chmod 400 /var/www/onlyoffice/Data/certs/onlyoffice.key

# workaround until we have nodejs 8.x + custom config for metrics
RUN sed -i 's/"rejectUnauthorized": true/"rejectUnauthorized": false/' /etc/onlyoffice/documentserver/default.json
#ADD ./etc/server.js /var/www/onlyoffice/documentserver/server/DocService/sources/

EXPOSE 80 443

CMD bash -C '/app/onlyoffice/run-document-server.sh';'bash'

