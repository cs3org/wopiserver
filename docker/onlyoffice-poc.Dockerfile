FROM onlyoffice/documentserver-de

MAINTAINER Enrico Bocchi <enrico.bocchi@cern.ch>

# Copy TLS certificate and key
RUN mkdir -p /app/onlyoffice/DocumentServer/data/certs
ADD ./etc/hostcert.pem /var/www/onlyoffice/Data/etc/onlyoffice.crt
ADD ./etc/hostkey.pem /var/www/onlyoffice/Data/etc/onlyoffice.key
RUN chmod 400 /var/www/onlyoffice/Data/etc/onlyoffice.key
#ADD ./etc/CERN-bundle.pem /var/www/onlyoffice/Data/etc/ca-certificates.pem

# workaround until we have nodejs 8.x + custom config for metrics
ADD ./etc/default.json /etc/onlyoffice/documentserver/default.json
#ADD ./etc/server.js /var/www/onlyoffice/documentserver/server/DocService/sources/

# More custom configuration to enable metrics gathering
ADD ./etc/config.js /var/www/onlyoffice/documentserver/server/Metrics/config/

# Copy license
ADD ./etc/license.lic /app/onlyoffice/DocumentServer/data/

EXPOSE 80 443

CMD bash -C '/app/onlyoffice/run-document-server.sh';'bash'

