FROM onlyoffice/documentserver

MAINTAINER Enrico Bocchi <enrico.bocchi@cern.ch>

# Copy TLS certificate and key
RUN mkdir -p /app/onlyoffice/DocumentServer/data/certs
ADD ./certs/hostcert.pem /var/www/onlyoffice/Data/certs/onlyoffice.crt
ADD ./certs/hostkey.pem /var/www/onlyoffice/Data/certs/onlyoffice.key
RUN chmod 400 /var/www/onlyoffice/Data/certs/onlyoffice.key

EXPOSE 80 443

CMD bash -C '/app/onlyoffice/run-document-server.sh';'bash'

