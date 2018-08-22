# Dockerfile for Collabora
#
# Please, build and run via docker-compose file: collabora.yaml


FROM collabora/code

MAINTAINER Enrico Bocchi <enrico.bocchi@cern.ch>

# Copy TLS certificate and key
RUN mkdir -p /etc/loolwsd
ADD ./etc/hostcert.pem /etc/loolwsd/cert.pem 
ADD ./etc/hostkey.pem /etc/loolwsd/key.pem
ADD ./etc/ca-chain.cert.pem.fake /etc/loolwsd/ca-chain.cert.pem
RUN chmod 644 /etc/loolwsd/*.pem

# Install curl for healthcheck
RUN apt-get update && apt-get install -y curl

# Exporse port internally
EXPOSE 9980

# Run libreoffice
CMD bash start-libreoffice.sh

