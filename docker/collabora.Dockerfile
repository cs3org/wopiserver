FROM collabora/code

MAINTAINER Enrico Bocchi <enrico.bocchi@cern.ch>

# Copy TLS certificate and key
RUN mkdir -p /etc/loolwsd
ADD ./certs/hostcert.pem /etc/loolwsd/cert.pem 
ADD ./certs/hostkey.pem /etc/loolwsd/key.pem
ADD ./certs/ca-chain.cert.pem.fake /etc/loolwsd/ca-chain.cert.pem
RUN chmod 644 /etc/loolwsd/*.pem

EXPOSE 9980

CMD bash start-libreoffice.sh


