# Dockerfile for WOPI Server
#
# Please, build and run via docker-compose file: wopiserver.yaml

FROM python:3

LABEL maintainer="cernbox-admins@cern.ch" name="The ScienceMesh IOP WOPI server" version="1.0"

# prerequisites
RUN pip3 install flask pyOpenSSL PyJWT requests cs3apis  # tusclient not available for pip3

# install software
RUN mkdir -p /app /etc/wopi /var/log/wopi /var/wopi_local_storage
ADD ./src/* ./docker/entrypoint /app/
ADD wopiserver.conf /etc/wopi/wopiserver.defaults.conf

# add basic custom configuration; need to contextualize
ADD ./docker/etc/*secret  ./docker/etc/wopiserver.conf /etc/wopi/
#RUN mkdir /etc/certs
#ADD ./etc/*.pem /etc/certs/   if certificates shall be added

#CMD /app/entrypoint
CMD ["python3", "/app/wopiserver.py"]
