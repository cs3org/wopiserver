# Dockerfile for the WOPI Bridge PoC
#
# Build: docker-compose -f wopibridge.yaml build --build-arg VERSION=`git describe | sed 's/^v//'` wopibridge

FROM python:3

ARG VERSION=latest

LABEL maintainer="cernbox-admins@cern.ch" \
  org.opencontainers.image.title="The ScienceMesh IOP WOPI bridge" \
  org.opencontainers.image.version="$VERSION"

RUN pip install flask requests
RUN mkdir -p /var/log/wopi /app
ADD poc_src/* /app/
RUN sed -i "s/WBVERSION = 'git'/WBVERSION = '$VERSION'/" /app/wopibridge.py

CMD ["python3", "/app/wopibridge.py"]
