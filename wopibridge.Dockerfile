# Simple dockerfile to "package" the CodiMD to WOPI PoC

FROM python:3
MAINTAINER Giuseppe Lo Presti <lopresti@cern.ch>

RUN pip install flask requests
RUN mkdir -p /var/log/wopi /app
ADD wopibridge.defaults.conf /etc/wopi/
ADD src/wopibridge.py /app

CMD ["python3", "/app/wopibridge.py"]

