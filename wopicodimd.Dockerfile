# Simple dockerfile to "package" the CodiMD to WOPI PoC

FROM python:3
MAINTAINER Giuseppe Lo Presti <lopresti@cern.ch>

RUN pip install flask requests
RUN mkdir -p /var/log/wopi
ADD codimdtowopi.defaults.conf /etc/wopi/
ADD src/codimdtowopi.py /

CMD ["python3", "/codimdtowopi.py"]
