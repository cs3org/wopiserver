# Simple Dockerfile to "package" the WOPI Bridge PoC

FROM python:3
MAINTAINER Giuseppe Lo Presti <lopresti@cern.ch>

RUN pip install flask requests
RUN mkdir -p /var/log/wopi /app
ADD poc_src/wopibridge.py /app

CMD ["python3", "/app/wopibridge.py"]
