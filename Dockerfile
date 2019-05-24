FROM python:3.6-alpine

RUN set -ex \
    && apk add --no-cache \
    bash

RUN mkdir /checker

RUN pip3 install requests

COPY dashboard_checker.py /checker
COPY settings.py /checker
COPY kick_off.sh /usr/sbin/kick_off
RUN chmod 0777 /usr/sbin/kick_off

CMD ["kick_off"]
