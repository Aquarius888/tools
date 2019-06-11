FROM python:3.6-alpine

RUN set -ex \
    && apk add --no-cache \
    bash

RUN mkdir -pv \
     /checker \
     /checker/log \
     /checker/config

RUN pip3 install asyncio aiohttp

COPY dashboard_checker.py /checker
COPY settings.py /checker/config
COPY kick_off.sh /usr/sbin/kick_off
RUN chmod 0777 /usr/sbin/kick_off

CMD kick_off "\0 \*/2 \* \* \* python3 /checker/dashboard_checker.py -c 86400 -f RO -q Helios -i"
