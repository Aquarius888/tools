FROM python:3.6-alpine

RUN mkdir /checker

RUN pip3 install requests elasticsearch

COPY hosts /checker
RUN cat /checker/hosts > /etc/hosts
COPY dashboard_checker.py /checker
COPY settings.py /checker

WORKDIR /checker
ENTRYPOINT ["python3"]
