FROM python:3.6-alpine

RUN mkdir /checker

RUN pip3 install requests elasticsearch

COPY dashboard_checker.py /checker
COPY settings.py /checker

WORKDIR /checker
ENTRYPOINT ["python3"]
