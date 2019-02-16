FROM python:3.7-slim

WORKDIR /heavenlyGlory

RUN apt-get update
RUN apt-get install -y nmap masscan sudo

COPY heavenlyglory.py /heavenlyGlory
COPY Pipfile /heavenlyGlory
COPY Pipfile.lock /heavenlyGlory

RUN pip install --trusted-host pypi.python.org pipenv
RUN pipenv install

ENTRYPOINT ["pipenv", "run", "python", "heavenlyglory.py"]
