FROM python:3.7-slim-buster

RUN adduser --disabled-password --gecos "" ctf && \
    python -m pip install pandas -i https://pypi.douban.com/simple && \
    python -m pip install numpy -i https://pypi.douban.com/simple

WORKDIR /home/ctf

COPY ./bin/next-server.py    .
COPY ./bin/picData.csv       .
COPY ./bin/weight.dat        .

RUN chmod +x ./run.sh

CMD ["./run.sh"]