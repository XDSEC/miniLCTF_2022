FROM ubuntu:20.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
    apt-get update && apt-get -y upgrade && \
    apt-get install -y lib32z1

RUN useradd -u 10000 -m ctf

WORKDIR /home/ctf

COPY ./start.sh /start.sh
RUN chmod +x /start.sh

COPY ./bin/* /home/ctf/
RUN chown -R root:ctf /home/ctf && \
    chmod -R 750 /home/ctf && \
    chmod +x /home/ctf/run.sh

CMD ["/start.sh"]

EXPOSE 9999
