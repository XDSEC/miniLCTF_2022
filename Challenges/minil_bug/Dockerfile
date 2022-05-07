FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.ustc.edu.cn/g" /etc/apt/sources.list &&\
    apt-get update &&\
    apt-get install -y --no-install-recommends gcc g++ cmake make wget unzip socat git

WORKDIR /app/

# RUN git config --global http.sslverify false &&\
#     git config --global https.sslverify false &&\
#     git clone https://github.com/parrt/simple-virtual-machine-C
COPY ./simple-virtual-machine-C.zip /app/

RUN unzip ./simple-virtual-machine-C.zip &&\
    mv ./simple-virtual-machine-C-master ./simple-virtual-machine-C
COPY ./bug_repaired.patch /app/simple-virtual-machine-C

COPY ./main.c /app/simple-virtual-machine-C/src/vmtest.c
RUN cd simple-virtual-machine-C &&\
    git apply bug_repaired.patch &&\
    cmake . &&\
    make &&\
    mv ./simple_virtual_machine_C /app/bugged_interpreter &&\
    cd /app/ &&\
    rm -rf ./simple-virtual-machine-C*
RUN useradd --no-create-home -u 1000 user
COPY ./run.sh /app
RUN chmod +x ./run.sh

EXPOSE 9999
CMD ["/app/run.sh"]