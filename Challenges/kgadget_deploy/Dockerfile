FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN sed -i 's/http:\/\/archive.ubuntu.com/http:\/\/mirrors.ustc.edu.cn/g' /etc/apt/sources.list && \
    sed -i 's/http:\/\/security.ubuntu.com/http:\/\/mirrors.ustc.edu.cn/g' /etc/apt/sources.list && \
    apt-get -y update && \
    apt-get install -y lib32z1 xinetd apt-transport-https python3 git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev qemu qemu-system-x86 cpio


RUN useradd -m ctf &&  \
    echo "service ctf\n{\n    disable = no\n    socket_type = stream\n    protocol    = tcp\n    wait        = no\n    user        = root\n    type        = UNLISTED\n    port        = 9999\n    bind        = 0.0.0.0\n    server      = /start.sh\n    banner_fail = /etc/banner_fail\n    # safety options\n    per_source    = 10 # the maximum instances of this service per source IP address\n    #rlimit_cpu    = 1 # the maximum number of CPU seconds that the service may use\n    #rlimit_as  = 1024M # the Address Space resource limit for the service\n    #access_times = 2:00-9:00 12:00-24:00\n}" > /etc/xinetd.d/ctf && \
    echo "#!/bin/bash\n/etc/init.d/xinetd start\nsleep infinity" > /root/start.sh && \
    chmod +x /root/start.sh

COPY ./start.sh  /
COPY ./chal/ /chal/

RUN chmod +x /start.sh 

CMD "/root/start.sh"
