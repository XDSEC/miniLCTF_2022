FROM ubuntu:20.04

COPY ./start.sh /start.sh
COPY ./main /main
RUN chmod +x /start.sh
RUN /start.sh
ENTRYPOINT  ["/main"]
