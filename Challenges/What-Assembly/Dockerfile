FROM alpine:3

RUN apk add apache2
WORKDIR /var/www/localhost/htdocs/
ADD src/index.html  .
ADD src/flag.js     .
ADD src/flag.wasm   .
ADD src/index.css   .
ADD src/init.sh /etc/init.sh
RUN chmod +x /etc/init.sh
