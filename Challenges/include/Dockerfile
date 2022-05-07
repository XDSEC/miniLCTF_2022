FROM php:7.4-apache

COPY src /tmp/src/

RUN chown -R root:root /var/www/html/ && \
        chmod -R 755 /var/www/html && \
        mv /tmp/src/start.sh / &&\
        chmod +x /start.sh &&\
        mv /tmp/src/php.ini /usr/local/etc/php/ &&\
        mv /tmp/src/* /var/www/html/ && \
        mv /tmp/src/.upload.php.swp /var/www/html/ && \
        chmod 777 /var/www/html/upload/ && \
        rm -rf /tmp/src && \
        sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list && \
	    sed -i '/security/d' /etc/apt/sources.list && \
        sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list && \
        sed -i s@/security.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list && \
        apt-get update && \
        apt-get install -y sendmail 


EXPOSE 80

CMD /start.sh
