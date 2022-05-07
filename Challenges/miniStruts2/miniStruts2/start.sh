#! /usr/bin/env bash
chmod 755 /main
echo $FLAG > /flag
export FLAG=not_flag
FLAG=not_flag
chmod -R 555 /flag
/usr/local/tomcat/bin/catalina.sh run
