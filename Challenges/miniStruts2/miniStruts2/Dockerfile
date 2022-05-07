FROM tomcat:9.0.62

COPY ./Mini-Struts2.war /usr/local/tomcat/webapps/miniStruts2.war

RUN rm /usr/local/tomcat/conf/server.xml

COPY ./server.xml /usr/local/tomcat/conf/server.xml
COPY ./start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]
