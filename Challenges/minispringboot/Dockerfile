FROM openjdk:8-jre
COPY files /tmp/files/
RUN mv /tmp/files/flag.sh / && \
    chmod +x /flag.sh && \
    bash /flag.sh
CMD ["java","-jar","/tmp/files/thymeleaf-0.0.1-SNAPSHOT.jar"]