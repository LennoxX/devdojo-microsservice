FROM openjdk:11-jdk
VOLUME /tmp
ADD target/gateway.jar gateway.jar
EXPOSE 8081
ENTRYPOINT ["java","-jar","gateway.jar"]
