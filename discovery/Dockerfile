FROM openjdk:11-jdk
VOLUME /tmp
ADD target/discovery.jar discovery.jar
EXPOSE 8081
ENTRYPOINT ["java","-jar","discovery.jar"]