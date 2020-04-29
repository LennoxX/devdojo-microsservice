FROM openjdk:11-jdk
VOLUME /tmp
ADD target/auth.jar auth.jar
EXPOSE 8081
ENTRYPOINT ["java","-jar","auth.jar"]
