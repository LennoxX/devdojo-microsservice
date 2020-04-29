FROM openjdk:11-jdk
VOLUME /tmp
ADD target/course.jar course.jar
EXPOSE 8081
ENTRYPOINT ["java","-jar","course.jar"]
