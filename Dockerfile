# Build stage
FROM maven:3.9.9-eclipse-temurin-21 AS build

COPY src /home/app/src
COPY pom.xml /home/app

COPY docker /home/app/docker

RUN mvn -f /home/app/pom.xml clean package

# Package stage
FROM eclipse-temurin:21.0.6_7-jre-alpine

LABEL org.opencontainers.image.authors="CZERTAINLY <support@czertainly.com>"

# add non root user czertainly
RUN addgroup --system --gid 10001 czertainly && adduser --system --home /opt/czertainly --uid 10001 --ingroup czertainly czertainly

COPY --from=build /home/app/docker /
COPY --from=build /home/app/target/*.jar /opt/czertainly/app.jar

WORKDIR /opt/czertainly
# this should be improved, user should defined known_hosts and it will be read-only
RUN mkdir .ssh && touch .ssh/known_hosts && chown czertainly: .ssh/known_hosts && chmod 600 .ssh/known_hosts

ENV JDBC_URL=
ENV JDBC_USERNAME=
ENV JDBC_PASSWORD=
ENV DB_SCHEMA=keystore
ENV PORT=8080
ENV JAVA_OPTS=

USER 10001

ENTRYPOINT ["/opt/czertainly/entry.sh"]
