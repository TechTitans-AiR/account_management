FROM openjdk:19-jdk-alpine

# Instaliraj Maven
RUN apk add --no-cache maven

# Postavi radni direktorij
WORKDIR /usr/src/app

# Kopiraj POM i sve potrebne datoteke za preuzimanje dependencija
COPY ./pom.xml .
COPY ./src ./src

# Postavi varijable okoline koje će biti dostupne tijekom izvođenja Docker slike
ARG MONGO_DATABASE
ARG MONGO_USER
ARG MONGO_PASSWORD
ARG MONGO_CLUSTER

# Stvori .env datoteku unutar Docker kontejnera
RUN echo "MONGO_DATABASE=${MONGO_DATABASE}" > src/main/resources/.env
RUN echo "MONGO_USER=${MONGO_USER}" >> src/main/resources/.env
RUN echo "MONGO_PASSWORD=${MONGO_PASSWORD}" >> src/main/resources/.env
RUN echo "MONGO_CLUSTER=${MONGO_CLUSTER}" >> src/main/resources/.env

# Izgradi aplikaciju
RUN mvn clean install

# Pokreni aplikaciju
CMD ["java", "-jar", "target/account_management.jar"]