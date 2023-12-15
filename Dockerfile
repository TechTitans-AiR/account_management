# Koristi sliku s Javom 19
FROM openjdk:19-jdk-alpine

# Instaliraj Maven
RUN apk add --no-cache maven


# Postavi radni direktorij
WORKDIR /usr/src/app

# Kopiraj POM i sve potrebne datoteke za preuzimanje dependencija
COPY ./pom.xml .
COPY ./src ./src

# Izgradi aplikaciju
RUN mvn clean install

# Pokreni aplikaciju
CMD ["java", "-jar", "target/account_management.jar"]
