# Dependencies stage - caches dependencies layer
FROM maven:3.9-eclipse-temurin-21-jammy@sha256:3df7f4a433809a4362fe8a91e3f31521146309cb17cf2e141b3f847aa6c2ded1 AS builder-with-project-dependencies

WORKDIR /app

# Copy Maven project files
COPY pom.xml ./
#COPY ....settings.xml /root/.m2/settings.xml

# Pre-download dependencies
#RUN mvn dependency:go-offline -B 
RUN mvn dependency:go-offline -B -Daether.connector.https.securityMode=insecure

# Build stage - builds the application
FROM builder-with-project-dependencies AS builder

# Copy the rest of the project files
COPY . .

# Build the application
#RUN mvn package -DskipTests -B -Daether.connector.https.securityMode=insecure
RUN mvn package -DskipTests -B 


# Final runtime stage - using specific JRE version
FROM cgr.dev/chainguard/jre:latest@sha256:a6aff0af8fd0a45f06aad3e3f075e71a726b13256ea3b588f274506d05100244

USER java
WORKDIR /app

# Copy the built JAR file from the builder stage
COPY --from=builder /app/target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
