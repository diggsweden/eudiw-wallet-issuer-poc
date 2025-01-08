# Dependencies stage - caches dependencies layer
FROM maven:3.9-eclipse-temurin-21-jammy AS builder-with-project-dependencies

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
FROM cgr.dev/chainguard/jre:latest@sha256:7a63ab17be4f85821cedb56a57ae71adf4e5f93142f45171983b69b4e245cd0b

USER java
WORKDIR /app

# Copy the built JAR file from the builder stage
COPY --from=builder /app/target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
