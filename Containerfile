# Dependencies stage - caches dependencies layer
FROM gradle:jdk21-jammy@sha256:7990a44ed0ad609ee740426d3becc69ae7d10a5ed14da7e354ad83cf7ef1d087 AS builder-with-project-dependencies
WORKDIR /app
COPY build.gradle settings.gradle gradlew ./
COPY gradle gradle/
RUN ./gradlew dependencies --no-daemon

# Build stage - builds the application
FROM builder-with-project-dependencies AS builder 
COPY . .
RUN ./gradlew assemble --no-daemon

# Final runtime stage - using specific JRE version
FROM cgr.dev/chainguard/jre:latest@sha256:803b651145a3d287d9b35f1091239e16c014ce53d20915ac81d0a9dcd459d43b
USER java
WORKDIR /app

COPY --from=builder /app/build/libs/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar
ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
