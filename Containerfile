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
FROM cgr.dev/chainguard/jre:latest@sha256:de34b1e3274e3756052a7d61f0947d109f7fe577ec2e35fe9fff659581b62e9e
USER java
WORKDIR /app

COPY --from=builder /app/build/libs/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar
ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
