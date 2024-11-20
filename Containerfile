# Dependencies stage - caches dependencies layer
FROM gradle:jdk21-jammy AS builder-with-project-dependencies
WORKDIR /app
COPY build.gradle settings.gradle* ./
RUN gradle dependencies --no-daemon

# Build stage - builds the application
FROM builder-with-project-dependencies AS builder 
COPY . .
RUN gradle assemble --no-daemon

# Final runtime stage - using specific JRE version
FROM cgr.dev/chainguard/jre:openjdk-21.0.5
USER java
WORKDIR /app

COPY --from=builder /app/build/libs/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar
ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]