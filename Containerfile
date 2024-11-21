# Dependencies stage - caches dependencies layer
FROM gradle:jdk21-jammy AS builder-with-project-dependencies
WORKDIR /app
COPY ["build.gradle","settings.gradle", "gradlew","gradle","./"]
RUN ./gradlew dependencies --no-daemon

# Build stage - builds the application
FROM builder-with-project-dependencies AS builder 
COPY . .
RUN ./gradlew assemble --no-daemon

# Final runtime stage - using specific JRE version
FROM cgr.dev/chainguard/jre:latest@sha256:49dc9ce0548430570f3e40f627482fc8a785ff3a5009c414fa41826a1f45c34a
USER java
WORKDIR /app

COPY --from=builder /app/build/libs/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar
ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
