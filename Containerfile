FROM cgr.dev/chainguard/jre:latest@sha256:67f6ee753cd4a63da43a82f8f0d6429af0a36d815df847950224a70218860875

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
