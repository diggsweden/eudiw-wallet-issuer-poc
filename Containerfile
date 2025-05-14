FROM cgr.dev/chainguard/jre:latest@sha256:c4e02258ca54fcf0e0ea8b3cc5b9f0bcfa95fb2947ca280c9b529c88e992f8aa

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
