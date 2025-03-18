FROM cgr.dev/chainguard/jre:latest@sha256:47f8c0e6c2ef7ec671509baccdfde936d67311d7c91b460ea51b2856ddbb2beb

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
