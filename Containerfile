FROM cgr.dev/chainguard/jre:latest@sha256:71c0dc29e7bf9b8565e2bb69b2ebebc01ecf71dcbed5a9bb4dec530e93cf992d

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
