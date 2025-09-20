FROM cgr.dev/chainguard/jre:latest@sha256:ff602a2bf86b1df05d715d1f6a4b3fc15d08a73e96e18e7710fc630ce8c42833

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
