FROM cgr.dev/chainguard/jre:latest@sha256:609d523ac115a88fa2a705a3c690b5a12fa112e8c9d363ab2d20f592b4798422

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
