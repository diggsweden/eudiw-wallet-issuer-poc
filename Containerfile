FROM cgr.dev/chainguard/jre:latest@sha256:6d451110703b1b80e7451de80b8b7a4f210a8c08725cb891bd016592c59dadc7

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
