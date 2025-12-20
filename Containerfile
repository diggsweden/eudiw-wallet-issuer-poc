FROM cgr.dev/chainguard/jre:latest@sha256:7b98a5f707f4740913bfabe7577296ef890ec31081636f712b92b8b5d00aa424

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
