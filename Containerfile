FROM cgr.dev/chainguard/jre:latest@sha256:81bd9df8030d2ec70c4d464ab87417c034023d85c425943fd5772fb63cd9be0a

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
