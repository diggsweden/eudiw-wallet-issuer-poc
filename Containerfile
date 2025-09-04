FROM cgr.dev/chainguard/jre:latest@sha256:87a3d467f27458afa2863c9e34c5ab58588c7153ec7236d81caa9dba79f84171

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
