FROM cgr.dev/chainguard/jre:latest@sha256:dd41610cc173eb24a5eca49018f2c801cc58b4a52e280d6900d90d3d906a11fe

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
