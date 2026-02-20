FROM cgr.dev/chainguard/jre:latest@sha256:5c919534908bd378a2fdc54e4427a909741f4e70f6a763984bac765a44250cc8

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
