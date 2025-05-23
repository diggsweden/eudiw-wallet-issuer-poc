FROM cgr.dev/chainguard/jre:latest@sha256:77e8a18979e3164bbd7dac1fa51221664d9a6499e6487639f4ebf851725568e0

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
