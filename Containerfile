FROM cgr.dev/chainguard/jre:latest@sha256:6cd7329ab8626f7a39c7adf12f42756051a44c28446be34af08134e1ff6a5a84

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
