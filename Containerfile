FROM cgr.dev/chainguard/jre:latest@sha256:cf2821e9754fda9996cf1ff675ed296156c2ab8a04a9ef3a93989c6e0ceac522

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
