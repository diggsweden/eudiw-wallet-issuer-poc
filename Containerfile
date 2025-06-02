FROM cgr.dev/chainguard/jre:latest@sha256:a834e5dba7010b1889a14c1e32cbbbbb807ffcdbd21c5f157cce290ed0a09313

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
