FROM cgr.dev/chainguard/jre:latest@sha256:fba813a1a91ce642ce87515ea6603fa3255cd6732c9faef014b696ab358222df

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
