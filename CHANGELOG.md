# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.23.2] - 2025-12-01

### Changed

- Use reuseable ci 2.4.x
- Pin version
- Use base renovate config
- Adjust settings

## [0.23.1] - 2025-10-16

### Added

- Add support for parsing proofs with an attested key (#197)

### Removed

- Remove jreleaser from pom


## [0.23.0] - 2025-10-14

### Changed

- Set project-type for devflow
- Use reuseable-ci v2

### Fixed

- Refactor WuaToCredentialControllerTest


## [0.22.0] - 2025-10-06

### Changed

- Feat/verify root ca (#191)
- Use openssf-scorecard v1
- Use openssf-scorecard v1
- Use reusable-ci v1
- Update dependency org.apache.maven.plugins:maven-enforcer-plugin to v3.6.2 (#190)
- Feat/validate credentials (#189)

### Fixed

- Update dependency com.nimbusds:oauth2-oidc-sdk to v11.29.2 (#187)


## [0.21.0] - 2025-09-29

### Added

- Add release flow perm
- Add release flow

### Changed

- Update dependency org.openapitools:openapi-generator-maven-plugin to v7.16.0 (#185)
- Update orhun/git-cliff-action action to v4.6.0 (#183)
- Update dependency org.apache.maven.plugins:maven-javadoc-plugin to v3.12.0 (#182)
- Update maven-plugins to v3.5.4 (#176)
- Update step-security/harden-runner action to v2.13.1 (#174)

### Fixed

- Update dependency com.nimbusds:oauth2-oidc-sdk to v11.29.1 (#184)
- Update dependency org.apache.httpcomponents.core5:httpcore5 to v5.3.6 (#181)
- Update dependency org.springframework.boot:spring-boot-starter-parent to v3.5.6 (#180)
- Update dependency org.projectlombok:lombok to v1.18.42 (#179)
- Update dependency com.google.guava:guava to v33.5.0-jre (#178)
- Update java non-major to v1.82 (#177)
- Update java non-major to v2.0.7 (#175)
- Update dependency io.projectreactor:reactor-core to v3.7.11 (#173)


## [0.0.20] - 2025-09-09

### Added

- Add optional personal_administrative_number to sdjwt pid
- Add support for credential_configuration_id parameter in credential endpoint
- Add support for list of credentials in credential end-point
- Add versionnumbers to gh actions
- Add versionnumbers to gh actions
- Add versionnumbers to gh actions
- Add proxy config for rest client
- Add ewc itb issuer endpoints
- Add link to tokenlib at frontpage
- Add par metadata

### Changed

- Update vct and type to latest specification
- Update dependency org.jreleaser:jreleaser-maven-plugin to v1.20.0 (#164)
- Update to follow Draft 15 of OID4VCI (#150)
- Update dependency org.openapitools:openapi-generator-maven-plugin to v7.15.0 (#159)
- Update github actions
- Update github actions to v5 (major)
- Extend descriptionlength for commitlint
- Update maven-plugins (#144)
- Update dependency org.jreleaser:jreleaser-maven-plugin to v1.19.0 (#142)
- Disable ewc itb automatic cookie management for rest client
- Skip consent page for pid issuance
- Update docker/build-push-action digest to 1dc7386 (#123)
- Update cgr.dev/chainguard/jre:latest docker digest to c4e0225 (#109)

### Fixed

- Update dependency org.springdoc:springdoc-openapi-starter-webmvc-ui to v2.8.13 (#172)
- Update dependency com.nimbusds:nimbus-jose-jwt to v10.5 (#171)
- Update dependency org.projectlombok:lombok to v1.18.40 (#170)
- Update dependency io.lettuce:lettuce-core to v6.8.1.release (#168)
- Update dependency org.springdoc:springdoc-openapi-starter-webmvc-ui to v2.8.12 (#167)
- Update dependency com.nimbusds:oauth2-oidc-sdk to v11.28 (#163)
- Update java non-major (#162)
- Update dependency org.jsoup:jsoup to v1.21.2 (#160)
- Update spring non-major (#157)
- Update spring non-major (#137)
- Update nimbusds (#156)
- Update dependency io.projectreactor:reactor-core to v3.7.9 (#155)
- Update dependency io.lettuce:lettuce-core to v6.8.0.release (#153)
- Update dependency com.nimbusds:nimbus-jose-jwt to v10.4.1 (#152)
- Update dependency com.nimbusds:oauth2-oidc-sdk to v11.27 (#151)
- Update dependency com.nimbusds:oauth2-oidc-sdk to v11.26.1 (#149)
- Update dependency com.nimbusds:nimbus-jose-jwt to v10.4 (#148)
- Update dependency commons-io:commons-io to v2.20.0 (#147)
- Update java non-major to v2.19.2 (#146)
- Update dependency io.projectreactor:reactor-core to v3.7.8 (#145)
- Update dependency com.nimbusds:nimbus-jose-jwt to v10.3.1 (#143)
- Update java non-major (#138)
- Update dependency com.nimbusds:oauth2-oidc-sdk to v11.26 (#136)
- Update java non-major to v2.19.1 (#135)
- Update dependency io.projectreactor:reactor-core to v3.7.7 (#134)
- Update spring non-major (#130)
- Update java non-major (#133)
- Update dependency io.lettuce:lettuce-core to v6.7.0.release (#132)
- Update dependency com.nimbusds:oauth2-oidc-sdk to v11.25 (#129)


## [0.0.19] - 2025-05-19

### Changed

- Disable redirect uri verification

### Fixed

- Update dependency io.projectreactor:reactor-core to v3.7.6 (#122)
- Update nimbusds (#112)


## [0.0.18] - 2025-05-09

### Added

- Add correct selected credentials to pre-auth credential offer
- Add new work-around for android ref impl wallet app
- Add work-around for android ref impl wallet app
- Add funded by eu logo asset
- Add funded by eu logo to site and some text fixes

### Changed

- Update github actions (#106)
- Update maven-plugins to v3.5.3 (#107)

### Fixed

- Update java non-major to v2.0.6 (#120)
- Update dev tools (#108)
- Update spring non-major (#100)
- Update java non-major (#99)
- Fix CI
- Correct eudiw ri credential status code when missing proof


## [0.0.17] - 2025-04-24

### Added

- Add refactored credential offer
- Add content to information page
- Add digg logo and branding in issuer metadata
- Add code in project as temp work-around mvn deps
- Add pre-auth credential offer support

### Changed

- Clean up oidc sweden dependencies
- Html fixes and a fix in the proof work around
- Update github actions
- Update cgr.dev/chainguard/jre:latest docker digest to 47f8c0e
- Update maven-plugins

### Fixed

- Fix birth date bug in credential
- Update nimbusds
- Update java non-major
- Update spring non-major to v6.2.5 (#98)


## [0.0.15] - 2025-03-19

### Added

- Add correct birth_date and age_in_years age_over_nn based on birth_date
- Add issuer state in auth code credential offer

### Fixed

- Update spring non-major


## [0.0.15-diggdev] - 2025-03-10

### Added

- Add valkey as cache, credential offer wip and static front page
- Add cwt proof metadata
- Add code_key supported in metadata
- Add mso mdoc proof support
- Add token lib source code as temporary work-around
- Add par metadata in well-known

### Changed

- Use snapshots from central
- Change encoding of mso mdoc credential to base64 url encoded
- Bump token lib files
- Replace token lib
- Quick and dirty fix _sd_alg lowercase in order to test with refimpl app
- Update cgr.dev/chainguard/jre:latest docker digest to 35d28ee

### Fixed

- Fix another proof binding work-around
- Fix proof binding work-around
- Fix dependency issue
- Update spring non-major
- Update nimbusds

## [0.0.14] - 2025-02-03

### Fixed

- Fix jar build for image


## [0.0.13] - 2025-02-03

### Changed

- Use org wide shared components
- Correct typ in jwt header when sd jwt vc
- Correct credential response exkl nonce


## [0.0.12] - 2025-01-30

### Added

- Add mso mdoc support
- Add missing mdl metadata
- Add mdl eu.europa.ec.eudi.pid_mdoc - work in progress
- Add scope eu.europa.ec.eudi.pid.1 support


## [0.0.11] - 2025-01-29

### Changed

- Update dependency org.apache.maven.plugins:maven-gpg-plugin to v3
- Upgrade nimbus dependencies
- Update maven-plugins
- Update github actions
- Merge branch 'renovate/cgr.dev-chainguard-jre-latest'
- Update cgr.dev/chainguard/jre:latest docker digest to 32f8e50

### Fixed

- Update dependency se.swedenconnect.security:credentials-support to v2
- Update java non-major
- Update dev tools


## [0.0.10] - 2025-01-28

### Changed

- Correct package info
- Generate pid with data-types and add dependencies as source code


## [0.0.9] - 2025-01-23

### Changed

- Restore releaseTmp note
- Restore jar artifact
- Update github actions
- Migrate renovate config
- Update orhun/git-cliff-action action to v4
- Group java deps
- Improve release flow

### Removed

- Remove gradle


## [0.0.8] - 2025-01-23

### Removed

- Remove hard coded urls (#55)


## [0.0.7] - 2025-01-18

### Added

- Add refresh of main branch


## [0.0.6] - 2025-01-18

### Added

- Add tok for bot


## [0.0.5] - 2025-01-16

### Changed

- Resolve wallet instance from oidfederation with clientid


## [0.0.4] - 2025-01-16

### Fixed

- Fix types in var


## [0.0.3] - 2025-01-15

### Changed

- Update dependency org.apache.maven.plugins:maven-enforcer-plugin to v3.5.0
- Update dependency org.apache.maven.plugins:maven-failsafe-plugin to v3.5.2
- Update dependency org.apache.maven.plugins:maven-source-plugin to v3.3.1
- Update dependency org.apache.maven.plugins:maven-deploy-plugin to v3.1.3
- Update dependency org.apache.maven.plugins:maven-javadoc-plugin to v3.11.2
- Update dependency org.apache.maven.plugins:maven-surefire-plugin to v3.5.2
- Update dependency org.openapitools:openapi-generator-maven-plugin to v7.10.0
- Pin dependencies
- Update cgr.dev/chainguard/jre:latest docker digest to fba813a

### Fixed

- Update dependency org.bouncycastle:bcprov-jdk18on to v1.80
- Correct typo


## [0.0.2] - 2025-01-15

### Added

- Add work-around in order to handle a bug in openapi gen lib when multiple Accept types
- Add mvn build deps and fix test application.yml
- Add maven package repository for poc lib
- Add mvn support (#21)
- Add par authorization endpoint
- Add pre-auth code flow"
- Add working oidfed metadata and wip add jwk to issued credential
- Add cert instruction
- Add openid-federation and improve openid-credential-issuer metadata
- Add oid federation rest client

### Changed

- Improve workflows and friends
- Update cgr.dev/chainguard/jre:latest docker digest to fba813a
- Update plugin org.openapi.generator to v7.10.0
- Refactor, clean up, fix deprecated warnings
- Expose public jwk on endpoint and include kid in jwk
- Change configured host in dev profile to https://local.dev.swedenconnect.se:8443

### Fixed

- Correct release vars
- Make test run with bogus cert
- Update spring non-major
- Fix linting issues

## [0.0.1] - 2024-11-22

### Added

- Add ci,image,renovate,etc

### Changed

- Chore: cleanup and add workflow.
- Initial commit

### Fixed

- Update zxing to v3.5.3
- Update spring non-major

[0.23.2]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.23.1..v0.23.2
[0.23.1]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.23.0..v0.23.1
[0.23.0]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.22.0..v0.23.0
[0.22.0]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.21.0..v0.22.0
[0.21.0]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.20..v0.21.0
[0.0.20]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.19..v0.0.20
[0.0.19]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.18..v0.0.19
[0.0.18]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.17..v0.0.18
[0.0.17]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.15..v0.0.17
[0.0.15]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/0.0.15-diggdev..v0.0.15
[0.0.15-diggdev]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.14..0.0.15-diggdev
[0.0.14]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.13..v0.0.14
[0.0.13]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.12..v0.0.13
[0.0.12]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.11..v0.0.12
[0.0.11]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.10..v0.0.11
[0.0.10]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.9..v0.0.10
[0.0.9]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.8..v0.0.9
[0.0.8]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.7..v0.0.8
[0.0.7]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.6..v0.0.7
[0.0.6]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.5..v0.0.6
[0.0.5]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.4..v0.0.5
[0.0.4]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.3..v0.0.4
[0.0.3]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.2..v0.0.3
[0.0.2]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.1..v0.0.2

<!-- generated by git-cliff -->
