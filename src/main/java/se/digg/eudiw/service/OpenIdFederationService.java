package se.digg.eudiw.service;


import se.oidc.oidfed.md.wallet.credentialissuer.WalletOAuthClientMetadata;

import java.util.List;

public interface OpenIdFederationService {
  WalletOAuthClientMetadata resolveWallet(String walletId);

  String trustMark(String trustMarkId, String subject);

  List<String> activeWallets();
}

