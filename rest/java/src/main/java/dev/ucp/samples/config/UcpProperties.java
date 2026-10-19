/*
 * Copyright 2026 UCP Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dev.ucp.samples.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Server configuration, bound from {@code ucp.*} in application.properties, which in turn reads
 * the same environment variables as the Node.js and Python reference servers.
 *
 * <p>The flags are mutable so tests can toggle enforcement at runtime, mirroring the Node
 * server's {@code signatureConfig} and the Python server's {@code config.FLAGS}.
 */
@ConfigurationProperties(prefix = "ucp")
public class UcpProperties {

  /** The UCP protocol version this server implements. */
  public static final String UCP_VERSION = "2026-04-08";

  /**
   * REQUIRE_SIGNATURES: reject requests whose RFC 9421 signature is missing or invalid. When
   * false, a present signature is still verified and the outcome logged.
   */
  private boolean requireSignatures;

  /**
   * ALLOW_INSECURE_PROFILE_URLS: permit http and loopback/private profile URLs when resolving
   * signer keys. For localhost demos and CI only.
   */
  private boolean allowInsecureProfileUrls;

  /**
   * WEBHOOK_SIGNING_KEY: path to a PEM private key (EC P-256 or Ed25519) used to sign outbound
   * order-event webhooks. When unset, an ephemeral demo key is generated at startup.
   */
  private String webhookSigningKey;

  /** SIMULATION_SECRET: shared secret guarding the testing endpoints. */
  private String simulationSecret = "super-secret-sim-key";

  /** Path of the SQLite products database. */
  private String productsDbPath = "databases/products.db";

  /** Path of the SQLite transactions database. */
  private String transactionsDbPath = "databases/transactions.db";

  public boolean isRequireSignatures() {
    return requireSignatures;
  }

  public void setRequireSignatures(boolean requireSignatures) {
    this.requireSignatures = requireSignatures;
  }

  public boolean isAllowInsecureProfileUrls() {
    return allowInsecureProfileUrls;
  }

  public void setAllowInsecureProfileUrls(boolean allowInsecureProfileUrls) {
    this.allowInsecureProfileUrls = allowInsecureProfileUrls;
  }

  public String getWebhookSigningKey() {
    return webhookSigningKey;
  }

  public void setWebhookSigningKey(String webhookSigningKey) {
    this.webhookSigningKey = webhookSigningKey;
  }

  public String getSimulationSecret() {
    return simulationSecret;
  }

  public void setSimulationSecret(String simulationSecret) {
    this.simulationSecret = simulationSecret;
  }

  public String getProductsDbPath() {
    return productsDbPath;
  }

  public void setProductsDbPath(String productsDbPath) {
    this.productsDbPath = productsDbPath;
  }

  public String getTransactionsDbPath() {
    return transactionsDbPath;
  }

  public void setTransactionsDbPath(String transactionsDbPath) {
    this.transactionsDbPath = transactionsDbPath;
  }
}
