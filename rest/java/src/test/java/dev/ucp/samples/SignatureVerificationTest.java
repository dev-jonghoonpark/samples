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

package dev.ucp.samples;

import static org.assertj.core.api.Assertions.assertThat;

import dev.ucp.samples.signing.HttpSignatures;
import dev.ucp.samples.signing.Jwks;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/** RFC 9421 request-signature verification on the business endpoints. */
class SignatureVerificationTest extends ServerTestSupport {

  private static final byte[] BODY =
      "{\"line_items\":[{\"item\":{\"id\":\"bouquet_roses\"},\"quantity\":1}]}".getBytes();

  private static StubServer profiles;
  private static KeyPair es256;
  private static KeyPair ed25519;
  private static KeyPair unpublished;

  @BeforeAll
  static void startProfileServer() throws Exception {
    es256 = ecKeyPair();
    unpublished = ecKeyPair();
    ed25519 = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();

    profiles = new StubServer();
    ArrayNode keys = JSON.createArrayNode();
    keys.add(Jwks.fromPublicKey(es256.getPublic(), "es256-key"));
    keys.add(Jwks.fromPublicKey(ed25519.getPublic(), "ed25519-key"));
    keys.add(json("{'kid':'rsa-key','kty':'RSA','n':'AQAB','e':'AQAB'}"));
    ObjectNode profile = JSON.createObjectNode();
    profile.putObject("ucp").put("version", "2026-04-08");
    profile.set("signing_keys", keys);
    profiles.serve("/profile", JSON.writeValueAsString(profile));
    profiles.serve("/keyless", "{\"ucp\":{\"version\":\"2026-04-08\"}}");
  }

  @AfterAll
  static void stopProfileServer() {
    profiles.close();
  }

  @BeforeEach
  void enforce() {
    properties.setRequireSignatures(true);
    // The stub profile server is plain http on loopback.
    properties.setAllowInsecureProfileUrls(true);
  }

  private Map<String, String> baseHeaders(String profilePath) {
    Map<String, String> headers = new LinkedHashMap<>();
    headers.put("Content-Type", "application/json");
    headers.put("Idempotency-Key", UUID.randomUUID().toString());
    headers.put("UCP-Agent", "profile=\"" + profiles.url() + profilePath + "\"");
    return headers;
  }

  /** Signs a create request with the given key and returns all headers to send. */
  private Map<String, String> signedCreate(KeyPair key, String kid, String profilePath) {
    Map<String, String> headers = baseHeaders(profilePath);
    headers.putAll(
        HttpSignatures.signRequest(
            key.getPrivate(),
            kid,
            "POST",
            baseUrl() + "/checkout-sessions",
            headers,
            BODY,
            null,
            List.of()));
    return headers;
  }

  private Response create(Map<String, String> headers) {
    return sendRaw("POST", "/checkout-sessions", BODY, headers);
  }

  @Test
  void aCorrectlySignedRequestIsAccepted() {
    assertThat(create(signedCreate(es256, "es256-key", "/profile")).status()).isEqualTo(201);
  }

  @Test
  void anEd25519SignedRequestIsAccepted() {
    assertThat(create(signedCreate(ed25519, "ed25519-key", "/profile")).status()).isEqualTo(201);
  }

  @Test
  void aSignedGetVerifiesEndToEnd() {
    Map<String, String> headers = new LinkedHashMap<>();
    headers.put("UCP-Agent", "profile=\"" + profiles.url() + "/profile\"");
    headers.putAll(
        HttpSignatures.signRequest(
            es256.getPrivate(),
            "es256-key",
            "GET",
            baseUrl() + "/checkout-sessions/missing",
            headers,
            new byte[0],
            null,
            List.of()));

    // Past the signature gate: the checkout simply does not exist.
    assertError(sendRaw("GET", "/checkout-sessions/missing", new byte[0], headers), 404,
        "RESOURCE_NOT_FOUND");
  }

  @Test
  void anUnsignedRequestIsRejected() {
    Response response = create(baseHeaders("/profile"));

    assertError(response, 401, "signature_missing");
    assertThat(response.body().path("messages").path(0).path("severity").asString())
        .isEqualTo("unrecoverable");
    assertError(get("/orders/anything"), 401, "signature_missing");
  }

  @Test
  void aSignatureWithoutAProfileIsInvalid() {
    Map<String, String> headers = signedCreate(es256, "es256-key", "/profile");
    headers.remove("UCP-Agent");

    assertError(create(headers), 401, "signature_invalid");
  }

  @Test
  void aTamperedBodyIsADigestMismatch() {
    Map<String, String> headers = signedCreate(es256, "es256-key", "/profile");
    byte[] tampered = new String(BODY).replace("\"quantity\":1", "\"quantity\":9").getBytes();

    assertError(sendRaw("POST", "/checkout-sessions", tampered, headers), 400, "digest_mismatch");
  }

  @Test
  void aGarbageSignatureIsInvalid() {
    Map<String, String> headers = signedCreate(es256, "es256-key", "/profile");
    headers.put("Signature", "sig1=:" + Base64.getEncoder().encodeToString(new byte[64]) + ":");

    assertError(create(headers), 401, "signature_invalid");
  }

  @Test
  void aSignatureFromAnUnpublishedKeyIsInvalid() {
    assertError(create(signedCreate(unpublished, "es256-key", "/profile")), 401,
        "signature_invalid");
  }

  @Test
  void anUnknownKeyidIsKeyNotFound() {
    assertError(create(signedCreate(es256, "who-is-this", "/profile")), 401, "key_not_found");
  }

  @Test
  void aDerEncodedSignatureIsRejected() throws Exception {
    Map<String, String> headers = signedCreate(es256, "es256-key", "/profile");
    String rawParams = headers.get("Signature-Input").substring("sig1=".length());
    String base =
        "\"@method\": POST\n\"@authority\": localhost:%d\n\"@path\": /checkout-sessions\n"
                .formatted(port)
            + "\"content-digest\": %s\n\"content-type\": application/json\n"
                .formatted(headers.get("Content-Digest"))
            + "\"idempotency-key\": %s\n\"ucp-agent\": %s\n\"@signature-params\": %s"
                .formatted(headers.get("Idempotency-Key"), headers.get("UCP-Agent"), rawParams);
    Signature der = Signature.getInstance("SHA256withECDSA");
    der.initSign(es256.getPrivate());
    der.update(base.getBytes());
    headers.put("Signature", "sig1=:" + Base64.getEncoder().encodeToString(der.sign()) + ":");

    Response response = create(headers);

    assertError(response, 401, "signature_invalid");
    assertThat(response.body().path("messages").path(0).path("content").asString())
        .contains("ASN.1/DER");
  }

  @Test
  void omittingARequiredComponentIsInvalid() {
    Map<String, String> headers = baseHeaders("/profile");
    // Sign before adding the idempotency key, so the signature does not cover it.
    String key = headers.remove("Idempotency-Key");
    headers.putAll(
        HttpSignatures.signRequest(
            es256.getPrivate(), "es256-key", "POST", baseUrl() + "/checkout-sessions", headers,
            BODY, null, List.of()));
    headers.put("Idempotency-Key", key);

    assertError(create(headers), 401, "signature_invalid");
  }

  @Test
  void anAlgParameterIsInvalid() {
    Map<String, String> headers = signedCreate(es256, "es256-key", "/profile");
    headers.put("Signature-Input", headers.get("Signature-Input") + ";alg=\"ecdsa-p256-sha256\"");

    assertError(create(headers), 401, "signature_invalid");
  }

  @Test
  void aKeyidSelectingAnRsaKeyIsAlgorithmUnsupported() {
    assertError(create(signedCreate(es256, "rsa-key", "/profile")), 400, "algorithm_unsupported");
  }

  @Test
  void aKeylessProfileIsMalformed() {
    assertError(create(signedCreate(es256, "es256-key", "/keyless")), 422, "profile_malformed");
  }

  @Test
  void anUnreachableProfileIsReported() {
    Map<String, String> headers = signedCreate(es256, "es256-key", "/profile");
    headers.put("UCP-Agent", "profile=\"http://127.0.0.1:1/profile\"");

    assertError(create(headers), 424, "profile_unreachable");
  }

  @Test
  void anHttpProfileWithoutTheCarveOutIsRejected() {
    properties.setAllowInsecureProfileUrls(false);

    assertError(create(signedCreate(es256, "es256-key", "/profile")), 400, "invalid_profile_url");
  }

  @Test
  void oneBadAndOneValidSignatureIsAccepted() {
    Map<String, String> headers = signedCreate(es256, "es256-key", "/profile");
    String input = headers.get("Signature-Input").substring("sig1=".length());
    String signature = headers.get("Signature").substring("sig1=".length());
    headers.put("Signature-Input", "bad=" + input + ", sig1=" + input);
    headers.put(
        "Signature",
        "bad=:" + Base64.getEncoder().encodeToString(new byte[64]) + ":, sig1=" + signature);

    assertThat(create(headers).status()).isEqualTo(201);
  }

  @Test
  void permissiveModeAllowsUnsignedAndInvalidRequests() {
    properties.setRequireSignatures(false);

    assertThat(create(baseHeaders("/profile")).status()).isEqualTo(201);
    Map<String, String> invalid = signedCreate(unpublished, "es256-key", "/profile");
    assertThat(create(invalid).status()).isEqualTo(201);
  }

  private static KeyPair ecKeyPair() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    return generator.generateKeyPair();
  }
}
