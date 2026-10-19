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

package dev.ucp.samples.signing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.StringWriter;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.JsonNode;

/** Unit tests for the RFC 9421 helpers, JWK conversion, SSRF rules, and key loading. */
class SigningUnitTest {

  private static final byte[] BODY = "{\"hello\":\"world\"}".getBytes(StandardCharsets.UTF_8);

  @Test
  void contentDigestRoundTrips() {
    String digest = HttpSignatures.contentDigest(BODY);

    assertThat(digest).startsWith("sha-256=:").endsWith(":");
    assertThat(HttpSignatures.contentDigestMatches(digest, BODY)).isTrue();
    assertThat(HttpSignatures.contentDigestMatches(digest, "other".getBytes())).isFalse();
    assertThat(HttpSignatures.contentDigestMatches("sha-512=:AAAA:", BODY)).isFalse();
  }

  @Test
  void signatureInputIsParsedWithItsRawMemberValue() {
    var parsed =
        HttpSignatures.parseSignatureInput(
            "sig1=(\"@method\" \"@path\");created=1700000000;keyid=\"k1\"");

    assertThat(parsed).containsKey("sig1");
    var member = parsed.get("sig1");
    assertThat(member.components()).containsExactly("@method", "@path");
    assertThat(member.params()).containsEntry("keyid", "k1").containsEntry("created", "1700000000");
    assertThat(member.raw()).isEqualTo("(\"@method\" \"@path\");created=1700000000;keyid=\"k1\"");
    assertThat(HttpSignatures.parseSignatureInput("garbage")).isNull();
    assertThat(HttpSignatures.parseSignature("sig1=:not base64!:")).isNull();
  }

  @Test
  void authorityIsNormalized() {
    assertThat(HttpSignatures.normalizeAuthority("Shop.Example:443")).isEqualTo("shop.example");
    assertThat(HttpSignatures.normalizeAuthority("shop.example:80")).isEqualTo("shop.example");
    assertThat(HttpSignatures.normalizeAuthority("shop.example:8443"))
        .isEqualTo("shop.example:8443");
  }

  @Test
  void es256AndEd25519SignaturesRoundTrip() throws Exception {
    for (KeyPair pair : List.of(ecKeyPair(), KeyPairGenerator.getInstance("Ed25519").generateKeyPair())) {
      JsonNode jwk = Jwks.fromPublicKey(pair.getPublic(), "k1");
      Map<String, String> headers = new LinkedHashMap<>();
      headers.put("Idempotency-Key", "abc");
      headers.putAll(
          HttpSignatures.signRequest(
              pair.getPrivate(),
              "k1",
              "POST",
              "https://shop.example/checkout-sessions?x=1",
              headers,
              BODY,
              null,
              List.of()));
      Map<String, String> lower = new LinkedHashMap<>();
      headers.forEach((k, v) -> lower.put(k.toLowerCase(), v));

      String keyid =
          HttpSignatures.verifyRequest(
              "POST", "shop.example:443", "/checkout-sessions", "x=1", lower, BODY, List.of(jwk));

      assertThat(keyid).isEqualTo("k1");
      assertThat(lower.get("signature-input")).contains("\"@query\"", "\"idempotency-key\"");
    }
  }

  @Test
  void ecdsaSignaturesAreFixedWidth() throws Exception {
    KeyPair pair = ecKeyPair();
    byte[] signature = HttpSignatures.rawSign(pair.getPrivate(), BODY);

    assertThat(signature).hasSize(64);
  }

  @Test
  void jwkRoundTripsAndRejectsOffCurvePoints() throws Exception {
    KeyPair pair = ecKeyPair();
    var jwk = Jwks.fromPublicKey(pair.getPublic(), "k1");

    assertThat(Jwks.toPublicKey(jwk)).isEqualTo(pair.getPublic());

    jwk.put("y", jwk.get("x").stringValue());
    assertThatThrownBy(() -> Jwks.toPublicKey(jwk))
        .isInstanceOf(SignatureException.class)
        .extracting("code")
        .isEqualTo("signature_invalid");
  }

  @Test
  void thumbprintIsStableForAKey() throws Exception {
    KeyPair pair = ecKeyPair();

    assertThat(Jwks.thumbprint(pair.getPublic()))
        .isEqualTo(Jwks.thumbprint(pair.getPublic()))
        .matches("[A-Za-z0-9_-]{43}");
  }

  @Test
  void specialUseAddressesAreDisallowed() throws Exception {
    for (String address :
        List.of("127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.0.1", "::1", "fe80::1",
            "::ffff:127.0.0.1", "2001:db8::1")) {
      assertThat(ProfileKeyResolver.isDisallowedAddress(InetAddress.getByName(address)))
          .as(address)
          .isTrue();
    }
    for (String address : List.of("8.8.8.8", "2606:4700::1111")) {
      assertThat(ProfileKeyResolver.isDisallowedAddress(InetAddress.getByName(address)))
          .as(address)
          .isFalse();
    }
  }

  @Test
  void profileUrlsMustBeHttpsWithoutCredentials() {
    assertThatThrownBy(() -> ProfileKeyResolver.assertProfileUrlAllowed("http://a.example/p", false))
        .extracting("code")
        .isEqualTo("invalid_profile_url");
    assertThatThrownBy(
            () -> ProfileKeyResolver.assertProfileUrlAllowed("https://u:p@a.example/p", false))
        .extracting("code")
        .isEqualTo("invalid_profile_url");
    assertThatThrownBy(() -> ProfileKeyResolver.assertProfileUrlAllowed("https://127.0.0.1/p", false))
        .extracting("code")
        .isEqualTo("invalid_profile_url");
  }

  @Test
  void pemSigningKeysLoadWithAStableKid(@TempDir Path dir) throws Exception {
    for (KeyPair pair : List.of(ecKeyPair(), KeyPairGenerator.getInstance("Ed25519").generateKeyPair())) {
      Path pem = dir.resolve(pair.getPrivate().getAlgorithm() + ".pem");
      Files.writeString(pem, pkcs8Pem(pair.getPrivate()));

      KeyPair loaded = WebhookSigningKey.load(pem);

      assertThat(loaded.getPublic()).isEqualTo(pair.getPublic());
      assertThat(Jwks.thumbprint(loaded.getPublic())).isEqualTo(Jwks.thumbprint(pair.getPublic()));
    }
  }

  @Test
  void sec1EcSigningKeysLoad(@TempDir Path dir) throws Exception {
    KeyPair pair = ecKeyPair();
    // RFC 5915 ECPrivateKey with the named curve in its parameters, as `openssl ecparam
    // -genkey` writes it.
    byte[] sec1 =
        new org.bouncycastle.asn1.sec.ECPrivateKey(
                256,
                ((ECPrivateKey) pair.getPrivate()).getS(),
                new X962Parameters(SECObjectIdentifiers.secp256r1))
            .getEncoded();
    Path pem = dir.resolve("sec1.pem");
    try (PemWriter writer = new PemWriter(Files.newBufferedWriter(pem))) {
      writer.writeObject(new PemObject("EC PRIVATE KEY", sec1));
    }

    assertThat(WebhookSigningKey.load(pem).getPublic()).isEqualTo(pair.getPublic());
  }

  @Test
  void nonP256SigningKeysAreRefused(@TempDir Path dir) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp384r1"));
    Path pem = dir.resolve("p384.pem");
    Files.writeString(pem, pkcs8Pem(generator.generateKeyPair().getPrivate()));

    assertThatThrownBy(() -> WebhookSigningKey.load(pem))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("P-256");
  }

  private static String pkcs8Pem(PrivateKey key) throws Exception {
    StringWriter out = new StringWriter();
    try (PemWriter writer = new PemWriter(out)) {
      writer.writeObject(new PemObject("PRIVATE KEY", key.getEncoded()));
    }
    return out.toString();
  }

  private static KeyPair ecKeyPair() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    return generator.generateKeyPair();
  }
}
