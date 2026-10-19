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

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * Conversion between JDK public keys and UCP JWKs (RFC 7517), limited to the key types UCP
 * verifiers must support (EC P-256) plus Ed25519.
 */
public final class Jwks {

  /** P-256 coordinate width in bytes. */
  static final int ES256_COORD_BYTES = 32;

  /** The fixed DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410), before the raw key. */
  private static final byte[] ED25519_SPKI_PREFIX = {
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
  };

  private static final ECParameterSpec P256 = p256();

  private Jwks() {}

  /** Exports a public key as a UCP JWK carrying {@code kid}, {@code use: "sig"} and {@code alg}. */
  public static ObjectNode fromPublicKey(PublicKey publicKey, String kid) {
    ObjectNode jwk = JsonNodeFactory.instance.objectNode();
    jwk.put("kid", kid);
    if (publicKey instanceof ECPublicKey ec) {
      ECPoint w = ec.getW();
      jwk.put("kty", "EC");
      jwk.put("crv", "P-256");
      jwk.put("x", b64url(unsigned(w.getAffineX(), ES256_COORD_BYTES)));
      jwk.put("y", b64url(unsigned(w.getAffineY(), ES256_COORD_BYTES)));
      jwk.put("use", "sig");
      jwk.put("alg", "ES256");
    } else if (publicKey instanceof EdECPublicKey) {
      byte[] spki = publicKey.getEncoded();
      jwk.put("kty", "OKP");
      jwk.put("crv", "Ed25519");
      jwk.put("x", b64url(Arrays.copyOfRange(spki, spki.length - 32, spki.length)));
      jwk.put("use", "sig");
      jwk.put("alg", "EdDSA");
    } else {
      throw new IllegalArgumentException("Unsupported key type: " + publicKey.getAlgorithm());
    }
    return jwk;
  }

  /**
   * Builds a JDK public key from a UCP JWK. EC P-256 and Ed25519 are supported; anything else is
   * {@code algorithm_unsupported}, and a malformed supported key is {@code signature_invalid}.
   */
  public static PublicKey toPublicKey(JsonNode jwk) {
    String kty = text(jwk, "kty");
    String crv = text(jwk, "crv");
    try {
      if ("EC".equals(kty) && "P-256".equals(crv)) {
        BigInteger x = new BigInteger(1, coordinate(jwk, "x"));
        BigInteger y = new BigInteger(1, coordinate(jwk, "y"));
        ECPoint point = new ECPoint(x, y);
        if (!onP256(point)) {
          throw new GeneralSecurityException("point is not on P-256");
        }
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, P256));
      }
      if ("OKP".equals(kty) && "Ed25519".equals(crv)) {
        byte[] raw = coordinate(jwk, "x");
        byte[] spki = Arrays.copyOf(ED25519_SPKI_PREFIX, ED25519_SPKI_PREFIX.length + raw.length);
        System.arraycopy(raw, 0, spki, ED25519_SPKI_PREFIX.length, raw.length);
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
      }
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      throw new SignatureException("signature_invalid", 401, "Malformed JWK: " + e.getMessage());
    }
    throw new SignatureException(
        "algorithm_unsupported",
        400,
        "Unsupported key type/curve: kty=" + quote(kty) + " crv=" + quote(crv));
  }

  /**
   * The RFC 7638 JWK thumbprint (base64url SHA-256 over the required public members in
   * lexicographic order, no whitespace), used as the kid so a key keeps its identifier across
   * restarts.
   */
  public static String thumbprint(PublicKey publicKey) {
    JsonNode jwk = fromPublicKey(publicKey, "");
    String canonical =
        "OKP".equals(text(jwk, "kty"))
            ? "{\"crv\":\"%s\",\"kty\":\"OKP\",\"x\":\"%s\"}"
                .formatted(text(jwk, "crv"), text(jwk, "x"))
            : "{\"crv\":\"%s\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}"
                .formatted(text(jwk, "crv"), text(jwk, "x"), text(jwk, "y"));
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8));
      return b64url(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Whether a public key is an EC P-256 key. */
  static boolean isP256(ECParameterSpec params) {
    return params.getCurve().equals(P256.getCurve())
        && params.getGenerator().equals(P256.getGenerator())
        && params.getOrder().equals(P256.getOrder());
  }

  static ECParameterSpec p256Params() {
    return P256;
  }

  private static boolean onP256(ECPoint point) {
    BigInteger p = ((ECFieldFp) P256.getCurve().getField()).getP();
    BigInteger x = point.getAffineX();
    BigInteger y = point.getAffineY();
    if (x.signum() < 0 || x.compareTo(p) >= 0 || y.signum() < 0 || y.compareTo(p) >= 0) {
      return false;
    }
    BigInteger left = y.multiply(y).mod(p);
    BigInteger right =
        x.pow(3).add(P256.getCurve().getA().multiply(x)).add(P256.getCurve().getB()).mod(p);
    return left.equals(right);
  }

  private static byte[] coordinate(JsonNode jwk, String member) {
    String value = text(jwk, member);
    if (value == null) {
      throw new IllegalArgumentException("missing member '" + member + "'");
    }
    byte[] decoded = Base64.getUrlDecoder().decode(value);
    if (decoded.length != 32) {
      throw new IllegalArgumentException("member '" + member + "' must be 32 bytes");
    }
    return decoded;
  }

  private static String text(JsonNode node, String member) {
    JsonNode value = node == null ? null : node.get(member);
    return value != null && value.isString() ? value.stringValue() : null;
  }

  private static String quote(String value) {
    return value == null ? "undefined" : "\"" + value + "\"";
  }

  static String b64url(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  /** A non-negative integer as a fixed-width big-endian byte array. */
  static byte[] unsigned(BigInteger value, int width) {
    byte[] bytes = value.toByteArray();
    if (bytes.length == width) {
      return bytes;
    }
    byte[] out = new byte[width];
    if (bytes.length > width) {
      // Strip the sign byte BigInteger adds when the high bit is set.
      System.arraycopy(bytes, bytes.length - width, out, 0, width);
    } else {
      System.arraycopy(bytes, 0, out, width - bytes.length, bytes.length);
    }
    return out;
  }

  private static ECParameterSpec p256() {
    try {
      AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
      params.init(new ECGenParameterSpec("secp256r1"));
      return params.getParameterSpec(ECParameterSpec.class);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("P-256 is not available in this JDK", e);
    }
  }
}
