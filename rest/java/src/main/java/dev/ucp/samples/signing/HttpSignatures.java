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

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.EdECKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import tools.jackson.databind.JsonNode;

/**
 * RFC 9421 HTTP Message Signatures for UCP, using the default UCP profile.
 *
 * <p>This is the Java twin of the Python server's {@code ucp_signing.py} and the Node.js
 * server's {@code signature.ts}: signature-base construction with the UCP covered-component set,
 * RFC 9530 {@code Content-Digest} over the raw body bytes (sha-256), ES256 (ECDSA P-256 with
 * fixed-width raw {@code r||s} signatures, never ASN.1/DER) plus Ed25519. Only the JDK's built-in
 * providers are used; the RFC 8941 structured-field subset is hand-rolled.
 */
public final class HttpSignatures {

  private static final Pattern BASE64 =
      Pattern.compile("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$");

  /** One parsed Signature-Input member. */
  public record SignatureInputMember(
      String raw, List<String> components, Map<String, String> params) {}

  private HttpSignatures() {}

  /** The RFC 9530 Content-Digest value (sha-256 over the raw body bytes). */
  public static String contentDigest(byte[] body) {
    return "sha-256=:" + Base64.getEncoder().encodeToString(sha256(body)) + ":";
  }

  /**
   * Whether a Content-Digest header covers the given body. Only the sha-256 member is inspected,
   * matching the spec's requirement to use sha-256.
   */
  public static boolean contentDigestMatches(String headerValue, byte[] body) {
    byte[] want = sha256(body);
    for (String member : sfSplit(headerValue, ",")) {
      int eq = member.indexOf('=');
      String key = (eq == -1 ? member : member.substring(0, eq)).trim();
      if (!key.equals("sha-256")) {
        continue;
      }
      String value = (eq == -1 ? "" : member.substring(eq + 1)).trim();
      if (value.length() < 2 || !value.startsWith(":") || !value.endsWith(":")) {
        return false;
      }
      String encoded = value.substring(1, value.length() - 1);
      if (!BASE64.matcher(encoded).matches()) {
        return false;
      }
      return MessageDigest.isEqual(want, Base64.getDecoder().decode(encoded));
    }
    return false;
  }

  /**
   * Splits a structured-field string on top-level separators. Quoted strings and inner lists are
   * opaque -- enough of RFC 8941 to parse the signature headers.
   */
  public static List<String> sfSplit(String value, String separators) {
    List<String> out = new ArrayList<>();
    StringBuilder cur = new StringBuilder();
    int depth = 0;
    boolean quote = false;
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (quote) {
        cur.append(c);
        if (c == '\\' && i + 1 < value.length()) {
          cur.append(value.charAt(i + 1));
          i++;
        } else if (c == '"') {
          quote = false;
        }
      } else if (c == '"') {
        quote = true;
        cur.append(c);
      } else if (c == '(') {
        depth++;
        cur.append(c);
      } else if (c == ')') {
        depth--;
        cur.append(c);
      } else if (separators.indexOf(c) >= 0 && depth == 0) {
        out.add(cur.toString().trim());
        cur.setLength(0);
      } else {
        cur.append(c);
      }
    }
    String tail = cur.toString().trim();
    if (!tail.isEmpty()) {
      out.add(tail);
    }
    return out;
  }

  /**
   * Parses a Signature-Input header into per-label descriptors: the member value verbatim (what
   * {@code @signature-params} must echo), the unquoted component identifiers, and the parameters.
   *
   * @return the members by label, or null on malformed input
   */
  public static Map<String, SignatureInputMember> parseSignatureInput(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    Map<String, SignatureInputMember> out = new LinkedHashMap<>();
    for (String member : sfSplit(value, ",")) {
      int eq = member.indexOf('=');
      String label = (eq == -1 ? member : member.substring(0, eq)).trim();
      String val = (eq == -1 ? "" : member.substring(eq + 1)).trim();
      if (eq == -1 || label.isEmpty() || !val.startsWith("(")) {
        return null;
      }
      int depth = 0;
      int end = -1;
      for (int i = 0; i < val.length(); i++) {
        char c = val.charAt(i);
        if (c == '(') {
          depth++;
        } else if (c == ')') {
          depth--;
          if (depth == 0) {
            end = i;
            break;
          }
        }
      }
      if (end == -1) {
        return null;
      }
      String inner = val.substring(1, end);
      String rest = val.substring(end + 1);
      List<String> components = new ArrayList<>();
      for (String token : sfSplit(inner, " ")) {
        if (token.length() < 2
            || !token.startsWith("\"")
            || !token.endsWith("\"")
            || token.contains(";")) {
          return null;
        }
        components.add(token.substring(1, token.length() - 1));
      }
      Map<String, String> params = new LinkedHashMap<>();
      for (String part : sfSplit(rest, ";")) {
        if (part.isEmpty()) {
          continue;
        }
        int pEq = part.indexOf('=');
        String k = (pEq == -1 ? part : part.substring(0, pEq)).trim();
        String v = pEq == -1 ? "" : part.substring(pEq + 1);
        if (v.length() >= 2 && v.startsWith("\"") && v.endsWith("\"")) {
          v = v.substring(1, v.length() - 1);
        }
        params.put(k, v);
      }
      out.put(label, new SignatureInputMember(val, components, params));
    }
    return out.isEmpty() ? null : out;
  }

  /**
   * Parses a Signature header into raw signature bytes by label.
   *
   * @return the signatures by label, or null on malformed input
   */
  public static Map<String, byte[]> parseSignature(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    Map<String, byte[]> out = new LinkedHashMap<>();
    for (String member : sfSplit(value, ",")) {
      int eq = member.indexOf('=');
      String label = (eq == -1 ? member : member.substring(0, eq)).trim();
      String val = (eq == -1 ? "" : member.substring(eq + 1)).trim();
      if (eq == -1 || val.length() < 2 || !val.startsWith(":") || !val.endsWith(":")) {
        return null;
      }
      String encoded = val.substring(1, val.length() - 1);
      if (!BASE64.matcher(encoded).matches()) {
        return null;
      }
      out.put(label, Base64.getDecoder().decode(encoded));
    }
    return out.isEmpty() ? null : out;
  }

  /**
   * Constructs the RFC 9421 signature base. The raw Signature-Input member value is echoed
   * verbatim on the {@code @signature-params} line.
   *
   * @return the base, or null if any covered component cannot be resolved for this message
   */
  public static byte[] buildSignatureBase(
      List<String> components, String rawParams, Function<String, String> resolve) {
    List<String> lines = new ArrayList<>();
    for (String name : components) {
      String value = resolve.apply(name);
      if (value == null) {
        return null;
      }
      lines.add("\"" + name + "\": " + value);
    }
    lines.add("\"@signature-params\": " + rawParams);
    return String.join("\n", lines).getBytes(StandardCharsets.UTF_8);
  }

  /**
   * The components a UCP request signature MUST cover (the verification-side coverage gate from
   * signatures.md). Coverage keys on header presence, not on the method.
   *
   * @param headers request headers keyed by lowercase name
   */
  public static List<String> requiredComponents(
      boolean hasQuery, Map<String, String> headers, boolean hasBody) {
    List<String> required = new ArrayList<>(List.of("@method", "@authority", "@path"));
    if (hasQuery) {
      required.add("@query");
    }
    if (hasBody) {
      required.add("content-digest");
      required.add("content-type");
    }
    if (headers.containsKey("idempotency-key")) {
      required.add("idempotency-key");
    }
    if (headers.containsKey("ucp-agent")) {
      required.add("ucp-agent");
    }
    return required;
  }

  /**
   * Normalises an authority per RFC 9421 Section 2.2.3: lowercase, scheme default port stripped,
   * so {@code host:443} added by an intermediary reconstructs to the value the signer used.
   */
  public static String normalizeAuthority(String host) {
    String authority = host.toLowerCase(Locale.ROOT);
    if (authority.endsWith(":443")) {
      return authority.substring(0, authority.length() - 4);
    }
    if (authority.endsWith(":80")) {
      return authority.substring(0, authority.length() - 3);
    }
    return authority;
  }

  /**
   * Verifies a signature base against a JWK public key. The algorithm is derived from the key's
   * kty/crv -- never from a Signature-Input {@code alg} parameter, which UCP forbids. ECDSA
   * signatures MUST be fixed-width raw {@code r||s} (64 bytes for P-256); ASN.1/DER is rejected
   * before any verification is attempted.
   */
  public static void verifyRawSignature(JsonNode jwk, byte[] base, byte[] signature) {
    PublicKey publicKey = Jwks.toPublicKey(jwk);
    if (publicKey instanceof EdECKey) {
      if (!verify("Ed25519", publicKey, base, signature)) {
        throw new SignatureException(
            "signature_invalid", 401, "Ed25519 signature verification failed");
      }
      return;
    }
    if (signature.length != 2 * Jwks.ES256_COORD_BYTES) {
      throw new SignatureException(
          "signature_invalid",
          401,
          "ECDSA signature must be "
              + 2 * Jwks.ES256_COORD_BYTES
              + "-byte raw r||s, got "
              + signature.length
              + " bytes (ASN.1/DER is not permitted)");
    }
    if (!verify("SHA256withECDSAinP1363Format", publicKey, base, signature)) {
      throw new SignatureException("signature_invalid", 401, "ES256 signature verification failed");
    }
  }

  /**
   * Verifies the signatures on an inbound UCP request. A request is accepted when at least one
   * carried signature fully verifies; it is rejected only when every candidate signature is
   * skipped or fails.
   *
   * @param headers request headers keyed by lowercase name
   * @return the keyid that verified
   */
  public static String verifyRequest(
      String method,
      String authority,
      String path,
      String query,
      Map<String, String> headers,
      byte[] body,
      List<JsonNode> keys) {
    Map<String, SignatureInputMember> sigInput =
        parseSignatureInput(headers.getOrDefault("signature-input", ""));
    Map<String, byte[]> sigs = parseSignature(headers.getOrDefault("signature", ""));
    if (sigInput == null || sigs == null) {
      throw new SignatureException(
          "signature_missing", 401, "Missing Signature-Input or Signature header");
    }

    boolean hasBody = body.length > 0;
    if (hasBody) {
      String digestHeader = headers.get("content-digest");
      if (digestHeader == null || !contentDigestMatches(digestHeader, body)) {
        throw new SignatureException(
            "digest_mismatch", 400, "Content-Digest does not match the body");
      }
    }

    List<String> required = requiredComponents(!query.isEmpty(), headers, hasBody);
    // A profile's keys[] JWK Set may carry non-signature keys (RFC 7517 Sections 4.2, 4.3).
    Map<String, JsonNode> keysByKid = new HashMap<>();
    for (JsonNode key : keys) {
      if (sigCapable(key)) {
        JsonNode kid = key.get("kid");
        keysByKid.put(kid != null && kid.isString() ? kid.stringValue() : null, key);
      }
    }

    Function<String, String> resolve =
        name ->
            switch (name) {
              case "@method" -> method.toUpperCase(Locale.ROOT);
              case "@authority" -> normalizeAuthority(authority);
              case "@path" -> path.isEmpty() ? "/" : path; // RFC 9421 2.2.6: empty is "/"
              case "@query" -> "?" + query;
              default -> {
                String value = headers.get(name);
                // RFC 9421 Section 2.1: a covered field value is OWS-trimmed.
                yield value == null ? null : value.trim();
              }
            };

    SignatureException lastError =
        new SignatureException("signature_invalid", 401, "No valid signature found");
    for (Map.Entry<String, SignatureInputMember> entry : sigInput.entrySet()) {
      byte[] signature = sigs.get(entry.getKey());
      if (signature == null) {
        continue;
      }
      SignatureInputMember desc = entry.getValue();
      if (desc.params().containsKey("alg")) {
        lastError =
            new SignatureException(
                "signature_invalid", 401, "Signature-Input MUST NOT carry an 'alg' parameter");
        continue;
      }
      List<String> missing =
          required.stream().filter(c -> !desc.components().contains(c)).sorted().toList();
      if (!missing.isEmpty()) {
        lastError =
            new SignatureException(
                "signature_invalid",
                401,
                "Signature does not cover required components: " + String.join(", ", missing));
        continue;
      }
      String keyid = desc.params().get("keyid");
      JsonNode jwk = keysByKid.get(keyid);
      if (jwk == null) {
        lastError =
            new SignatureException(
                "key_not_found",
                401,
                "No published key with kid=" + (keyid == null ? "undefined" : "\"" + keyid + "\""));
        continue;
      }
      byte[] base = buildSignatureBase(desc.components(), desc.raw(), resolve);
      if (base == null) {
        lastError = new SignatureException("signature_invalid", 401, "Unresolvable signed component");
        continue;
      }
      try {
        verifyRawSignature(jwk, base, signature);
      } catch (SignatureException e) {
        lastError = e;
        continue;
      }
      return keyid == null ? "" : keyid;
    }
    throw lastError;
  }

  /**
   * Signs a UCP request and returns the headers to add: Content-Digest (when a body is present),
   * Content-Type (when absent), Signature-Input, and Signature covering the UCP required-component
   * set. Used by the webhook sender as this business's signer, and by the tests as the client
   * side of the loop.
   *
   * @param created the signature's {@code created} timestamp, or null for now
   * @param extraComponents additional header components to cover beyond the UCP floor; each is
   *     covered when the header is present on the request
   */
  public static Map<String, String> signRequest(
      PrivateKey privateKey,
      String kid,
      String method,
      String url,
      Map<String, String> headers,
      byte[] body,
      Long created,
      List<String> extraComponents) {
    URI target = URI.create(url);
    Map<String, String> additions = new LinkedHashMap<>();
    Map<String, String> merged = new HashMap<>();
    headers.forEach((k, v) -> merged.put(k.toLowerCase(Locale.ROOT), v));
    boolean hasBody = body.length > 0;
    if (hasBody) {
      String digest = contentDigest(body);
      additions.put("Content-Digest", digest);
      merged.put("content-digest", digest);
      // The signer must fix and cover Content-Type: a value the transport adds after signing
      // would not be part of the signature base.
      if (!merged.containsKey("content-type")) {
        merged.put("content-type", "application/json");
        additions.put("Content-Type", "application/json");
      }
    }

    String query = target.getRawQuery() == null ? "" : target.getRawQuery();
    List<String> components = new ArrayList<>(requiredComponents(!query.isEmpty(), merged, hasBody));
    for (String name : extraComponents) {
      if (!components.contains(name) && merged.containsKey(name)) {
        components.add(name);
      }
    }
    long createdAt = created != null ? created : Instant.now().getEpochSecond();
    String rawParams =
        components.stream().map(c -> "\"" + c + "\"").collect(Collectors.joining(" ", "(", ")"))
            + ";created="
            + createdAt
            + ";keyid=\""
            + kid
            + "\"";

    String authority =
        target.getPort() == -1 ? target.getHost() : target.getHost() + ":" + target.getPort();
    String rawPath = target.getRawPath() == null ? "" : target.getRawPath();
    Function<String, String> resolve =
        name ->
            switch (name) {
              case "@method" -> method.toUpperCase(Locale.ROOT);
              case "@authority" -> normalizeAuthority(authority);
              case "@path" -> rawPath.isEmpty() ? "/" : rawPath;
              case "@query" -> "?" + query;
              default -> merged.get(name);
            };

    byte[] base = buildSignatureBase(components, rawParams, resolve);
    if (base == null) {
      List<String> missing = components.stream().filter(c -> resolve.apply(c) == null).toList();
      throw new SignatureException(
          "signature_invalid", 401, "Cannot sign; missing components: " + String.join(", ", missing));
    }
    byte[] signature = rawSign(privateKey, base);
    additions.put("Signature-Input", "sig1=" + rawParams);
    additions.put("Signature", "sig1=:" + Base64.getEncoder().encodeToString(signature) + ":");
    return additions;
  }

  /** Signs a raw signature base, emitting fixed-width raw {@code r||s} for ECDSA. */
  static byte[] rawSign(PrivateKey privateKey, byte[] base) {
    String algorithm =
        privateKey instanceof EdECKey ? "Ed25519" : "SHA256withECDSAinP1363Format";
    try {
      Signature signer = Signature.getInstance(algorithm);
      signer.initSign(privateKey);
      signer.update(base);
      return signer.sign();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Signing failed", e);
    }
  }

  /**
   * Whether a JWK is usable for signature verification: a key marked {@code use: "enc"}, or
   * whose {@code key_ops} is present but omits {@code "verify"}, is skipped.
   */
  private static boolean sigCapable(JsonNode jwk) {
    JsonNode use = jwk.get("use");
    if (use != null && use.isString() && "enc".equals(use.stringValue())) {
      return false;
    }
    JsonNode keyOps = jwk.get("key_ops");
    if (keyOps == null) {
      return true;
    }
    for (JsonNode op : keyOps) {
      if (op.isString() && "verify".equals(op.stringValue())) {
        return true;
      }
    }
    return false;
  }

  private static boolean verify(String algorithm, PublicKey key, byte[] base, byte[] signature) {
    try {
      Signature verifier = Signature.getInstance(algorithm);
      verifier.initVerify(key);
      verifier.update(base);
      return verifier.verify(signature);
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      return false;
    }
  }

  private static byte[] sha256(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}
