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

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Resolves a signer's published signing keys from the UCP profile behind its {@code UCP-Agent}
 * header, with the spec's transport and SSRF rules and a short-lived cache.
 */
@Component
public class ProfileKeyResolver {

  /** Public keys resolved from a signer profile are cached for this long. */
  private static final Duration KEY_CACHE_TTL = Duration.ofMinutes(5);

  private record CachedKeys(long expiresAtMillis, List<JsonNode> keys) {}

  private final Map<String, CachedKeys> cache = new ConcurrentHashMap<>();
  private final JsonMapper json;
  private final HttpClient http;

  public ProfileKeyResolver(JsonMapper json) {
    this.json = json;
    // A redirect would hand key discovery to a URL the SSRF check never saw, so 3xx is treated
    // as unreachable rather than followed.
    this.http =
        HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();
  }

  /** Fetches (or serves from cache) the signing keys published by a signer profile. */
  public List<JsonNode> fetchSigningKeys(String profileUrl, boolean allowInsecure) {
    CachedKeys cached = cache.get(profileUrl);
    if (cached != null && cached.expiresAtMillis() > System.currentTimeMillis()) {
      return cached.keys();
    }

    assertProfileUrlAllowed(profileUrl, allowInsecure);
    HttpResponse<byte[]> response;
    try {
      HttpRequest request =
          HttpRequest.newBuilder(URI.create(profileUrl)).timeout(Duration.ofSeconds(5)).GET().build();
      response = http.send(request, HttpResponse.BodyHandlers.ofByteArray());
    } catch (IOException e) {
      throw new SignatureException("profile_unreachable", 424, "Profile fetch failed: " + e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new SignatureException("profile_unreachable", 424, "Profile fetch interrupted");
    }
    if (response.statusCode() >= 300) {
      throw new SignatureException(
          "profile_unreachable", 424, "Profile fetch returned HTTP " + response.statusCode());
    }
    JsonNode document;
    try {
      document = json.readTree(response.body());
    } catch (JacksonException e) {
      throw new SignatureException("profile_malformed", 422, "Profile is not valid JSON");
    }
    List<JsonNode> keys = extractKeys(document);
    if (keys.isEmpty()) {
      throw new SignatureException("profile_malformed", 422, "Profile publishes no signing keys");
    }
    cache.put(
        profileUrl, new CachedKeys(System.currentTimeMillis() + KEY_CACHE_TTL.toMillis(), keys));
    return keys;
  }

  /** Empties the resolved-key cache (used by tests). */
  public void clearCache() {
    cache.clear();
  }

  /**
   * Pulls the signing keys out of a profile document. At the UCP version this server declares
   * (2026-04-08), profile_schema.json declares {@code signing_keys} as a top-level sibling of
   * {@code ucp}, so the top level is read directly.
   *
   * <p>ucp#566 renames this field to a top-level {@code keys[]} for 2026-08-25 and later. When
   * the server's UCP version moves to that pin, this field name must move with it, together with
   * the publication side in {@code DiscoveryController}.
   */
  static List<JsonNode> extractKeys(JsonNode document) {
    List<JsonNode> keys = new ArrayList<>();
    if (document != null && document.isObject()) {
      JsonNode value = document.get("signing_keys");
      if (value != null && value.isArray()) {
        value.forEach(keys::add);
      }
    }
    return keys;
  }

  /**
   * Rejects profile URLs that violate the spec's transport and SSRF rules.
   *
   * <p>NOTE: like the other reference servers, this check is vulnerable to DNS rebinding (TOCTOU):
   * the IP is validated here but resolved again by the HTTP client. A production implementation
   * should resolve once, validate, and pin the connection.
   */
  static void assertProfileUrlAllowed(String url, boolean allowInsecure) {
    URI target;
    try {
      target = URI.create(url);
    } catch (IllegalArgumentException e) {
      throw new SignatureException(
          "invalid_profile_url", 400, "Profile URL is malformed: \"" + url + "\"");
    }
    String scheme = target.getScheme();
    if (!"https".equalsIgnoreCase(scheme)
        && !(allowInsecure && "http".equalsIgnoreCase(scheme))) {
      throw new SignatureException(
          "invalid_profile_url", 400, "Profile URL must be HTTPS: \"" + url + "\"");
    }
    if (target.getRawUserInfo() != null) {
      throw new SignatureException(
          "invalid_profile_url", 400, "Profile URL must not carry credentials");
    }
    String host = target.getHost();
    if (host != null && host.startsWith("[") && host.endsWith("]")) {
      host = host.substring(1, host.length() - 1);
    }
    if (host == null || host.isEmpty()) {
      throw new SignatureException(
          "invalid_profile_url", 400, "Profile URL has no host: \"" + url + "\"");
    }
    if (allowInsecure) {
      return;
    }
    InetAddress[] addresses;
    try {
      addresses = InetAddress.getAllByName(host);
    } catch (UnknownHostException e) {
      throw new SignatureException(
          "profile_unreachable", 424, "Cannot resolve profile host: " + host);
    }
    for (InetAddress address : addresses) {
      if (isDisallowedAddress(address)) {
        throw new SignatureException(
            "invalid_profile_url",
            400,
            "Profile URL resolves to a disallowed address: " + address.getHostAddress());
      }
    }
  }

  /**
   * Whether an address is special-use (loopback, private, link-local, reserved, multicast,
   * unspecified). IPv6 is vetted by allowing only current global unicast (2000::/3, minus
   * documentation space). The JDK already maps {@code ::ffff:a.b.c.d} to an IPv4 address.
   */
  static boolean isDisallowedAddress(InetAddress address) {
    byte[] b = address.getAddress();
    if (address instanceof Inet4Address) {
      int a0 = b[0] & 0xff;
      int a1 = b[1] & 0xff;
      int a2 = b[2] & 0xff;
      return a0 == 0 // "this network"
          || a0 == 10 // RFC 1918
          || a0 == 127 // loopback
          || (a0 == 100 && a1 >= 64 && a1 < 128) // shared address space
          || (a0 == 169 && a1 == 254) // link-local (incl. cloud metadata)
          || (a0 == 172 && a1 >= 16 && a1 < 32) // RFC 1918
          || (a0 == 192 && a1 == 0 && a2 == 0) // IETF protocol assignments
          || (a0 == 192 && a1 == 0 && a2 == 2) // documentation
          || (a0 == 192 && a1 == 168) // RFC 1918
          || (a0 == 198 && (a1 == 18 || a1 == 19)) // benchmarking
          || (a0 == 198 && a1 == 51 && a2 == 100) // documentation
          || (a0 == 203 && a1 == 0 && a2 == 113) // documentation
          || a0 >= 224; // multicast and reserved
    }
    if ((b[0] & 0xff) == 0x20 && (b[1] & 0xff) == 0x01 && (b[2] & 0xff) == 0x0d
        && (b[3] & 0xff) == 0xb8) {
      return true; // 2001:db8::/32 documentation
    }
    int firstGroup = ((b[0] & 0xff) << 8) | (b[1] & 0xff);
    return firstGroup < 0x2000 || firstGroup >= 0x4000;
  }
}
