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

package dev.ucp.samples.web;

import dev.ucp.samples.config.UcpProperties;
import dev.ucp.samples.error.ErrorEnvelope;
import dev.ucp.samples.error.UcpException;
import dev.ucp.samples.signing.HttpSignatures;
import dev.ucp.samples.signing.ProfileKeyResolver;
import dev.ucp.samples.signing.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Verifies an inbound request's RFC 9421 signature per the UCP spec on every business endpoint.
 * The signer's keys are discovered from the {@code UCP-Agent} header's profile URL.
 *
 * <ul>
 *   <li>With REQUIRE_SIGNATURES, a missing or invalid signature is rejected with the spec's error
 *       code (401 signature_missing / signature_invalid / key_not_found, 400 digest_mismatch /
 *       algorithm_unsupported, ...).
 *   <li>Otherwise (the default), signatures are still verified when present and the outcome is
 *       logged, but unsigned or invalid requests are allowed, keeping the sample interoperable
 *       with clients that do not sign yet.
 * </ul>
 *
 * <p>No profile fetch occurs unless a Signature-Input header is present. The discovery profile
 * is never verified: it is the public document a platform must read before it can sign anything.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class SignatureVerificationFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(SignatureVerificationFilter.class);
  private static final Pattern PROFILE = Pattern.compile("profile=\"([^\"]+)\"");
  private static final List<String> PROTECTED_PREFIXES =
      List.of("/checkout-sessions", "/orders", "/testing");

  private final UcpProperties properties;
  private final ProfileKeyResolver keyResolver;
  private final JsonMapper json;

  public SignatureVerificationFilter(
      UcpProperties properties, ProfileKeyResolver keyResolver, JsonMapper json) {
    this.properties = properties;
    this.keyResolver = keyResolver;
    this.json = json;
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    String path = request.getRequestURI();
    return PROTECTED_PREFIXES.stream().noneMatch(path::startsWith);
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    CachedBodyRequest cached =
        request instanceof CachedBodyRequest c ? c : new CachedBodyRequest(request);
    boolean enforcing = properties.isRequireSignatures();
    Map<String, String> headers = cached.lowercaseHeaders();

    if (!headers.containsKey("signature-input") || !headers.containsKey("signature")) {
      if (enforcing) {
        reject(
            response,
            new SignatureException("signature_missing", 401, "Request signature is required"));
        return;
      }
      log.debug("No request signature present; skipping verification");
      chain.doFilter(cached, response);
      return;
    }

    Matcher profile = PROFILE.matcher(headers.getOrDefault("ucp-agent", ""));
    if (!profile.find()) {
      SignatureException error =
          new SignatureException(
              "signature_invalid",
              401,
              "UCP-Agent profile URL is required to resolve the signing key");
      if (enforcing) {
        reject(response, error);
        return;
      }
      log.warn("Cannot verify signature: {}", error.getMessage());
      chain.doFilter(cached, response);
      return;
    }

    String profileUrl = profile.group(1);
    try {
      List<JsonNode> keys =
          keyResolver.fetchSigningKeys(profileUrl, properties.isAllowInsecureProfileUrls());
      String keyid =
          HttpSignatures.verifyRequest(
              cached.getMethod(),
              authority(cached),
              cached.getRequestURI(),
              cached.getQueryString() == null ? "" : cached.getQueryString(),
              headers,
              cached.body(),
              keys);
      log.info("RFC 9421 signature verified (keyid={}, profile={})", keyid, profileUrl);
    } catch (SignatureException e) {
      if (enforcing) {
        reject(response, e);
        return;
      }
      log.warn(
          "Request signature verification failed ({}: {}); "
              + "allowing because REQUIRE_SIGNATURES is not set",
          e.code(),
          e.getMessage());
    }
    chain.doFilter(cached, response);
  }

  /** The request authority as the client addressed it (the Host header). */
  private static String authority(HttpServletRequest request) {
    String host = request.getHeader("Host");
    if (host != null && !host.isBlank()) {
      return host;
    }
    return request.getServerName() + ":" + request.getServerPort();
  }

  /**
   * Answers with the UCP error envelope, like every other protocol-level rejection. Severity is
   * unrecoverable: no resource exists to act on when a request is turned away at this layer.
   */
  private void reject(HttpServletResponse response, SignatureException error) throws IOException {
    ErrorEnvelope.write(
        response,
        error.status(),
        ErrorEnvelope.of(error.code(), error.getMessage(), UcpException.Severity.UNRECOVERABLE),
        json);
  }
}
