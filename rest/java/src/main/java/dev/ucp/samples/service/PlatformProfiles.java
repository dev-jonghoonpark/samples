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

package dev.ucp.samples.service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Reads the platform's configuration (its order webhook URL) from the profile referenced by the
 * {@code UCP-Agent} header. Both {@code data:} URIs and http(s) URLs are supported, like the
 * Node.js server.
 */
@Component
public class PlatformProfiles {

  private static final Logger log = LoggerFactory.getLogger(PlatformProfiles.class);
  private static final Pattern PROFILE = Pattern.compile("profile=\"([^\"]+)\"");

  private final JsonMapper json;
  private final HttpClient http =
      HttpClient.newBuilder()
          .followRedirects(HttpClient.Redirect.NORMAL)
          .connectTimeout(Duration.ofSeconds(5))
          .build();

  public PlatformProfiles(JsonMapper json) {
    this.json = json;
  }

  /**
   * Resolves the platform config ({@code {"webhook_url": ...}}) from the {@code
   * dev.ucp.shopping.order} capability of the agent's profile, or empty if there is none.
   */
  public Optional<ObjectNode> platformConfig(String ucpAgentHeader) {
    if (ucpAgentHeader == null) {
      return Optional.empty();
    }
    Matcher match = PROFILE.matcher(ucpAgentHeader);
    if (!match.find()) {
      return Optional.empty();
    }
    String profileUri = match.group(1);
    try {
      JsonNode profile = null;
      if (profileUri.startsWith("data:")) {
        int comma = profileUri.indexOf(',');
        if (comma >= 0) {
          profile = json.readTree(Base64.getDecoder().decode(profileUri.substring(comma + 1)));
        }
      } else if (profileUri.startsWith("http")) {
        HttpResponse<byte[]> response =
            http.send(
                HttpRequest.newBuilder(URI.create(profileUri))
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build(),
                HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() >= 200 && response.statusCode() < 300) {
          profile = json.readTree(response.body());
        }
      }
      if (profile != null) {
        JsonNode webhookUrl =
            profile
                .path("ucp")
                .path("capabilities")
                .path("dev.ucp.shopping.order")
                .path(0)
                .path("config")
                .path("webhook_url");
        if (webhookUrl.isString() && !webhookUrl.stringValue().isEmpty()) {
          ObjectNode config = json.createObjectNode();
          config.put("webhook_url", webhookUrl.stringValue());
          return Optional.of(config);
        }
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    } catch (Exception e) {
      log.warn("Failed to fetch or parse agent profile {}: {}", profileUri, e.toString());
    }
    return Optional.empty();
  }
}
