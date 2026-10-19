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

import dev.ucp.samples.config.UcpProperties;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

/** The {@code /.well-known/ucp} merchant profile. */
class DiscoveryTest extends ServerTestSupport {

  @Test
  void profileDeclaresVersionServicesAndCapabilities() {
    JsonNode ucp = get("/.well-known/ucp").body().path("ucp");

    assertThat(ucp.path("version").asString()).isEqualTo(UcpProperties.UCP_VERSION);
    assertThat(ucp.path("services").path("dev.ucp.shopping").path(0).path("transport").asString())
        .isEqualTo("rest");
    assertThat(ucp.path("capabilities").propertyNames())
        .containsExactlyInAnyOrder(
            "dev.ucp.shopping.checkout",
            "dev.ucp.shopping.order",
            "dev.ucp.shopping.discount",
            "dev.ucp.shopping.fulfillment",
            "dev.ucp.shopping.buyer_consent");
    // Every capability's schema lives at the server's own version.
    for (String name : ucp.path("capabilities").propertyNames()) {
      JsonNode capability = ucp.path("capabilities").path(name).path(0);
      assertThat(capability.path("version").asString()).isEqualTo(UcpProperties.UCP_VERSION);
      assertThat(capability.path("schema").asString())
          .startsWith("https://ucp.dev/" + UcpProperties.UCP_VERSION + "/schemas/shopping/");
    }
    assertThat(ucp.path("payment_handlers").path("dev.ucp.mock_payment").path(0).path("id").asString())
        .isEqualTo("mock_payment_handler");
  }

  @Test
  void restEndpointIsDerivedFromTheRequestOrigin() {
    JsonNode service =
        get("/.well-known/ucp").body().path("ucp").path("services").path("dev.ucp.shopping").path(0);

    assertThat(service.path("endpoint").asString()).isEqualTo(baseUrl());
  }

  @Test
  void signingKeysArePublishedAtTheTopLevel() {
    JsonNode profile = get("/.well-known/ucp").body();

    JsonNode key = profile.path("signing_keys").path(0);
    assertThat(key.path("kty").asString()).isEqualTo("EC");
    assertThat(key.path("crv").asString()).isEqualTo("P-256");
    assertThat(key.path("alg").asString()).isEqualTo("ES256");
    assertThat(key.path("kid").asString()).isNotEmpty();
    assertThat(profile.path("ucp").has("keys")).isFalse();
  }

  @Test
  void profileIsPubliclyCacheable() {
    String cacheControl = get("/.well-known/ucp").header("Cache-Control");

    List<String> directives =
        Arrays.stream(cacheControl.split(",")).map(String::trim).toList();
    assertThat(directives).contains("public").doesNotContain("private", "no-store", "no-cache");
    int maxAge =
        directives.stream()
            .filter(d -> d.startsWith("max-age="))
            .map(d -> Integer.parseInt(d.substring("max-age=".length())))
            .findFirst()
            .orElseThrow();
    assertThat(maxAge).isGreaterThanOrEqualTo(60);
  }

  @Test
  void profileIsNeverSignatureGated() {
    properties.setRequireSignatures(true);

    assertThat(send("GET", "/.well-known/ucp", null, Map.of()).status()).isEqualTo(200);
  }
}
