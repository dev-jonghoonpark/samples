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

package dev.ucp.samples.api;

import static dev.ucp.samples.config.UcpProperties.UCP_VERSION;

import dev.ucp.samples.signing.WebhookSigningKey;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * UCP discovery: {@code /.well-known/ucp} tells platforms which protocol version, services,
 * capabilities, and payment handlers this merchant supports, and publishes the key its webhooks
 * are signed with.
 */
@RestController
public class DiscoveryController {

  /**
   * overview.md (Discovery) requires a {@code Cache-Control} header with {@code public} and a
   * {@code max-age} of at least 60 seconds, and forbids private, no-store, and no-cache.
   */
  private static final String PROFILE_CACHE_CONTROL = "public, max-age=3600";

  private static final String BASE = "https://ucp.dev/" + UCP_VERSION;

  private final WebhookSigningKey signingKey;
  private final JsonMapper json;

  public DiscoveryController(WebhookSigningKey signingKey, JsonMapper json) {
    this.signingKey = signingKey;
    this.json = json;
  }

  @GetMapping("/.well-known/ucp")
  public ResponseEntity<JsonNode> merchantProfile(HttpServletRequest request) {
    ObjectNode profile = json.createObjectNode();

    ObjectNode ucp = profile.putObject("ucp");
    ucp.put("version", UCP_VERSION);

    ObjectNode shopping = ucp.putObject("services").putArray("dev.ucp.shopping").addObject();
    shopping.put("version", UCP_VERSION);
    shopping.put("spec", BASE + "/specification/overview");
    shopping.put("transport", "rest");
    shopping.put("schema", BASE + "/services/shopping/rest.openapi.json");
    shopping.put("endpoint", Origins.of(request));

    ObjectNode capabilities = ucp.putObject("capabilities");
    capability(capabilities, "checkout", "checkout", null);
    capability(capabilities, "order", "order", null);
    capability(capabilities, "discount", "discount", "dev.ucp.shopping.checkout");
    capability(capabilities, "fulfillment", "fulfillment", "dev.ucp.shopping.checkout");
    capability(capabilities, "buyer_consent", "buyer-consent", "dev.ucp.shopping.checkout");

    ObjectNode handlers = ucp.putObject("payment_handlers");
    ObjectNode shopPay =
        handler(
            handlers,
            "com.shopify.shop_pay",
            "shop_pay",
            UCP_VERSION,
            "https://shopify.dev/ucp/handlers/shop_pay",
            "https://shopify.dev/ucp/handlers/shop_pay/config.json",
            List.of("https://shopify.dev/ucp/handlers/shop_pay/instrument.json"));
    shopPay.putObject("config").put("shop_id", "test-shop-id");
    ObjectNode googlePay =
        handler(
            handlers,
            "google.pay",
            "google_pay",
            "1.0",
            "https://example.com/spec",
            "https://example.com/schema",
            List.of());
    googlePay.putObject("config");
    ObjectNode mock =
        handler(
            handlers,
            "dev.ucp.mock_payment",
            "mock_payment_handler",
            "1.0",
            BASE + "/specification/mock",
            BASE + "/schemas/mock.json",
            List.of(BASE + "/schemas/shopping/types/card_payment_instrument.json"));
    mock.putObject("config").putArray("supported_tokens").add("success_token").add("fail_token");

    // Publish the webhook-signing public key so platforms can verify our order-event deliveries
    // (order.md, Webhook Signature Verification). At the 2026-04-08 pin, profile_schema.json
    // declares signing_keys as a top-level sibling of ucp. ucp#566 renames it to a top-level
    // keys[] for 2026-08-25; this must move together with ProfileKeyResolver.extractKeys().
    profile.putArray("signing_keys").add(signingKey.publicJwk());

    ArrayNode flatHandlers = profile.putObject("payment").putArray("handlers");
    flatHandlers.add(shopPay.deepCopy()).add(googlePay.deepCopy()).add(mock.deepCopy());

    return ResponseEntity.ok().header("Cache-Control", PROFILE_CACHE_CONTROL).body(profile);
  }

  private static void capability(
      ObjectNode capabilities, String name, String specPage, String extendsCapability) {
    ObjectNode capability =
        capabilities.putArray("dev.ucp.shopping." + name).addObject();
    capability.put("version", UCP_VERSION);
    capability.put("spec", BASE + "/specification/" + specPage);
    capability.put("schema", BASE + "/schemas/shopping/" + name + ".json");
    if (extendsCapability != null) {
      capability.put("extends", extendsCapability);
    }
  }

  private static ObjectNode handler(
      ObjectNode handlers,
      String name,
      String id,
      String version,
      String spec,
      String configSchema,
      List<String> instrumentSchemas) {
    ObjectNode handler = handlers.putArray(name).addObject();
    handler.put("id", id);
    handler.put("name", name);
    handler.put("version", version);
    handler.put("spec", spec);
    handler.put("config_schema", configSchema);
    ArrayNode schemas = handler.putArray("instrument_schemas");
    instrumentSchemas.forEach(schemas::add);
    return handler;
  }
}
