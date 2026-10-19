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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

/** Order-event webhooks: delivered to the platform's webhook URL and signed as the business. */
class WebhookTest extends ServerTestSupport {

  @Test
  void orderEventsAreDeliveredSigned() throws Exception {
    try (StubServer platform = new StubServer()) {
      String profile =
          """
          {"ucp":{"capabilities":{"dev.ucp.shopping.order":[
            {"name":"dev.ucp.shopping.order","config":{"webhook_url":"%s/webhook"}}]}}}
          """
              .formatted(platform.url());
      String ucpAgent =
          "profile=\"data:application/json;base64,"
              + Base64.getEncoder().encodeToString(profile.getBytes(StandardCharsets.UTF_8))
              + "\"";

      Response created =
          send(
              "POST",
              "/checkout-sessions",
              json(
                  """
                  {'line_items':[{'item':{'id':'bouquet_tulips'},'quantity':2}],
                   'buyer':{'email':'john.doe@example.com'},
                   'fulfillment':{'methods':[{'type':'shipping','selected_destination_id':'addr_2',
                     'groups':[{'selected_option_id':'exp-ship-us'}]}]}}
                  """),
              Map.of("UCP-Agent", ucpAgent));
      assertThat(created.status()).isEqualTo(201);
      assertThat(created.body().path("platform").path("webhook_url").asString())
          .isEqualTo(platform.url() + "/webhook");
      String id = created.body().path("id").asString();

      Response completed =
          post(
              "/checkout-sessions/" + id + "/complete",
              json(
                  """
                  {'payment':{'instruments':[{'id':'pi_1','handler_id':'google_pay','type':'card',
                    'credential':{'type':'PAYMENT_GATEWAY','token':'tok'}}]}}
                  """));
      assertThat(completed.status()).isEqualTo(200);
      String orderId = completed.body().path("order").path("id").asString();

      StubServer.Received placed = platform.await("POST", "/webhook");
      assertThat(placed.headers().get("x-event-type")).isEqualTo("order_placed");
      JsonNode order = JSON.readTree(placed.body());
      assertThat(order.path("id").asString()).isEqualTo(orderId);
      assertSignedByMerchant(platform, placed);

      Response shipped =
          send(
              "POST",
              "/testing/simulate-shipping/" + orderId,
              null,
              Map.of("Simulation-Secret", "super-secret-sim-key"));
      assertThat(shipped.status()).isEqualTo(200);

      StubServer.Received shippedEvent = platform.await("POST", "/webhook");
      assertThat(shippedEvent.headers().get("x-event-type")).isEqualTo("order_shipped");
      assertThat(
              JSON.readTree(shippedEvent.body())
                  .path("fulfillment")
                  .path("events")
                  .path(0)
                  .path("type")
                  .asString())
          .isEqualTo("shipped");
      assertSignedByMerchant(platform, shippedEvent);
      assertThat(shippedEvent.headers().get("webhook-id"))
          .isNotEqualTo(placed.headers().get("webhook-id"));
    }
  }

  /** Verifies a delivery against the key the merchant publishes in its discovery profile. */
  private void assertSignedByMerchant(StubServer platform, StubServer.Received delivery) {
    Map<String, String> headers = delivery.headers();
    assertThat(headers.get("ucp-agent")).isEqualTo("profile=\"" + baseUrl() + "/.well-known/ucp\"");
    assertThat(headers.get("idempotency-key")).isEqualTo(headers.get("webhook-id"));
    assertThat(headers.get("signature-input"))
        .contains("\"webhook-id\"", "\"webhook-timestamp\"", "\"x-event-type\"");

    List<JsonNode> keys = new ArrayList<>();
    get("/.well-known/ucp").body().path("signing_keys").forEach(keys::add);
    String keyid =
        HttpSignatures.verifyRequest(
            "POST",
            "127.0.0.1:" + platform.port(),
            "/webhook",
            "",
            headers,
            delivery.body(),
            keys);
    assertThat(keyid).isEqualTo(keys.get(0).path("kid").asString());
  }
}
