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

import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/** The checkout lifecycle end to end over HTTP: create, update, complete, cancel, ship. */
class CheckoutFlowTest extends ServerTestSupport {

  private static final String KNOWN_BUYER = "{'email':'john.doe@example.com'}";

  private static ObjectNode createBody() {
    return json("{'line_items':[{'item':{'id':'bouquet_roses'},'quantity':1}],'payment':{}}");
  }

  private static ObjectNode payment(String token) {
    return json(
        """
        {'payment':{'instruments':[{'id':'pi_1','handler_id':'mock_payment_handler',
          'type':'card','brand':'visa','last_digits':'4242',
          'credential':{'type':'network_token','token':'%s'}}]}}
        """
            .formatted(token));
  }

  /** Creates a checkout with a known-customer destination, then selects the quoted option. */
  private String createReadyToComplete() {
    Response created =
        post(
            "/checkout-sessions",
            json(
                """
                {'line_items':[{'item':{'id':'bouquet_roses'},'quantity':1}],
                 'buyer':%s,
                 'fulfillment':{'methods':[{'type':'shipping','selected_destination_id':'addr_1'}]}}
                """
                    .formatted(KNOWN_BUYER)));
    assertThat(created.status()).isEqualTo(201);
    String id = created.body().path("id").asString();
    JsonNode group = created.body().path("fulfillment").path("methods").path(0).path("groups").path(0);
    String optionId = group.path("options").path(0).path("id").asString();

    Response updated =
        put(
            "/checkout-sessions/" + id,
            json(
                """
                {'line_items':[{'id':'line_1','item':{'id':'bouquet_roses'},'quantity':1}],
                 'buyer':%s,
                 'fulfillment':{'methods':[{'type':'shipping','selected_destination_id':'addr_1',
                   'groups':[{'selected_option_id':'%s'}]}]}}
                """
                    .formatted(KNOWN_BUYER, optionId)));
    assertThat(updated.status()).isEqualTo(200);
    return id;
  }

  @Test
  void createReturns201WithAnIncompleteCheckout() {
    Response response = post("/checkout-sessions", createBody());

    assertThat(response.status()).isEqualTo(201);
    JsonNode checkout = response.body();
    assertThat(checkout.path("id").asString()).isNotEmpty();
    assertThat(checkout.path("status").asString()).isEqualTo("incomplete");
    assertThat(checkout.path("currency").asString()).isEqualTo("USD");
    assertThat(checkout.path("line_items").path(0).path("item").path("price").asLong())
        .isEqualTo(3500);
    assertThat(checkout.path("ucp").path("payment_handlers").isObject()).isTrue();
  }

  @Test
  void createdCheckoutIsRetrievable() {
    String id = post("/checkout-sessions", createBody()).body().path("id").asString();

    Response response = get("/checkout-sessions/" + id);

    assertThat(response.status()).isEqualTo(200);
    assertThat(response.body().path("id").asString()).isEqualTo(id);
    assertThat(response.body().path("ucp").path("payment_handlers").isObject()).isTrue();
  }

  @Test
  void createDoesNotAdoptBusinessOwnedMembers() {
    ObjectNode body = createBody();
    body.put("continue_url", "https://evil.example/continue");
    body.put("expires_at", "2000-01-01T00:00:00Z");
    body.putArray("messages").addObject().put("type", "info");
    body.putObject("order").put("id", "ord_forged");

    JsonNode checkout = post("/checkout-sessions", body).body();

    assertThat(checkout.has("continue_url")).isFalse();
    assertThat(checkout.has("expires_at")).isFalse();
    assertThat(checkout.has("messages")).isFalse();
    assertThat(checkout.has("order")).isFalse();
  }

  @Test
  void selectingAFulfillmentOptionAddsItsCostToTheReceipt() {
    String id = createReadyToComplete();

    JsonNode checkout = get("/checkout-sessions/" + id).body();

    JsonNode group = checkout.path("fulfillment").path("methods").path(0).path("groups").path(0);
    assertThat(group.path("selected_option_id").asString()).isEqualTo("std-ship");
    // Roses ship free.
    assertThat(group.path("options").path(0).path("title").asString())
        .isEqualTo("Free Standard Shipping");
    assertThat(totalOfType(checkout, "fulfillment")).isZero();
    assertThat(totalOfType(checkout, "total")).isEqualTo(3500);
  }

  @Test
  void aMethodWithoutQuotableOptionsStillGetsOneGroup() {
    JsonNode checkout =
        post(
                "/checkout-sessions",
                json(
                    """
                    {'line_items':[{'item':{'id':'bouquet_roses'},'quantity':1}],
                     'fulfillment':{'methods':[{'type':'pickup'}]}}
                    """))
            .body();

    JsonNode groups = checkout.path("fulfillment").path("methods").path(0).path("groups");
    assertThat(groups.size()).isEqualTo(1);
    assertThat(groups.path(0).path("line_item_ids").path(0).asString()).isEqualTo("line_1");
    assertThat(groups.path(0).path("options").size()).isZero();
  }

  @Test
  void discountsAreAppliedCaseInsensitivelyAndReconcile() {
    ObjectNode body = createBody();
    body.putObject("discounts").putArray("codes").add("welcome20");

    JsonNode checkout = post("/checkout-sessions", body).body();

    JsonNode applied = checkout.path("discounts").path("applied").path(0);
    assertThat(applied.path("code").asString()).isEqualTo("welcome20");
    assertThat(applied.path("amount").asLong()).isEqualTo(700);
    assertThat(applied.path("allocations").path(0).path("amount").asLong()).isEqualTo(700);
    assertThat(totalOfType(checkout, "discount")).isEqualTo(-700);
    assertThat(totalOfType(checkout, "total")).isEqualTo(2800);
  }

  @Test
  void consentDefaultsAreFilledIn() {
    ObjectNode body = createBody();
    body.set("buyer", json("{'consent':{'marketing':{'granted':true}}}"));

    JsonNode consent = post("/checkout-sessions", body).body().path("buyer").path("consent");

    assertThat(consent.path("marketing").path("description").asString())
        .isEqualTo("Consent for marketing");
    assertThat(consent.path("marketing").path("source").asString()).isEqualTo("platform");
  }

  @Test
  void completeCreatesAnOrder() {
    String id = createReadyToComplete();

    Response completed = post("/checkout-sessions/" + id + "/complete", payment("success_token"));

    assertThat(completed.status()).isEqualTo(200);
    assertThat(completed.body().path("status").asString()).isEqualTo("completed");
    String orderId = completed.body().path("order").path("id").asString();
    assertThat(orderId).startsWith("ord_");

    Response order = get("/orders/" + orderId);
    assertThat(order.status()).isEqualTo(200);
    assertThat(order.body().path("checkout_id").asString()).isEqualTo(id);
    assertThat(order.body().path("line_items").path(0).path("quantity").path("total").asLong())
        .isEqualTo(1);
    JsonNode expectation = order.body().path("fulfillment").path("expectations").path(0);
    assertThat(expectation.path("method_type").asString()).isEqualTo("shipping");
    assertThat(expectation.path("destination").path("postal_code").asString()).isEqualTo("62704");
  }

  @Test
  void completingTwiceIsAConflict() {
    String id = createReadyToComplete();
    post("/checkout-sessions/" + id + "/complete", payment("success_token"));

    Response again = post("/checkout-sessions/" + id + "/complete", payment("success_token"));

    assertError(again, 409, "CHECKOUT_NOT_MODIFIABLE");
  }

  @Test
  void declinedPaymentsSurfaceTheirStatus() {
    String id = createReadyToComplete();

    assertError(
        post("/checkout-sessions/" + id + "/complete", payment("fail_token")),
        402,
        "INSUFFICIENT_FUNDS");
    assertError(
        post("/checkout-sessions/" + id + "/complete", payment("fraud_token")),
        403,
        "FRAUD_DETECTED");
    Response failed = post("/checkout-sessions/" + id + "/complete", payment("fail_token"));
    assertThat(failed.body().path("messages").path(0).path("severity").asString())
        .isEqualTo("requires_buyer_input");
  }

  @Test
  void completionWithoutFulfillmentIsRejected() {
    String id = post("/checkout-sessions", createBody()).body().path("id").asString();

    assertError(
        post("/checkout-sessions/" + id + "/complete", payment("success_token")),
        400,
        "INVALID_REQUEST");
  }

  @Test
  void anEmptyMethodsArrayBlocksCompletion() {
    ObjectNode body = createBody();
    body.putObject("fulfillment").putArray("methods");
    String id = post("/checkout-sessions", body).body().path("id").asString();

    assertError(
        post("/checkout-sessions/" + id + "/complete", payment("success_token")),
        400,
        "INVALID_REQUEST");
  }

  @Test
  void cancelMovesTheCheckoutToCanceled() {
    String id = post("/checkout-sessions", createBody()).body().path("id").asString();

    Response canceled = post("/checkout-sessions/" + id + "/cancel", null);

    assertThat(canceled.status()).isEqualTo(200);
    assertThat(canceled.body().path("status").asString()).isEqualTo("canceled");
    assertError(put("/checkout-sessions/" + id, createBody()), 409, "CHECKOUT_NOT_MODIFIABLE");
    assertError(post("/checkout-sessions/" + id + "/cancel", null), 409, "CHECKOUT_NOT_MODIFIABLE");
  }

  @Test
  void aCanceledCheckoutCannotBeCompleted() {
    String id = createReadyToComplete();
    post("/checkout-sessions/" + id + "/cancel", null);

    assertError(
        post("/checkout-sessions/" + id + "/complete", payment("success_token")),
        409,
        "CHECKOUT_NOT_MODIFIABLE");
  }

  @Test
  void shippingAnOrderRecordsAFulfillmentEvent() {
    String id = createReadyToComplete();
    String orderId =
        post("/checkout-sessions/" + id + "/complete", payment("success_token"))
            .body()
            .path("order")
            .path("id")
            .asString();

    Response forbidden =
        send("POST", "/testing/simulate-shipping/" + orderId, null, Map.of());
    assertThat(forbidden.status()).isEqualTo(403);

    Response shipped =
        send(
            "POST",
            "/testing/simulate-shipping/" + orderId,
            null,
            Map.of("Simulation-Secret", "super-secret-sim-key"));
    assertThat(shipped.status()).isEqualTo(200);

    JsonNode event = get("/orders/" + orderId).body().path("fulfillment").path("events").path(0);
    assertThat(event.path("type").asString()).isEqualTo("shipped");
    assertThat(event.path("line_items").path(0).path("id").asString()).isEqualTo("line_1");
    assertThat(event.path("line_items").path(0).path("quantity").asLong()).isEqualTo(1);
  }

  @Test
  void anOrderCanBeReplaced() {
    String id = createReadyToComplete();
    String orderId =
        post("/checkout-sessions/" + id + "/complete", payment("success_token"))
            .body()
            .path("order")
            .path("id")
            .asString();
    ObjectNode order = (ObjectNode) get("/orders/" + orderId).body();
    order.put("id", "ignored");
    order.put("permalink_url", "https://shop.example/orders/1");

    Response replaced = put("/orders/" + orderId, order);

    assertThat(replaced.status()).isEqualTo(200);
    assertThat(replaced.body().path("id").asString()).isEqualTo(orderId);
    assertThat(get("/orders/" + orderId).body().path("permalink_url").asString())
        .isEqualTo("https://shop.example/orders/1");
  }

  // --- Idempotency -----------------------------------------------------------------------------

  @Test
  void sameKeyAndBodyReplaysTheFirstResponse() {
    String key = UUID.randomUUID().toString();
    Map<String, String> headers = Map.of("Idempotency-Key", key);
    Response first = send("POST", "/checkout-sessions", createBody(), headers);
    Response second = send("POST", "/checkout-sessions", createBody(), headers);

    assertThat(second.status()).isEqualTo(201);
    assertThat(second.body().path("id").asString()).isEqualTo(first.body().path("id").asString());
    assertThat(second.body().path("ucp").path("payment_handlers").isObject()).isTrue();
  }

  @Test
  void sameKeyWithADifferentBodyIsAConflict() {
    Map<String, String> headers = Map.of("Idempotency-Key", UUID.randomUUID().toString());
    send("POST", "/checkout-sessions", createBody(), headers);
    ObjectNode different = createBody();
    ((ObjectNode) different.path("line_items").path(0)).put("quantity", 2);

    assertError(
        send("POST", "/checkout-sessions", different, headers), 409, "IDEMPOTENCY_CONFLICT");
  }

  @Test
  void memberOrderDoesNotChangeTheFingerprint() {
    Map<String, String> headers = Map.of("Idempotency-Key", UUID.randomUUID().toString());
    Response first =
        send(
            "POST",
            "/checkout-sessions",
            json("{'line_items':[{'item':{'id':'bouquet_roses'},'quantity':1}],'payment':{}}"),
            headers);
    Response second =
        send(
            "POST",
            "/checkout-sessions",
            json("{'payment':{},'line_items':[{'quantity':1,'item':{'id':'bouquet_roses'}}]}"),
            headers);

    assertThat(second.body().path("id").asString()).isEqualTo(first.body().path("id").asString());
  }

  @Test
  void noKeyCreatesIndependentCheckouts() {
    String a = post("/checkout-sessions", createBody()).body().path("id").asString();
    String b = post("/checkout-sessions", createBody()).body().path("id").asString();

    assertThat(a).isNotEqualTo(b);
  }

  @Test
  void aKeyIsScopedToTheCheckout() {
    String a = post("/checkout-sessions", createBody()).body().path("id").asString();
    String b = post("/checkout-sessions", createBody()).body().path("id").asString();
    Map<String, String> headers = Map.of("Idempotency-Key", UUID.randomUUID().toString());

    assertThat(send("POST", "/checkout-sessions/" + a + "/cancel", null, headers).status())
        .isEqualTo(200);
    assertError(
        send("POST", "/checkout-sessions/" + b + "/cancel", null, headers),
        409,
        "IDEMPOTENCY_CONFLICT");
  }

  // --- Errors and validation -------------------------------------------------------------------

  @Test
  void unknownResourcesAre404() {
    assertError(get("/checkout-sessions/nope"), 404, "RESOURCE_NOT_FOUND");
    assertError(get("/orders/nope"), 404, "RESOURCE_NOT_FOUND");
    assertError(
        put(
            "/orders/nope",
            json(
                """
                {'ucp':{},'id':'nope','checkout_id':'c','permalink_url':'u',
                 'line_items':[],'fulfillment':{},'totals':[]}
                """)),
        404,
        "RESOURCE_NOT_FOUND");
    assertError(
        send(
            "POST",
            "/testing/simulate-shipping/nope",
            null,
            Map.of("Simulation-Secret", "super-secret-sim-key")),
        404,
        "RESOURCE_NOT_FOUND");
  }

  @Test
  void anUnknownProductIsAnInvalidRequest() {
    assertError(
        post(
            "/checkout-sessions",
            json("{'line_items':[{'item':{'id':'no_such_flower'},'quantity':1}]}")),
        400,
        "INVALID_REQUEST");
  }

  @Test
  void insufficientStockIsOutOfStock() {
    // gardenias are seeded with zero stock.
    assertError(
        post(
            "/checkout-sessions",
            json("{'line_items':[{'item':{'id':'gardenias'},'quantity':1}]}")),
        400,
        "OUT_OF_STOCK");
  }

  @Test
  void quantitiesBelowOneOrFractionalAreRejectedAtValidation() {
    for (String quantity : new String[] {"0", "-1", "1.5"}) {
      Response response =
          post(
              "/checkout-sessions",
              json(
                  "{'line_items':[{'item':{'id':'bouquet_roses'},'quantity':" + quantity + "}]}"));
      assertError(response, 422, "INVALID_REQUEST");
      assertThat(response.body().path("messages").path(0).path("content").asString())
          .contains("line_items[0].quantity");
    }
  }

  @Test
  void aMissingLineItemsArrayIsAValidationError() {
    assertError(post("/checkout-sessions", json("{'currency':'USD'}")), 422, "INVALID_REQUEST");
  }

  @Test
  void malformedJsonIsAnInvalidRequest() {
    assertError(
        sendRaw(
            "POST",
            "/checkout-sessions",
            "{not json".getBytes(),
            Map.of("Content-Type", "application/json")),
        400,
        "INVALID_REQUEST");
  }

  @Test
  void aNewerProtocolVersionIsUnsupported() {
    Response response =
        send(
            "POST",
            "/checkout-sessions",
            createBody(),
            Map.of("UCP-Agent", "profile=\"https://agent.example/p\"; version=\"2099-01-01\""));

    assertError(response, 422, "VERSION_UNSUPPORTED");
  }

  private static long totalOfType(JsonNode checkout, String type) {
    for (JsonNode total : checkout.path("totals")) {
      if (type.equals(total.path("type").asString())) {
        return total.path("amount").asLong();
      }
    }
    throw new AssertionError("no " + type + " total in " + checkout.path("totals"));
  }
}
