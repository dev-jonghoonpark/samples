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

import dev.ucp.samples.data.TransactionStore;
import dev.ucp.samples.signing.HttpSignatures;
import dev.ucp.samples.signing.WebhookSigningKey;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Delivers signed order-event webhooks to the platform.
 *
 * <p>Per the UCP REST OpenAPI ({@code webhooks.orderEvent}) the request body is the order object
 * itself; the event type travels in the {@code X-Event-Type} header. Every delivery is signed as
 * this business (order.md, Webhook Signature Verification).
 */
@Component
public class WebhookNotifier {

  private static final Logger log = LoggerFactory.getLogger(WebhookNotifier.class);
  private static final int MAX_ATTEMPTS = 3;

  private final TransactionStore transactions;
  private final WebhookSigningKey signingKey;
  private final JsonMapper json;
  // A redirect transparently followed would re-POST to a URL the signature does not cover, so
  // 3xx surfaces as a response instead.
  private final HttpClient http =
      HttpClient.newBuilder()
          .followRedirects(HttpClient.Redirect.NEVER)
          .connectTimeout(Duration.ofSeconds(5))
          .build();

  public WebhookNotifier(
      TransactionStore transactions, WebhookSigningKey signingKey, JsonMapper json) {
    this.transactions = transactions;
    this.signingKey = signingKey;
    this.json = json;
  }

  /**
   * Notifies the checkout's platform webhook of an order event. Nothing is sent when the
   * checkout has no webhook or no order to deliver, since the body must always be a valid order.
   * Delivery failures are logged and never propagate into the order flow.
   */
  public void notify(ObjectNode checkout, String eventType, String baseUrl) {
    JsonNode webhookNode = checkout.path("platform").path("webhook_url");
    if (!webhookNode.isString()) {
      return;
    }
    String webhookUrl = webhookNode.stringValue();

    Optional<ObjectNode> order = Optional.empty();
    JsonNode orderRef = checkout.path("order").path("id");
    if (orderRef.isString()) {
      order = transactions.getOrder(orderRef.stringValue());
    }
    if (order.isEmpty()) {
      log.warn(
          "Skipping {} webhook for checkout {}: no order to deliver",
          eventType,
          checkout.path("id").asString());
      return;
    }

    // Serialize exactly once: the signed Content-Digest and the wire body must be the same bytes.
    byte[] body = json.writeValueAsBytes(order.get());
    String webhookId = UUID.randomUUID().toString();
    Map<String, String> headers = new LinkedHashMap<>();
    headers.put("Content-Type", "application/json");
    headers.put("X-Event-Type", eventType);
    headers.put("Webhook-Id", webhookId);
    headers.put("Webhook-Timestamp", Long.toString(Instant.now().getEpochSecond()));
    // A webhook POST is state-changing, so the signed-component table requires idempotency-key.
    // The event id doubles as the key: retries carry the same value, letting the platform
    // deduplicate redelivered events.
    headers.put("Idempotency-Key", webhookId);
    // Sign AS this business: the profile URL platforms fetch our signing_keys[] from.
    headers.put("UCP-Agent", "profile=\"" + baseUrl + "/.well-known/ucp\"");

    try {
      for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        // Re-sign per attempt so the signature's created timestamp reflects each send time.
        Map<String, String> additions =
            HttpSignatures.signRequest(
                signingKey.privateKey(),
                signingKey.kid(),
                "POST",
                webhookUrl,
                headers,
                body,
                null,
                List.of("webhook-id", "webhook-timestamp", "x-event-type"));
        HttpRequest.Builder request =
            HttpRequest.newBuilder(URI.create(webhookUrl))
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        headers.forEach(request::header);
        additions.forEach(request::setHeader);
        try {
          HttpResponse<Void> response =
              http.send(request.build(), HttpResponse.BodyHandlers.discarding());
          int status = response.statusCode();
          if (status >= 200 && status < 300) {
            return;
          }
          if (status < 500) {
            log.error("Webhook at {} rejected delivery with status {}", webhookUrl, status);
            return;
          }
        } catch (IOException e) {
          if (attempt == MAX_ATTEMPTS) {
            log.error("Failed to notify webhook at {}", webhookUrl, e);
            return;
          }
        }
        if (attempt < MAX_ATTEMPTS) {
          Thread.sleep(100L << (attempt - 1));
        }
      }
      log.error("Failed to notify webhook at {} after {} attempts", webhookUrl, MAX_ATTEMPTS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    } catch (RuntimeException e) {
      // A URL the signer cannot handle degrades to a logged failure, like an undeliverable
      // receiver.
      log.error("Failed to notify webhook at {}", webhookUrl, e);
    }
  }
}
