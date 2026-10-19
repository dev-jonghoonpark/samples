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

import dev.ucp.samples.config.UcpProperties;
import dev.ucp.samples.data.InventoryStore;
import dev.ucp.samples.data.ProductStore;
import dev.ucp.samples.data.ProductStore.Product;
import dev.ucp.samples.data.TransactionStore;
import dev.ucp.samples.data.TransactionStore.IdempotencyRecord;
import dev.ucp.samples.error.UcpException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * Checkout session management: create, read, update, complete (payment, inventory reservation,
 * order creation, webhook), cancel, and the simulated shipping of an order.
 *
 * <p>The business logic mirrors the Node.js server ({@code src/api/checkout.ts}) step for step.
 * Checkouts are handled as JSON documents so that fields this server does not model (extensions,
 * newer protocol members) round-trip untouched.
 */
@Service
public class CheckoutService {

  /** A response status and body. */
  public record Result(int status, JsonNode body) {}

  private static final String KNOWN_CUSTOMER_EMAIL = "john.doe@example.com";
  private static final String DISCOUNT_ALLOCATION_PATH = "$.totals[?(@.type=='subtotal')]";

  private final ProductStore products;
  private final InventoryStore inventory;
  private final TransactionStore transactions;
  private final PlatformProfiles platformProfiles;
  private final WebhookNotifier webhooks;
  private final JsonMapper json;

  public CheckoutService(
      ProductStore products,
      InventoryStore inventory,
      TransactionStore transactions,
      PlatformProfiles platformProfiles,
      WebhookNotifier webhooks,
      JsonMapper json) {
    this.products = products;
    this.inventory = inventory;
    this.transactions = transactions;
    this.platformProfiles = platformProfiles;
    this.webhooks = webhooks;
    this.json = json;
  }

  // ---------------------------------------------------------------------------------------------
  // Endpoints
  // ---------------------------------------------------------------------------------------------

  /** POST /checkout-sessions. */
  public Result createCheckout(ObjectNode request, String idempotencyKey, String ucpAgent) {
    String requestHash = null;
    if (idempotencyKey != null) {
      requestHash = computeHash("create_checkout", request, null);
      Optional<Result> replay = replay(idempotencyKey, requestHash);
      if (replay.isPresent()) {
        return replay.get();
      }
    }

    String checkoutId = UUID.randomUUID().toString();
    transactions.logRequest("POST", "/checkout-sessions", checkoutId, request);

    ArrayNode lineItems = json.createArrayNode();
    JsonNode requestLines = request.path("line_items");
    for (int i = 0; i < requestLines.size(); i++) {
      JsonNode line = requestLines.get(i);
      String productId = text(line.path("item"), "id");
      if (isEmpty(productId)) {
        throw UcpException.invalidRequest("Line item " + i + " missing product ID");
      }
      Product product =
          products
              .getProduct(productId)
              .orElseThrow(
                  () -> UcpException.invalidRequest("Product " + productId + " not found"));
      lineItems.add(lineItem("line_" + (i + 1), line.path("quantity").asLong(), product));
    }

    // checkout.json marks continue_url, expires_at, messages and order as ucp_request: omit, so
    // the business owns them on the response and they must not ride from the request into the
    // response. ucp, id, status, totals, links and currency are overwritten explicitly below.
    ObjectNode checkout = request.deepCopy();
    for (String omitted :
        List.of("fulfillment", "continue_url", "expires_at", "messages", "order")) {
      checkout.remove(omitted);
    }

    ObjectNode fulfillment =
        constructFulfillmentResponse(
            objectOrNull(request.get("fulfillment")),
            lineItems,
            objectOrNull(request.get("buyer")),
            null);
    Optional<ObjectNode> platform = platformProfiles.platformConfig(ucpAgent);

    checkout.put("id", checkoutId);
    if (fulfillment != null) {
      checkout.set("fulfillment", fulfillment);
    }
    checkout.set("ucp", checkoutUcpEnvelope());
    checkout.put("status", "incomplete");
    checkout.put("currency", "USD");
    checkout.set("line_items", lineItems);
    checkout.putArray("totals");
    checkout.putArray("links");
    platform.ifPresent(config -> checkout.set("platform", config));

    recalculateAndValidate(checkout);
    transactions.saveCheckout(checkoutId, "incomplete", checkout);
    if (idempotencyKey != null) {
      transactions.saveIdempotencyRecord(
          idempotencyKey, requestHash, 201, json.writeValueAsString(checkout));
    }
    return new Result(201, checkout);
  }

  /** GET /checkout-sessions/{id}. */
  public Result getCheckout(String id) {
    transactions.logRequest("GET", "/checkout-sessions/" + id, id, json.createObjectNode());
    return new Result(200, requireCheckout(id));
  }

  /** PUT /checkout-sessions/{id}. */
  public Result updateCheckout(
      String id, ObjectNode request, String idempotencyKey, String ucpAgent) {
    String requestHash = null;
    if (idempotencyKey != null) {
      requestHash = computeHash("update_checkout", request, id);
      Optional<Result> replay = replay(idempotencyKey, requestHash);
      if (replay.isPresent()) {
        return replay.get();
      }
    }

    transactions.logRequest("PUT", "/checkout-sessions/" + id, id, request);
    ObjectNode existing = requireCheckout(id);
    String status = text(existing, "status");
    if ("completed".equals(status) || "canceled".equals(status)) {
      throw UcpException.checkoutNotModifiable(
          "Cannot update a " + status + " checkout session");
    }

    if (request.get("buyer") instanceof ObjectNode buyer) {
      existing.set("buyer", buyer.deepCopy());
    }
    platformProfiles.platformConfig(ucpAgent).ifPresent(c -> existing.set("platform", c));

    // Simple shallow merge for payment. In the real world this might be more complex.
    ObjectNode payment = json.createObjectNode();
    if (existing.get("payment") instanceof ObjectNode current) {
      payment.setAll(current);
    }
    if (request.get("payment") instanceof ObjectNode update) {
      payment.setAll(update.deepCopy());
    }
    existing.set("payment", payment);

    if (request.get("discounts") instanceof ObjectNode discounts) {
      existing.set("discounts", discounts.deepCopy());
    }

    ArrayNode lineItems = json.createArrayNode();
    for (JsonNode line : request.path("line_items")) {
      String productId = text(line.path("item"), "id");
      if (isEmpty(productId)) {
        throw UcpException.invalidRequest("Line item missing product ID");
      }
      Product product =
          products
              .getProduct(productId)
              .orElseThrow(
                  () -> UcpException.invalidRequest("Product " + productId + " not found"));
      String lineId = text(line, "id");
      lineItems.add(
          lineItem(
              isEmpty(lineId) ? "line_" + (lineItems.size() + 1) : lineId,
              line.path("quantity").asLong(),
              product));
    }
    existing.set("line_items", lineItems);

    if (request.get("fulfillment") instanceof ObjectNode requested) {
      ObjectNode fulfillment =
          constructFulfillmentResponse(
              requested,
              lineItems,
              objectOrNull(existing.get("buyer")),
              objectOrNull(existing.get("fulfillment")));
      existing.set("fulfillment", fulfillment);
    }

    recalculateAndValidate(existing);
    transactions.saveCheckout(id, status, existing);
    if (idempotencyKey != null) {
      transactions.saveIdempotencyRecord(
          idempotencyKey, requestHash, 200, json.writeValueAsString(existing));
    }
    return new Result(200, existing);
  }

  /** POST /checkout-sessions/{id}/complete. */
  public Result completeCheckout(
      String id, ObjectNode request, String idempotencyKey, String baseUrl) {
    String requestHash = null;
    if (idempotencyKey != null) {
      requestHash = computeHash("complete_checkout", request, id);
      Optional<Result> replay = replay(idempotencyKey, requestHash);
      if (replay.isPresent()) {
        return replay.get();
      }
    }

    transactions.logRequest("POST", "/checkout-sessions/" + id + "/complete", id, request);
    ObjectNode checkout = requireCheckout(id);

    // Fulfillment must be fully selected. At least one method is required: an empty methods
    // array must not satisfy the gate vacuously.
    if (!fulfillmentSelected(checkout)) {
      throw UcpException.invalidRequest("Fulfillment address and option must be selected");
    }

    String status = text(checkout, "status");
    if ("completed".equals(status) || "canceled".equals(status)) {
      throw UcpException.checkoutNotModifiable("Checkout already completed or canceled");
    }

    processPayment(request.path("payment"));
    reserveInventory(checkout);

    checkout.put("status", "completed");
    String orderId = "ord_" + UUID.randomUUID();
    ObjectNode order = buildOrder(checkout, orderId, baseUrl);
    transactions.saveOrder(orderId, order);

    ObjectNode orderRef = checkout.putObject("order");
    orderRef.put("id", orderId);
    orderRef.put("permalink_url", order.path("permalink_url").asString());
    transactions.saveCheckout(id, "completed", checkout);

    webhooks.notify(checkout, "order_placed", baseUrl);

    if (idempotencyKey != null) {
      transactions.saveIdempotencyRecord(
          idempotencyKey, requestHash, 200, json.writeValueAsString(checkout));
    }
    return new Result(200, checkout);
  }

  /** POST /checkout-sessions/{id}/cancel. */
  public Result cancelCheckout(String id, String idempotencyKey) {
    ObjectNode request = json.createObjectNode(); // cancel carries no body
    String requestHash = null;
    if (idempotencyKey != null) {
      requestHash = computeHash("cancel_checkout", request, id);
      Optional<Result> replay = replay(idempotencyKey, requestHash);
      if (replay.isPresent()) {
        return replay.get();
      }
    }

    transactions.logRequest("POST", "/checkout-sessions/" + id + "/cancel", id, request);
    ObjectNode checkout = requireCheckout(id);
    String status = text(checkout, "status");
    if ("completed".equals(status) || "canceled".equals(status)) {
      throw UcpException.checkoutNotModifiable(
          "Cannot cancel a " + status + " checkout session");
    }

    checkout.put("status", "canceled");
    transactions.saveCheckout(id, "canceled", checkout);
    if (idempotencyKey != null) {
      transactions.saveIdempotencyRecord(
          idempotencyKey, requestHash, 200, json.writeValueAsString(checkout));
    }
    return new Result(200, checkout);
  }

  /** Records a "shipped" fulfillment event on an order and notifies the platform. */
  public void shipOrder(String orderId, String baseUrl) {
    ObjectNode order =
        transactions
            .getOrder(orderId)
            .orElseThrow(() -> UcpException.resourceNotFound("Order not found"));

    ObjectNode fulfillment =
        order.get("fulfillment") instanceof ObjectNode f ? f : order.putObject("fulfillment");
    ArrayNode events =
        fulfillment.get("events") instanceof ArrayNode e ? e : fulfillment.putArray("events");
    ObjectNode event = events.addObject();
    event.put("id", "evt_" + UUID.randomUUID());
    event.put("type", "shipped");
    event.put("occurred_at", Instant.now().toString());
    ArrayNode eventLines = event.putArray("line_items");
    for (JsonNode line : order.path("line_items")) {
      ObjectNode eventLine = eventLines.addObject();
      eventLine.set("id", line.path("id"));
      eventLine.set("quantity", line.path("quantity").path("total"));
    }
    transactions.saveOrder(orderId, order);

    String checkoutId = text(order, "checkout_id");
    if (checkoutId != null) {
      transactions
          .getCheckoutSession(checkoutId)
          .ifPresent(checkout -> webhooks.notify(checkout, "order_shipped", baseUrl));
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Idempotency
  // ---------------------------------------------------------------------------------------------

  /**
   * Fingerprints a request, scoped to the operation and (for update/complete/cancel) the target
   * checkout id, so a key cannot replay a different checkout or a different operation. Object
   * members are sorted so the fingerprint does not depend on member order.
   */
  String computeHash(String operation, JsonNode data, String resourceId) {
    ObjectNode payload = json.createObjectNode();
    payload.put("operation", operation);
    if (resourceId == null) {
      payload.putNull("resourceId");
    } else {
      payload.put("resourceId", resourceId);
    }
    payload.set("data", data);
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256")
              .digest(json.writeValueAsString(sorted(payload)).getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  private Optional<Result> replay(String idempotencyKey, String requestHash) {
    Optional<IdempotencyRecord> record = transactions.getIdempotencyRecord(idempotencyKey);
    if (record.isEmpty()) {
      return Optional.empty();
    }
    if (!record.get().requestHash().equals(requestHash)) {
      throw UcpException.idempotencyConflict("Idempotency key reused with different parameters");
    }
    return Optional.of(
        new Result(record.get().responseStatus(), json.readTree(record.get().responseBody())));
  }

  private JsonNode sorted(JsonNode node) {
    if (node.isObject()) {
      ObjectNode out = json.createObjectNode();
      node.propertyNames().stream().sorted().forEach(name -> out.set(name, sorted(node.get(name))));
      return out;
    }
    if (node.isArray()) {
      ArrayNode out = json.createArrayNode();
      node.forEach(element -> out.add(sorted(element)));
      return out;
    }
    return node;
  }

  // ---------------------------------------------------------------------------------------------
  // Checkout construction
  // ---------------------------------------------------------------------------------------------

  /**
   * The checkout response's ucp envelope. The 2026-04-08 schema binds checkout responses to
   * {@code ucp.json#/$defs/response_checkout_schema}, which requires {@code payment_handlers}, so
   * it is emitted as an (empty) object like the Python reference. It is persisted with the
   * checkout, so every later read inherits it.
   */
  private ObjectNode checkoutUcpEnvelope() {
    ObjectNode ucp = json.createObjectNode();
    ucp.put("version", UcpProperties.UCP_VERSION);
    ObjectNode capability =
        ucp.putObject("capabilities").putArray("dev.ucp.shopping.checkout").addObject();
    capability.put("name", "dev.ucp.shopping.checkout");
    capability.put("version", UcpProperties.UCP_VERSION);
    ucp.putObject("payment_handlers");
    return ucp;
  }

  private ObjectNode lineItem(String id, long quantity, Product product) {
    ObjectNode line = json.createObjectNode();
    line.put("id", id);
    line.put("quantity", quantity);
    line.putArray("totals");
    ObjectNode item = line.putObject("item");
    item.put("id", product.id());
    item.put("title", product.title());
    item.put("price", product.price());
    if (product.imageUrl() != null) {
      item.put("image_url", product.imageUrl());
    }
    return line;
  }

  /** The two addresses a known customer has on file. */
  private List<ObjectNode> mockDestinations() {
    return List.of(
        address("addr_1", "123 Main St", "Springfield", "IL", "62704"),
        address("addr_2", "456 Oak Ave", "Metropolis", "NY", "10012"));
  }

  private ObjectNode address(
      String id, String street, String locality, String region, String postalCode) {
    ObjectNode address = json.createObjectNode();
    address.put("id", id);
    address.put("address_country", "US");
    address.put("street_address", street);
    address.put("address_locality", locality);
    address.put("address_region", region);
    address.put("postal_code", postalCode);
    address.put("first_name", "John");
    address.put("last_name", "Doe");
    return address;
  }

  private static boolean addressesMatch(JsonNode known, JsonNode requested) {
    for (String field :
        List.of(
            "street_address", "address_locality", "address_region", "address_country",
            "postal_code")) {
      if (!Objects.equals(text(known, field), text(requested, field))) {
        return false;
      }
    }
    return true;
  }

  /**
   * Builds the response-side fulfillment from the requested one: assigns ids to methods,
   * destinations, and groups, resolves the known customer's saved addresses, and carries
   * destinations over from the existing fulfillment when the request omits them.
   */
  private ObjectNode constructFulfillmentResponse(
      ObjectNode requested, ArrayNode lineItems, ObjectNode buyer, ObjectNode existing) {
    if (requested == null) {
      return null;
    }
    boolean knownCustomer = KNOWN_CUSTOMER_EMAIL.equals(text(buyer, "email"));
    List<ObjectNode> known = knownCustomer ? mockDestinations() : List.of();

    ObjectNode fulfillment = json.createObjectNode();
    ArrayNode methods = fulfillment.putArray("methods");
    for (JsonNode m : requested.path("methods")) {
      String type = isEmpty(text(m, "type")) ? "shipping" : text(m, "type");

      ArrayNode destinations = null;
      if (m.get("destinations") instanceof ArrayNode requestedDestinations) {
        destinations = json.createArrayNode();
        for (JsonNode d : requestedDestinations) {
          ObjectNode destination = ((ObjectNode) d).deepCopy();
          if (isEmpty(text(d, "id"))) {
            String matchedId =
                known.stream()
                    .filter(k -> addressesMatch(k, d))
                    .map(k -> text(k, "id"))
                    .findFirst()
                    .orElse("dest_" + UUID.randomUUID());
            destination.put("id", matchedId);
          }
          destinations.add(destination);
        }
      } else if (existing != null && existing.get("methods") instanceof ArrayNode existingMethods) {
        for (JsonNode existingMethod : existingMethods) {
          if (type.equals(text(existingMethod, "type"))) {
            if (existingMethod.get("destinations") instanceof ArrayNode existingDestinations) {
              destinations = existingDestinations.deepCopy();
            }
            break;
          }
        }
      } else if (knownCustomer) {
        destinations = json.createArrayNode();
        known.forEach(destinations::add);
      }

      ObjectNode method = methods.addObject();
      method.put("id", "method_" + UUID.randomUUID());
      method.put("type", type);
      method.set("line_item_ids", lineItemIds(lineItems));
      if (destinations != null) {
        method.set("destinations", destinations);
      }
      String selectedDestination = text(m, "selected_destination_id");
      if (selectedDestination != null) {
        method.put("selected_destination_id", selectedDestination);
      }
      ArrayNode groups = method.putArray("groups");
      for (JsonNode g : m.path("groups")) {
        ObjectNode group = groups.addObject();
        group.put("id", "group_" + UUID.randomUUID());
        group.set("line_item_ids", lineItemIds(lineItems));
        String selectedOption = text(g, "selected_option_id");
        if (selectedOption != null) {
          group.put("selected_option_id", selectedOption);
        }
        group.putArray("options"); // populated in recalculateTotals
      }
    }
    return fulfillment;
  }

  private ArrayNode lineItemIds(ArrayNode lineItems) {
    ArrayNode ids = json.createArrayNode();
    lineItems.forEach(line -> ids.add(line.path("id").asString()));
    return ids;
  }

  private void recalculateAndValidate(ObjectNode checkout) {
    try {
      recalculateTotals(checkout);
    } catch (IllegalStateException e) {
      throw UcpException.invalidRequest(e.getMessage());
    }
    validateInventory(checkout);
  }

  /**
   * Recomputes line totals (from authoritative catalog prices), fulfillment options and their
   * cost, discounts, buyer-consent defaults, and the checkout totals.
   */
  private void recalculateTotals(ObjectNode checkout) {
    long grandTotal = 0;

    for (JsonNode line : checkout.path("line_items")) {
      ObjectNode item = (ObjectNode) line.path("item");
      String productId = text(item, "id");
      Product product =
          products
              .getProduct(productId)
              .orElseThrow(() -> new IllegalStateException("Product " + productId + " not found"));
      item.put("price", product.price());
      item.put("title", product.title());
      long lineTotal = product.price() * line.path("quantity").asLong();
      ArrayNode lineTotals = ((ObjectNode) line).putArray("totals");
      lineTotals.add(total("subtotal", lineTotal));
      lineTotals.add(total("total", lineTotal));
      grandTotal += lineTotal;
    }

    ArrayNode totals = checkout.putArray("totals");
    totals.add(total("subtotal", grandTotal));

    // Fulfillment (mock rates).
    if (checkout.path("fulfillment").get("methods") instanceof ArrayNode methods) {
      for (JsonNode node : methods) {
        ObjectNode method = (ObjectNode) node;
        // fulfillment.md, "Business Response Behavior": with the default supports_multi_group:
        // false the response MUST carry one group per method, even for a method the merchant
        // cannot quote options for.
        if (!(method.get("groups") instanceof ArrayNode groups) || groups.isEmpty()) {
          ObjectNode group = method.putArray("groups").addObject();
          group.put("id", "group_" + UUID.randomUUID());
          group.set(
              "line_item_ids",
              method.get("line_item_ids") instanceof ArrayNode ids
                  ? ids.deepCopy()
                  : json.createArrayNode());
          group.putArray("options");
        }

        String selectedDestination = text(method, "selected_destination_id");
        if (!"shipping".equals(text(method, "type"))
            || isEmpty(selectedDestination)
            || !(method.get("destinations") instanceof ArrayNode destinations)) {
          continue;
        }
        JsonNode destination = null;
        for (JsonNode d : destinations) {
          if (selectedDestination.equals(text(d, "id"))) {
            destination = d;
            break;
          }
        }
        if (destination == null) {
          continue;
        }
        // The country is a flat field on a postal address, or nested on a retail location.
        String country = text(destination, "address_country");
        if (isEmpty(country)) {
          country = text(destination.path("address"), "address_country");
        }
        if (isEmpty(country)) {
          continue;
        }

        ArrayNode options = shippingOptions(country, checkout, grandTotal);
        for (JsonNode group : method.path("groups")) {
          ((ObjectNode) group).set("options", options.deepCopy());
        }
        for (JsonNode group : method.path("groups")) {
          String selectedOption = text(group, "selected_option_id");
          if (isEmpty(selectedOption)) {
            continue;
          }
          for (JsonNode option : group.path("options")) {
            if (selectedOption.equals(text(option, "id"))) {
              long amount = totalOfType(option.path("totals"), "total");
              grandTotal += amount;
              ObjectNode fulfillmentTotal = total("fulfillment", amount);
              fulfillmentTotal.put("display_text", text(option, "title"));
              totals.add(fulfillmentTotal);
              break;
            }
          }
        }
      }
    }

    // Discounts (mock codes).
    ObjectNode discounts =
        checkout.get("discounts") instanceof ObjectNode d ? d : checkout.putObject("discounts");
    ArrayNode applied = discounts.putArray("applied");
    for (JsonNode code : discounts.path("codes")) {
      if (!code.isString()) {
        continue;
      }
      String title;
      long amount;
      switch (code.stringValue().toUpperCase(Locale.ROOT)) {
        case "10OFF" -> {
          title = "10% Off";
          amount = grandTotal / 10;
        }
        case "WELCOME20" -> {
          title = "Welcome 20% Off";
          amount = grandTotal / 5;
        }
        case "FIXED500" -> {
          title = "$5.00 Off";
          amount = Math.min(grandTotal, 500);
        }
        default -> {
          continue;
        }
      }
      grandTotal -= amount;
      ObjectNode discount = applied.addObject();
      discount.put("code", code.stringValue());
      discount.put("title", title);
      discount.put("amount", amount);
      ObjectNode allocation = discount.putArray("allocations").addObject();
      allocation.put("path", DISCOUNT_ALLOCATION_PATH);
      allocation.put("amount", amount);
      totals.add(total("discount", -amount));
    }

    // Buyer consent: fill in defaults.
    if (checkout.path("buyer").get("consent") instanceof ObjectNode consent) {
      for (Map.Entry<String, JsonNode> entry : consent.properties()) {
        if (entry.getValue() instanceof ObjectNode value) {
          if (isEmpty(text(value, "description"))) {
            value.put("description", "Consent for " + entry.getKey());
          }
          if (isEmpty(text(value, "source"))) {
            value.put("source", "platform");
          }
        }
      }
    }

    totals.add(total("total", grandTotal));
  }

  /** The mock shipping rates for a destination country. */
  private ArrayNode shippingOptions(String country, ObjectNode checkout, long subtotal) {
    ArrayNode options = json.createArrayNode();
    if ("US".equals(country)) {
      boolean hasRoses = false;
      for (JsonNode line : checkout.path("line_items")) {
        hasRoses |= "bouquet_roses".equals(text(line.path("item"), "id"));
      }
      boolean expensive = subtotal >= 10000;
      long standardCost = hasRoses || expensive ? 0 : 500;
      options.add(
          option(
              "std-ship",
              standardCost == 0 ? "Free Standard Shipping" : "Standard Shipping",
              "Arrives in 5-7 days",
              standardCost));
      options.add(option("exp-ship-us", "Express Shipping (US)", "Arrives in 2 days", 1500));
    } else {
      options.add(option("exp-ship-intl", "International Express", "Arrives in 5-10 days", 3000));
    }
    return options;
  }

  private ObjectNode option(String id, String title, String description, long cost) {
    ObjectNode option = json.createObjectNode();
    option.put("id", id);
    option.put("title", title);
    option.put("description", description);
    ArrayNode totals = option.putArray("totals");
    totals.add(total("subtotal", cost));
    totals.add(total("total", cost));
    return option;
  }

  private ObjectNode total(String type, long amount) {
    ObjectNode total = json.createObjectNode();
    total.put("type", type);
    total.put("amount", amount);
    return total;
  }

  private void validateInventory(ObjectNode checkout) {
    for (JsonNode line : checkout.path("line_items")) {
      String productId = text(line.path("item"), "id");
      OptionalLong available = inventory.getInventory(productId);
      if (available.isEmpty() || available.getAsLong() < line.path("quantity").asLong()) {
        throw UcpException.outOfStock("Insufficient stock for item " + productId, 400);
      }
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Completion
  // ---------------------------------------------------------------------------------------------

  private static boolean fulfillmentSelected(ObjectNode checkout) {
    if (!(checkout.path("fulfillment").get("methods") instanceof ArrayNode methods)
        || methods.isEmpty()) {
      return false;
    }
    for (JsonNode method : methods) {
      if (isEmpty(text(method, "selected_destination_id"))
          || !(method.get("groups") instanceof ArrayNode groups)) {
        return false;
      }
      for (JsonNode group : groups) {
        if (isEmpty(text(group, "selected_option_id"))) {
          return false;
        }
      }
    }
    return true;
  }

  /** Runs the (mock) payment handlers. Throws on a declined or unsupported payment. */
  private static void processPayment(JsonNode payment) {
    JsonNode instruments = payment.path("instruments");
    if (!instruments.isArray() || instruments.isEmpty()) {
      throw UcpException.invalidRequest("Missing payment data");
    }
    JsonNode instrument = instruments.get(0);
    JsonNode credential = instrument.get("credential");
    if (credential == null || credential.isNull()) {
      throw UcpException.invalidRequest("Missing credentials in instrument");
    }
    if ("card".equals(text(instrument, "type")) && "card".equals(text(credential, "type"))) {
      return; // card credentials are accepted as-is
    }

    String handlerId = text(instrument, "handler_id");
    String token = text(credential, "token");
    if ("mock_payment_handler".equals(handlerId)) {
      if ("success_token".equals(token)) {
        return;
      }
      if ("fail_token".equals(token)) {
        throw UcpException.paymentFailed(
            "Payment Failed: Insufficient Funds (Mock)", "INSUFFICIENT_FUNDS", 402);
      }
      if ("fraud_token".equals(token)) {
        throw UcpException.paymentFailed(
            "Payment Failed: Fraud Detected (Mock)", "FRAUD_DETECTED", 403);
      }
      throw UcpException.paymentFailed(
          "Unknown mock token: " + (token == null ? "undefined" : token), "UNKNOWN_TOKEN", 400);
    }
    if (List.of("google_pay", "gpay", "shop_pay").contains(handlerId)) {
      return; // mock success
    }
    throw UcpException.invalidRequest("Unsupported payment handler: " + handlerId);
  }

  /** Reserves stock for every line item, rolling back on the first shortage. */
  private void reserveInventory(ObjectNode checkout) {
    record Reservation(String productId, long quantity) {}
    List<Reservation> reserved = new ArrayList<>();
    for (JsonNode line : checkout.path("line_items")) {
      String productId = text(line.path("item"), "id");
      long quantity = line.path("quantity").asLong();
      if (products.getProduct(productId).isEmpty()) {
        continue;
      }
      if (!inventory.reserveStock(productId, quantity)) {
        reserved.forEach(r -> inventory.releaseStock(r.productId(), r.quantity()));
        throw UcpException.outOfStock("Item " + productId + " is out of stock", 409);
      }
      reserved.add(new Reservation(productId, quantity));
    }
  }

  private ObjectNode buildOrder(ObjectNode checkout, String orderId, String baseUrl) {
    ObjectNode order = json.createObjectNode();
    order.set("ucp", checkout.path("ucp").deepCopy());
    order.put("id", orderId);
    order.put("checkout_id", text(checkout, "id"));
    order.put("permalink_url", baseUrl + "/orders/" + orderId);

    ArrayNode orderLines = order.putArray("line_items");
    for (JsonNode line : checkout.path("line_items")) {
      ObjectNode orderLine = orderLines.addObject();
      orderLine.set("id", line.path("id"));
      orderLine.set("item", line.path("item").deepCopy());
      ObjectNode quantity = orderLine.putObject("quantity");
      quantity.put("total", line.path("quantity").asLong());
      quantity.put("fulfilled", 0);
      orderLine.set("totals", line.path("totals").deepCopy());
      orderLine.put("status", "processing");
      if (line.hasNonNull("parent_id")) {
        orderLine.set("parent_id", line.get("parent_id"));
      }
    }
    order.set("totals", checkout.path("totals").deepCopy());
    order.putObject("fulfillment").set("expectations", expectations(checkout));
    order.set("currency", checkout.path("currency"));
    return order;
  }

  /** One fulfillment expectation per group with a selected option. */
  private ArrayNode expectations(ObjectNode checkout) {
    ArrayNode expectations = json.createArrayNode();
    for (JsonNode method : checkout.path("fulfillment").path("methods")) {
      JsonNode address = json.createObjectNode();
      String selectedDestination = text(method, "selected_destination_id");
      if (!isEmpty(selectedDestination)) {
        for (JsonNode destination : method.path("destinations")) {
          if (selectedDestination.equals(text(destination, "id"))) {
            // A retail location carries a nested address; a postal address is the destination.
            address =
                destination.get("address") instanceof ObjectNode nested ? nested : destination;
            break;
          }
        }
      }

      for (JsonNode group : method.path("groups")) {
        String selectedOption = text(group, "selected_option_id");
        if (isEmpty(selectedOption)) {
          continue;
        }
        JsonNode selected = null;
        for (JsonNode option : group.path("options")) {
          if (selectedOption.equals(text(option, "id"))) {
            selected = option;
            break;
          }
        }
        if (selected == null) {
          continue;
        }
        ObjectNode expectation = expectations.addObject();
        expectation.put("id", "exp_" + UUID.randomUUID());
        expectation.set("destination", address.deepCopy());
        expectation.set("method_type", method.path("type"));
        ArrayNode expectationLines = expectation.putArray("line_items");
        for (JsonNode lineItemId : group.path("line_item_ids")) {
          for (JsonNode line : checkout.path("line_items")) {
            if (lineItemId.asString().equals(text(line, "id"))) {
              ObjectNode expectationLine = expectationLines.addObject();
              expectationLine.set("id", line.path("id"));
              expectationLine.set("quantity", line.path("quantity"));
              break;
            }
          }
        }
        expectation.put("description", text(selected, "title"));
      }
    }
    return expectations;
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------------------------

  private ObjectNode requireCheckout(String id) {
    return transactions
        .getCheckoutSession(id)
        .orElseThrow(() -> UcpException.resourceNotFound("Checkout session not found"));
  }

  private static long totalOfType(JsonNode totals, String type) {
    for (JsonNode total : totals) {
      if (type.equals(text(total, "type"))) {
        return total.path("amount").asLong();
      }
    }
    return 0;
  }

  private static ObjectNode objectOrNull(JsonNode node) {
    return node instanceof ObjectNode object ? object : null;
  }

  /** A string member, or null when the member is absent or not a string. */
  static String text(JsonNode node, String member) {
    if (node == null) {
      return null;
    }
    JsonNode value = node.get(member);
    return value != null && value.isString() ? value.stringValue() : null;
  }

  private static boolean isEmpty(String value) {
    return value == null || value.isEmpty();
  }
}
