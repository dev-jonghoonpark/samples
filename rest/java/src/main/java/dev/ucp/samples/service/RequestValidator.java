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

import dev.ucp.samples.error.UcpException;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Structural validation of request payloads, covering the constraints the Node.js server gets
 * from the UCP SDK's Zod schemas (required members, types, {@code quantity >= 1}).
 *
 * <p>A payload that fails validation is a protocol error answered with the UCP error envelope
 * (422 {@code INVALID_REQUEST}), its content a readable list of the violations.
 */
@Component
public class RequestValidator {

  private static final Logger log = LoggerFactory.getLogger(RequestValidator.class);

  private final JsonMapper json;

  public RequestValidator(JsonMapper json) {
    this.json = json;
  }

  /** Parses a JSON object body. An empty body parses as {@code {}}. */
  public ObjectNode parseObject(byte[] body) {
    if (body == null || body.length == 0) {
      return json.createObjectNode();
    }
    JsonNode node;
    try {
      node = json.readTree(body);
    } catch (JacksonException e) {
      throw UcpException.invalidRequest("Malformed JSON in request body");
    }
    if (!(node instanceof ObjectNode object)) {
      throw UcpException.validationFailed("✖ Expected object\n  → at ");
    }
    return object;
  }

  /** Validates a checkout create request. */
  public void checkoutCreate(ObjectNode body) {
    Violations v = new Violations();
    checkoutFields(body, v, false);
    v.throwIfAny(body);
  }

  /** Validates a checkout update request. */
  public void checkoutUpdate(ObjectNode body) {
    Violations v = new Violations();
    checkoutFields(body, v, true);
    v.throwIfAny(body);
  }

  /** Validates a checkout complete request. */
  public void checkoutComplete(ObjectNode body) {
    Violations v = new Violations();
    payment(body.get("payment"), "payment", v);
    v.throwIfAny(body);
  }

  /** Validates a full order document (PUT /orders/{id}). */
  public void order(ObjectNode body) {
    Violations v = new Violations();
    requireType(body, "ucp", "", Kind.OBJECT, v);
    requireType(body, "id", "", Kind.STRING, v);
    requireType(body, "checkout_id", "", Kind.STRING, v);
    requireType(body, "permalink_url", "", Kind.STRING, v);
    requireType(body, "line_items", "", Kind.ARRAY, v);
    requireType(body, "fulfillment", "", Kind.OBJECT, v);
    requireType(body, "totals", "", Kind.ARRAY, v);
    v.throwIfAny(body);
  }

  private void checkoutFields(ObjectNode body, Violations v, boolean update) {
    if (update) {
      optionalType(body, "id", "", Kind.STRING, v);
    }
    JsonNode lineItems = requireType(body, "line_items", "", Kind.ARRAY, v);
    if (lineItems != null) {
      for (int i = 0; i < lineItems.size(); i++) {
        lineItem(lineItems.get(i), "line_items[" + i + "]", v, update);
      }
    }
    optionalType(body, "currency", "", Kind.STRING, v);
    JsonNode buyer = optionalType(body, "buyer", "", Kind.OBJECT, v);
    if (buyer != null) {
      optionalType(buyer, "email", "buyer", Kind.STRING, v);
      optionalType(buyer, "consent", "buyer", Kind.OBJECT, v);
    }
    JsonNode fulfillment = optionalType(body, "fulfillment", "", Kind.OBJECT, v);
    if (fulfillment != null) {
      JsonNode methods = optionalType(fulfillment, "methods", "fulfillment", Kind.ARRAY, v);
      if (methods != null) {
        for (int i = 0; i < methods.size(); i++) {
          fulfillmentMethod(methods.get(i), "fulfillment.methods[" + i + "]", v);
        }
      }
    }
    payment(body.get("payment"), "payment", v);
    JsonNode discounts = optionalType(body, "discounts", "", Kind.OBJECT, v);
    if (discounts != null) {
      JsonNode codes = optionalType(discounts, "codes", "discounts", Kind.ARRAY, v);
      if (codes != null) {
        for (int i = 0; i < codes.size(); i++) {
          if (!codes.get(i).isString()) {
            v.add("Expected string", "discounts.codes[" + i + "]");
          }
        }
      }
    }
  }

  private void lineItem(JsonNode line, String path, Violations v, boolean update) {
    if (!line.isObject()) {
      v.add("Expected object", path);
      return;
    }
    if (update) {
      optionalType(line, "id", path, Kind.STRING, v);
    }
    JsonNode item = requireType(line, "item", path, Kind.OBJECT, v);
    if (item != null) {
      requireType(item, "id", path + ".item", Kind.STRING, v);
    }
    JsonNode quantity = requireType(line, "quantity", path, Kind.INTEGER, v);
    if (quantity != null && quantity.asLong() < 1) {
      v.add("Number must be greater than or equal to 1", path + ".quantity");
    }
  }

  private void fulfillmentMethod(JsonNode method, String path, Violations v) {
    if (!method.isObject()) {
      v.add("Expected object", path);
      return;
    }
    optionalType(method, "type", path, Kind.STRING, v);
    optionalType(method, "selected_destination_id", path, Kind.STRING, v);
    JsonNode destinations = optionalType(method, "destinations", path, Kind.ARRAY, v);
    if (destinations != null) {
      for (int i = 0; i < destinations.size(); i++) {
        if (!destinations.get(i).isObject()) {
          v.add("Expected object", path + ".destinations[" + i + "]");
        }
      }
    }
    JsonNode groups = optionalType(method, "groups", path, Kind.ARRAY, v);
    if (groups != null) {
      for (int i = 0; i < groups.size(); i++) {
        JsonNode group = groups.get(i);
        String groupPath = path + ".groups[" + i + "]";
        if (!group.isObject()) {
          v.add("Expected object", groupPath);
        } else {
          optionalType(group, "selected_option_id", groupPath, Kind.STRING, v);
        }
      }
    }
  }

  private void payment(JsonNode payment, String path, Violations v) {
    if (payment == null || payment.isNull()) {
      return;
    }
    if (!payment.isObject()) {
      v.add("Expected object, received " + kindOf(payment), path);
      return;
    }
    JsonNode instruments = optionalType(payment, "instruments", path, Kind.ARRAY, v);
    if (instruments != null) {
      for (int i = 0; i < instruments.size(); i++) {
        JsonNode instrument = instruments.get(i);
        String instrumentPath = path + ".instruments[" + i + "]";
        if (!instrument.isObject()) {
          v.add("Expected object", instrumentPath);
          continue;
        }
        requireType(instrument, "id", instrumentPath, Kind.STRING, v);
        requireType(instrument, "handler_id", instrumentPath, Kind.STRING, v);
        requireType(instrument, "type", instrumentPath, Kind.STRING, v);
        optionalType(instrument, "credential", instrumentPath, Kind.OBJECT, v);
      }
    }
  }

  private enum Kind {
    OBJECT("object"),
    ARRAY("array"),
    STRING("string"),
    INTEGER("integer");

    final String label;

    Kind(String label) {
      this.label = label;
    }

    boolean matches(JsonNode node) {
      return switch (this) {
        case OBJECT -> node.isObject();
        case ARRAY -> node.isArray();
        case STRING -> node.isString();
        case INTEGER -> node.isIntegralNumber() && node.canConvertToLong();
      };
    }
  }

  private static JsonNode requireType(
      JsonNode parent, String member, String path, Kind kind, Violations v) {
    JsonNode value = parent.get(member);
    String at = path.isEmpty() ? member : path + "." + member;
    if (value == null || value.isNull()) {
      v.add("Required", at);
      return null;
    }
    if (!kind.matches(value)) {
      v.add("Expected " + kind.label + ", received " + kindOf(value), at);
      return null;
    }
    return value;
  }

  private static JsonNode optionalType(
      JsonNode parent, String member, String path, Kind kind, Violations v) {
    JsonNode value = parent.get(member);
    if (value == null || value.isNull()) {
      return null;
    }
    if (!kind.matches(value)) {
      String at = path.isEmpty() ? member : path + "." + member;
      v.add("Expected " + kind.label + ", received " + kindOf(value), at);
      return null;
    }
    return value;
  }

  private static String kindOf(JsonNode node) {
    if (node.isObject()) {
      return "object";
    }
    if (node.isArray()) {
      return "array";
    }
    if (node.isString()) {
      return "string";
    }
    if (node.isBoolean()) {
      return "boolean";
    }
    if (node.isIntegralNumber()) {
      return "integer";
    }
    if (node.isNumber()) {
      return "float";
    }
    return "null";
  }

  /** Collects violations and renders them like the Node.js server's pretty Zod output. */
  private final class Violations {
    private final List<String> lines = new ArrayList<>();

    void add(String message, String path) {
      lines.add("✖ " + message + "\n  → at " + path);
    }

    void throwIfAny(JsonNode payload) {
      if (lines.isEmpty()) {
        return;
      }
      String pretty = String.join("\n", lines);
      log.warn("Request payload failed validation:\n{}\nRequest payload:\n{}", pretty, payload);
      throw UcpException.validationFailed(pretty);
    }
  }
}
