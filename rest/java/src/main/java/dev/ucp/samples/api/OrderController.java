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

import dev.ucp.samples.data.TransactionStore;
import dev.ucp.samples.error.UcpException;
import dev.ucp.samples.service.RequestValidator;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/** The order capability's REST binding ({@code dev.ucp.shopping.order}). */
@RestController
@RequestMapping("/orders")
public class OrderController {

  private final TransactionStore transactions;
  private final RequestValidator validator;
  private final JsonMapper json;

  public OrderController(TransactionStore transactions, RequestValidator validator, JsonMapper json) {
    this.transactions = transactions;
    this.validator = validator;
    this.json = json;
  }

  @GetMapping("/{id}")
  public ResponseEntity<JsonNode> get(@PathVariable String id) {
    transactions.logRequest("GET", "/orders/" + id, null, json.createObjectNode());
    ObjectNode order =
        transactions
            .getOrder(id)
            .orElseThrow(() -> UcpException.resourceNotFound("Order not found"));
    return ResponseEntity.ok(order);
  }

  @PutMapping("/{id}")
  public ResponseEntity<JsonNode> update(
      @PathVariable String id, @RequestBody(required = false) byte[] body) {
    ObjectNode order = validator.parseObject(body);
    validator.order(order);
    JsonNode checkoutId = order.get("checkout_id");
    transactions.logRequest(
        "PUT", "/orders/" + id, checkoutId != null ? checkoutId.asString() : null, order);

    if (transactions.getOrder(id).isEmpty()) {
      throw UcpException.resourceNotFound("Order not found");
    }
    order.put("id", id); // the path is authoritative
    transactions.saveOrder(id, order);
    return ResponseEntity.ok(order);
  }
}
