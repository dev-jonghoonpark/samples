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

import dev.ucp.samples.service.CheckoutService;
import dev.ucp.samples.service.CheckoutService.Result;
import dev.ucp.samples.service.RequestValidator;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/** The checkout capability's REST binding ({@code dev.ucp.shopping.checkout}). */
@RestController
@RequestMapping("/checkout-sessions")
public class CheckoutController {

  private final CheckoutService checkouts;
  private final RequestValidator validator;

  public CheckoutController(CheckoutService checkouts, RequestValidator validator) {
    this.checkouts = checkouts;
    this.validator = validator;
  }

  @PostMapping
  public ResponseEntity<JsonNode> create(
      @RequestBody(required = false) byte[] body,
      @RequestHeader(name = "Idempotency-Key", required = false) String idempotencyKey,
      @RequestHeader(name = "UCP-Agent", required = false) String ucpAgent) {
    ObjectNode request = validator.parseObject(body);
    validator.checkoutCreate(request);
    return respond(checkouts.createCheckout(request, idempotencyKey, ucpAgent));
  }

  @GetMapping("/{id}")
  public ResponseEntity<JsonNode> get(@PathVariable String id) {
    return respond(checkouts.getCheckout(id));
  }

  @PutMapping("/{id}")
  public ResponseEntity<JsonNode> update(
      @PathVariable String id,
      @RequestBody(required = false) byte[] body,
      @RequestHeader(name = "Idempotency-Key", required = false) String idempotencyKey,
      @RequestHeader(name = "UCP-Agent", required = false) String ucpAgent) {
    ObjectNode request = validator.parseObject(body);
    validator.checkoutUpdate(request);
    return respond(checkouts.updateCheckout(id, request, idempotencyKey, ucpAgent));
  }

  @PostMapping("/{id}/complete")
  public ResponseEntity<JsonNode> complete(
      @PathVariable String id,
      @RequestBody(required = false) byte[] body,
      @RequestHeader(name = "Idempotency-Key", required = false) String idempotencyKey,
      HttpServletRequest servletRequest) {
    ObjectNode request = validator.parseObject(body);
    validator.checkoutComplete(request);
    return respond(
        checkouts.completeCheckout(id, request, idempotencyKey, Origins.of(servletRequest)));
  }

  @PostMapping("/{id}/cancel")
  public ResponseEntity<JsonNode> cancel(
      @PathVariable String id,
      @RequestHeader(name = "Idempotency-Key", required = false) String idempotencyKey) {
    return respond(checkouts.cancelCheckout(id, idempotencyKey));
  }

  private static ResponseEntity<JsonNode> respond(Result result) {
    return ResponseEntity.status(result.status()).body(result.body());
  }
}
