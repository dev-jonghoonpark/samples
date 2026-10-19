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

package dev.ucp.samples.error;

/**
 * A business or protocol failure answered with the UCP error envelope ({@code ucp.status:
 * "error"} plus a {@code messages[]} entry carrying {@code code}, {@code content} and {@code
 * severity}).
 *
 * <p>The taxonomy mirrors the Python reference ({@code rest/python/server/exceptions.py}) and the
 * Node.js server ({@code src/utils/ucp_error.ts}).
 */
public class UcpException extends RuntimeException {

  /** message_error.json severities. */
  public enum Severity {
    RECOVERABLE("recoverable"),
    REQUIRES_BUYER_INPUT("requires_buyer_input"),
    REQUIRES_BUYER_REVIEW("requires_buyer_review"),
    UNRECOVERABLE("unrecoverable");

    private final String wireValue;

    Severity(String wireValue) {
      this.wireValue = wireValue;
    }

    public String wireValue() {
      return wireValue;
    }
  }

  private final String code;
  private final int status;
  private final Severity severity;

  public UcpException(String message, String code, int status, Severity severity) {
    super(message);
    this.code = code;
    this.status = status;
    this.severity = severity;
  }

  public UcpException(String message, String code, int status) {
    this(message, code, status, Severity.UNRECOVERABLE);
  }

  public String code() {
    return code;
  }

  public int status() {
    return status;
  }

  public Severity severity() {
    return severity;
  }

  public static UcpException resourceNotFound(String message) {
    return new UcpException(message, "RESOURCE_NOT_FOUND", 404);
  }

  public static UcpException idempotencyConflict(String message) {
    return new UcpException(message, "IDEMPOTENCY_CONFLICT", 409);
  }

  public static UcpException checkoutNotModifiable(String message) {
    return new UcpException(message, "CHECKOUT_NOT_MODIFIABLE", 409);
  }

  public static UcpException outOfStock(String message, int status) {
    return new UcpException(message, "OUT_OF_STOCK", status);
  }

  public static UcpException paymentFailed(String message, String code, int status) {
    return new UcpException(message, code, status, Severity.REQUIRES_BUYER_INPUT);
  }

  public static UcpException invalidRequest(String message) {
    return new UcpException(message, "INVALID_REQUEST", 400);
  }

  /** A request payload that failed validation (422, like the Node.js server's Zod hook). */
  public static UcpException validationFailed(String message) {
    return new UcpException(message, "INVALID_REQUEST", 422);
  }
}
