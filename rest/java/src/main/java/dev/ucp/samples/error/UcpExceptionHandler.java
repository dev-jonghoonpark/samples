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

import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import tools.jackson.databind.JsonNode;

/** Maps exceptions thrown by the controllers onto HTTP responses. */
@RestControllerAdvice
public class UcpExceptionHandler {

  private static final Logger log = LoggerFactory.getLogger(UcpExceptionHandler.class);

  @ExceptionHandler(UcpException.class)
  public ResponseEntity<JsonNode> handleUcp(UcpException error) {
    return ResponseEntity.status(error.status()).body(ErrorEnvelope.of(error));
  }

  /** Anything unexpected is an internal error, answered like the Node.js server does. */
  @ExceptionHandler(RuntimeException.class)
  public ResponseEntity<Map<String, String>> handleUnexpected(RuntimeException error) {
    if (error instanceof ErrorResponse framework) {
      // Spring MVC's own errors (unsupported media type, ...) keep their status.
      return ResponseEntity.status(framework.getStatusCode())
          .body(Map.of("detail", String.valueOf(framework.getBody().getDetail())));
    }
    log.error("Unhandled error", error);
    return ResponseEntity.status(500).body(Map.of("detail", "Internal server error"));
  }
}
