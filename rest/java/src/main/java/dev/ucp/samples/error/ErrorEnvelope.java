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

import dev.ucp.samples.config.UcpProperties;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/** Renders the UCP error envelope, byte-shape-identical to the other reference servers. */
public final class ErrorEnvelope {

  private ErrorEnvelope() {}

  /** Builds the envelope body for an error. */
  public static ObjectNode of(String code, String content, UcpException.Severity severity) {
    ObjectNode body = JsonNodeFactory.instance.objectNode();
    ObjectNode ucp = body.putObject("ucp");
    ucp.put("version", UcpProperties.UCP_VERSION);
    ucp.put("status", "error");
    ObjectNode message = body.putArray("messages").addObject();
    message.put("type", "error");
    message.put("code", code);
    message.put("content", content);
    message.put("severity", severity.wireValue());
    return body;
  }

  /** Builds the envelope body for a {@link UcpException}. */
  public static ObjectNode of(UcpException error) {
    return of(error.code(), error.getMessage(), error.severity());
  }

  /** Writes an envelope straight to a servlet response (for filters, outside MVC). */
  public static void write(
      HttpServletResponse response, int status, ObjectNode body, JsonMapper json)
      throws IOException {
    byte[] bytes = json.writeValueAsBytes(body);
    response.setStatus(status);
    response.setContentType("application/json");
    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
    response.setContentLength(bytes.length);
    response.getOutputStream().write(bytes);
  }
}
