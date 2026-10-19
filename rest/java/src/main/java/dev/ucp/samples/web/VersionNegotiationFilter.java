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

package dev.ucp.samples.web;

import dev.ucp.samples.config.UcpProperties;
import dev.ucp.samples.error.ErrorEnvelope;
import dev.ucp.samples.error.UcpException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.json.JsonMapper;

/**
 * Rejects requests from platforms that require a newer UCP version than this server implements,
 * using the {@code version="YYYY-MM-DD"} parameter of the {@code UCP-Agent} header.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class VersionNegotiationFilter extends OncePerRequestFilter {

  private static final Pattern VERSION = Pattern.compile("version=\"([^\"]+)\"");

  private final JsonMapper json;

  public VersionNegotiationFilter(JsonMapper json) {
    this.json = json;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String ucpAgent = request.getHeader("UCP-Agent");
    if (ucpAgent != null) {
      Matcher match = VERSION.matcher(ucpAgent);
      if (match.find()) {
        String clientVersion = match.group(1);
        // Versions are ISO dates, so lexicographic order is chronological order.
        if (clientVersion.compareTo(UcpProperties.UCP_VERSION) > 0) {
          ErrorEnvelope.write(
              response,
              422,
              ErrorEnvelope.of(
                  "VERSION_UNSUPPORTED",
                  "Version "
                      + clientVersion
                      + " is not supported. This merchant implements version "
                      + UcpProperties.UCP_VERSION
                      + ".",
                  UcpException.Severity.UNRECOVERABLE),
              json);
          return;
        }
      }
    }
    chain.doFilter(request, response);
  }
}
