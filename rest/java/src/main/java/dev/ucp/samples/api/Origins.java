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

import jakarta.servlet.http.HttpServletRequest;

/** Derives this server's public origin from the incoming request. */
final class Origins {

  private Origins() {}

  /** The request origin, e.g. {@code http://localhost:3000}. */
  static String of(HttpServletRequest request) {
    String host = request.getHeader("Host");
    if (host == null || host.isBlank()) {
      host = request.getServerName() + ":" + request.getServerPort();
    }
    return request.getScheme() + "://" + host;
  }
}
