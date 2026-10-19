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

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * A request whose body has been read into memory up front, so it can be read again: the
 * signature filter needs the exact raw bytes for the Content-Digest check, and the controllers
 * still need to parse them afterwards.
 */
public class CachedBodyRequest extends HttpServletRequestWrapper {

  private final byte[] body;

  public CachedBodyRequest(HttpServletRequest request) throws IOException {
    super(request);
    this.body = request.getInputStream().readAllBytes();
  }

  /** The raw request body bytes. */
  public byte[] body() {
    return body;
  }

  /**
   * The request headers keyed by lowercase name. Repeated headers are joined with {@code ", "},
   * which is how RFC 9110 combines field lines (and what the Fetch API's Headers does).
   */
  public Map<String, String> lowercaseHeaders() {
    Map<String, String> headers = new LinkedHashMap<>();
    for (String name : Collections.list(getHeaderNames())) {
      headers.put(
          name.toLowerCase(Locale.ROOT), String.join(", ", Collections.list(getHeaders(name))));
    }
    return headers;
  }

  @Override
  public ServletInputStream getInputStream() {
    ByteArrayInputStream in = new ByteArrayInputStream(body);
    return new ServletInputStream() {
      @Override
      public int read() {
        return in.read();
      }

      @Override
      public int read(byte[] b, int off, int len) {
        return in.read(b, off, len);
      }

      @Override
      public boolean isFinished() {
        return in.available() == 0;
      }

      @Override
      public boolean isReady() {
        return true;
      }

      @Override
      public void setReadListener(ReadListener listener) {
        throw new UnsupportedOperationException("Async reads are not supported");
      }
    };
  }

  @Override
  public BufferedReader getReader() {
    String encoding = getCharacterEncoding();
    Charset charset = encoding != null ? Charset.forName(encoding) : StandardCharsets.UTF_8;
    return new BufferedReader(new InputStreamReader(getInputStream(), charset));
  }
}
