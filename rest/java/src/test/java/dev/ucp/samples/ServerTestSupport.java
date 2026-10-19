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

package dev.ucp.samples;

import static org.assertj.core.api.Assertions.assertThat;

import dev.ucp.samples.config.UcpProperties;
import dev.ucp.samples.signing.ProfileKeyResolver;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/** Boots the real server on a random port with throwaway databases, plus an HTTP client. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public abstract class ServerTestSupport {

  private static final Path DB_DIR = createDbDir();

  @DynamicPropertySource
  static void databases(DynamicPropertyRegistry registry) {
    registry.add("ucp.products-db-path", () -> DB_DIR.resolve("products.db").toString());
    registry.add("ucp.transactions-db-path", () -> DB_DIR.resolve("transactions.db").toString());
  }

  protected static final JsonMapper JSON = JsonMapper.builder().build();
  protected static final HttpClient HTTP = HttpClient.newHttpClient();

  @LocalServerPort protected int port;
  @Autowired protected UcpProperties properties;
  @Autowired protected ProfileKeyResolver keyResolver;

  /** A response's status, headers, and parsed JSON body. */
  public record Response(int status, Map<String, String> headers, JsonNode body) {
    public String header(String name) {
      return headers.get(name.toLowerCase());
    }
  }

  @AfterEach
  void resetFlags() {
    properties.setRequireSignatures(false);
    properties.setAllowInsecureProfileUrls(false);
    keyResolver.clearCache();
  }

  protected String baseUrl() {
    return "http://localhost:" + port;
  }

  protected Response get(String path) {
    return send("GET", path, null, Map.of());
  }

  protected Response post(String path, Object body) {
    return send("POST", path, body, Map.of());
  }

  protected Response put(String path, Object body) {
    return send("PUT", path, body, Map.of());
  }

  /** Sends a request; a non-null body is serialized as JSON. */
  protected Response send(String method, String path, Object body, Map<String, String> headers) {
    byte[] bytes = body == null ? new byte[0] : JSON.writeValueAsBytes(body);
    Map<String, String> all = new LinkedHashMap<>();
    if (body != null) {
      all.put("Content-Type", "application/json");
    }
    all.putAll(headers);
    return sendRaw(method, path, bytes, all);
  }

  /** Sends a request with exact body bytes and headers. */
  protected Response sendRaw(String method, String path, byte[] body, Map<String, String> headers) {
    HttpRequest.Builder request =
        HttpRequest.newBuilder(URI.create(baseUrl() + path))
            .method(
                method,
                body.length == 0
                    ? HttpRequest.BodyPublishers.noBody()
                    : HttpRequest.BodyPublishers.ofByteArray(body));
    headers.forEach(request::header);
    try {
      HttpResponse<String> response =
          HTTP.send(request.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
      Map<String, String> responseHeaders = new LinkedHashMap<>();
      response.headers().map().forEach((k, v) -> responseHeaders.put(k.toLowerCase(), v.get(0)));
      JsonNode parsed =
          response.body().isEmpty() ? JSON.nullNode() : JSON.readTree(response.body());
      return new Response(response.statusCode(), responseHeaders, parsed);
    } catch (IOException e) {
      throw new RuntimeException(e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new RuntimeException(e);
    }
  }

  /** Parses a JSON literal (single quotes allowed for readability). */
  protected static ObjectNode json(String literal) {
    return (ObjectNode) JSON.readTree(literal.replace('\'', '"'));
  }

  /** Asserts the response is a UCP error envelope with the given status and code. */
  protected static void assertError(Response response, int status, String code) {
    assertThat(response.status()).as("status of %s", response.body()).isEqualTo(status);
    assertThat(response.body().path("ucp").path("status").asString()).isEqualTo("error");
    assertThat(response.body().path("messages").path(0).path("type").asString())
        .isEqualTo("error");
    assertThat(response.body().path("messages").path(0).path("code").asString()).isEqualTo(code);
  }

  private static Path createDbDir() {
    try {
      Path dir = Files.createTempDirectory("ucp-java-server-test");
      dir.toFile().deleteOnExit();
      return dir;
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
