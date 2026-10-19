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

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * A tiny HTTP server for tests: serves fixed JSON documents (signer profiles) and records every
 * request it receives (webhook deliveries).
 */
final class StubServer implements AutoCloseable {

  /** A request the stub received. Header names are lowercase. */
  record Received(String method, String path, Map<String, String> headers, byte[] body) {}

  private final HttpServer server;
  private final Map<String, String> documents = new ConcurrentHashMap<>();
  private final BlockingQueue<Received> received = new LinkedBlockingQueue<>();

  StubServer() {
    try {
      server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    server.createContext(
        "/",
        exchange -> {
          byte[] body = exchange.getRequestBody().readAllBytes();
          Map<String, String> headers =
              exchange.getRequestHeaders().entrySet().stream()
                  .collect(
                      Collectors.toMap(
                          e -> e.getKey().toLowerCase(Locale.ROOT),
                          e -> String.join(", ", e.getValue()),
                          (a, b) -> a));
          String path = exchange.getRequestURI().getRawPath();
          received.add(new Received(exchange.getRequestMethod(), path, headers, body));
          String document = documents.get(path);
          byte[] response =
              (document != null ? document : "{}").getBytes(StandardCharsets.UTF_8);
          exchange.getResponseHeaders().put("Content-Type", List.of("application/json"));
          boolean found = document != null || "POST".equals(exchange.getRequestMethod());
          exchange.sendResponseHeaders(found ? 200 : 404, response.length);
          exchange.getResponseBody().write(response);
          exchange.close();
        });
    server.start();
  }

  /** Serves a JSON document at a path. */
  void serve(String path, String json) {
    documents.put(path, json);
  }

  /** The stub's base URL, e.g. {@code http://127.0.0.1:54321}. */
  String url() {
    return "http://127.0.0.1:" + server.getAddress().getPort();
  }

  int port() {
    return server.getAddress().getPort();
  }

  /** Waits for the next received request matching a method and path. */
  Received await(String method, String path) throws InterruptedException {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (System.nanoTime() < deadline) {
      Received next = received.poll(100, TimeUnit.MILLISECONDS);
      if (next != null && next.method().equals(method) && next.path().equals(path)) {
        return next;
      }
    }
    throw new AssertionError("No " + method + " " + path + " received");
  }

  @Override
  public void close() {
    server.stop(0);
  }
}
