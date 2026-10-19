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

package dev.ucp.samples.data;

import dev.ucp.samples.config.UcpProperties;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.stereotype.Component;

/**
 * Owns the two SQLite connections (products and transactions), creates the tables on startup,
 * and seeds the flower-shop catalog.
 *
 * <p>The schema matches the Node.js server ({@code src/data/db.ts}). SQLite serializes writers
 * anyway, so each database uses a single connection and callers synchronize on it.
 */
@Component
public class Databases implements DisposableBean {

  private final Connection products;
  private final Connection transactions;

  public Databases(UcpProperties properties) throws SQLException {
    this.products = open(properties.getProductsDbPath());
    this.transactions = open(properties.getTransactionsDbPath());
    initSchema();
    seed();
  }

  /** The products (catalog) database. */
  public Connection products() {
    return products;
  }

  /** The transactions database: inventory, checkouts, orders, logs, idempotency keys. */
  public Connection transactions() {
    return transactions;
  }

  private static Connection open(String path) throws SQLException {
    if (!":memory:".equals(path)) {
      Path parent = Path.of(path).toAbsolutePath().getParent();
      if (parent != null) {
        try {
          Files.createDirectories(parent);
        } catch (IOException e) {
          throw new UncheckedIOException("Cannot create database directory " + parent, e);
        }
      }
    }
    return DriverManager.getConnection("jdbc:sqlite:" + path);
  }

  private void initSchema() throws SQLException {
    try (Statement st = products.createStatement()) {
      st.execute(
          """
          CREATE TABLE IF NOT EXISTS products (
            id TEXT PRIMARY KEY,
            title TEXT,
            price INTEGER,
            image_url TEXT
          )""");
    }
    try (Statement st = transactions.createStatement()) {
      st.execute(
          """
          CREATE TABLE IF NOT EXISTS inventory (
            product_id TEXT PRIMARY KEY,
            quantity INTEGER DEFAULT 0
          )""");
      st.execute(
          """
          CREATE TABLE IF NOT EXISTS checkouts (
            id TEXT PRIMARY KEY,
            status TEXT,
            data TEXT
          )""");
      st.execute(
          """
          CREATE TABLE IF NOT EXISTS orders (
            id TEXT PRIMARY KEY,
            data TEXT
          )""");
      st.execute(
          """
          CREATE TABLE IF NOT EXISTS request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            method TEXT,
            url TEXT,
            checkout_id TEXT,
            payload TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
          )""");
      st.execute(
          """
          CREATE TABLE IF NOT EXISTS idempotency_keys (
            key TEXT PRIMARY KEY,
            request_hash TEXT,
            response_status INTEGER,
            response_body TEXT
          )""");
    }
  }

  /**
   * Seeds the flower-shop catalog and stock levels (the same rows the Node.js server ships in its
   * prebuilt databases). INSERT OR IGNORE keeps existing rows, so stock consumed by earlier runs
   * is not reset on restart.
   */
  private void seed() throws SQLException {
    runScript(products, "seed/products.sql");
    runScript(transactions, "seed/inventory.sql");
  }

  private static void runScript(Connection connection, String resource) throws SQLException {
    String script;
    try (InputStream in = Databases.class.getClassLoader().getResourceAsStream(resource)) {
      if (in == null) {
        throw new IllegalStateException("Missing seed resource " + resource);
      }
      script = new String(in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    String withoutComments =
        script.lines().filter(line -> !line.strip().startsWith("--")).reduce("", (a, b) -> a + b + "\n");
    try (Statement st = connection.createStatement()) {
      for (String sql : withoutComments.split(";")) {
        if (!sql.isBlank()) {
          st.execute(sql.strip());
        }
      }
    }
  }

  @Override
  public void destroy() throws SQLException {
    products.close();
    transactions.close();
  }
}
