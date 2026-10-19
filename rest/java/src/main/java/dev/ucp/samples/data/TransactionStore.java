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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Persistence for checkout sessions, orders, request logs, and idempotency records.
 *
 * <p>Checkouts and orders are stored as JSON documents, exactly like the Node.js server.
 */
@Component
public class TransactionStore {

  private static final Logger log = LoggerFactory.getLogger(TransactionStore.class);

  /** A stored idempotency record: the request fingerprint and the response it produced. */
  public record IdempotencyRecord(
      String key, String requestHash, int responseStatus, String responseBody) {}

  private final Connection db;
  private final JsonMapper json;

  public TransactionStore(Databases databases, JsonMapper json) {
    this.db = databases.transactions();
    this.json = json;
  }

  /** Inserts or updates a checkout session. */
  public void saveCheckout(String checkoutId, String status, JsonNode checkout) {
    synchronized (db) {
      try (PreparedStatement st =
          db.prepareStatement(
              "INSERT INTO checkouts (id, status, data) VALUES (?, ?, ?) "
                  + "ON CONFLICT(id) DO UPDATE SET status = excluded.status, data = excluded.data")) {
        st.setString(1, checkoutId);
        st.setString(2, status);
        st.setString(3, json.writeValueAsString(checkout));
        st.executeUpdate();
      } catch (SQLException e) {
        throw new DataAccessFailure(e);
      }
    }
  }

  /** Loads a checkout session, or empty if it does not exist or cannot be parsed. */
  public Optional<ObjectNode> getCheckoutSession(String checkoutId) {
    return readDocument("SELECT data FROM checkouts WHERE id = ?", checkoutId, "checkout");
  }

  /** Inserts or updates an order. */
  public void saveOrder(String orderId, JsonNode order) {
    synchronized (db) {
      try (PreparedStatement st =
          db.prepareStatement(
              "INSERT INTO orders (id, data) VALUES (?, ?) "
                  + "ON CONFLICT(id) DO UPDATE SET data = excluded.data")) {
        st.setString(1, orderId);
        st.setString(2, json.writeValueAsString(order));
        st.executeUpdate();
      } catch (SQLException e) {
        throw new DataAccessFailure(e);
      }
    }
  }

  /** Loads an order, or empty if it does not exist or cannot be parsed. */
  public Optional<ObjectNode> getOrder(String orderId) {
    return readDocument("SELECT data FROM orders WHERE id = ?", orderId, "order");
  }

  /** Appends an entry to the request log. */
  public void logRequest(String method, String url, String checkoutId, JsonNode payload) {
    synchronized (db) {
      try (PreparedStatement st =
          db.prepareStatement(
              "INSERT INTO request_logs (method, url, checkout_id, payload) VALUES (?, ?, ?, ?)")) {
        st.setString(1, method);
        st.setString(2, url);
        st.setString(3, checkoutId);
        st.setString(4, json.writeValueAsString(payload));
        st.executeUpdate();
      } catch (SQLException e) {
        throw new DataAccessFailure(e);
      }
    }
  }

  /** Loads the idempotency record stored under a key. */
  public Optional<IdempotencyRecord> getIdempotencyRecord(String key) {
    synchronized (db) {
      try (PreparedStatement st =
          db.prepareStatement(
              "SELECT key, request_hash, response_status, response_body "
                  + "FROM idempotency_keys WHERE key = ?")) {
        st.setString(1, key);
        try (ResultSet rs = st.executeQuery()) {
          if (!rs.next()) {
            return Optional.empty();
          }
          return Optional.of(
              new IdempotencyRecord(
                  rs.getString(1), rs.getString(2), rs.getInt(3), rs.getString(4)));
        }
      } catch (SQLException e) {
        throw new DataAccessFailure(e);
      }
    }
  }

  /** Stores the response produced for an idempotency key. */
  public void saveIdempotencyRecord(String key, String requestHash, int status, String body) {
    synchronized (db) {
      try (PreparedStatement st =
          db.prepareStatement(
              "INSERT OR REPLACE INTO idempotency_keys "
                  + "(key, request_hash, response_status, response_body) VALUES (?, ?, ?, ?)")) {
        st.setString(1, key);
        st.setString(2, requestHash);
        st.setInt(3, status);
        st.setString(4, body);
        st.executeUpdate();
      } catch (SQLException e) {
        throw new DataAccessFailure(e);
      }
    }
  }

  private Optional<ObjectNode> readDocument(String sql, String id, String kind) {
    String data;
    synchronized (db) {
      try (PreparedStatement st = db.prepareStatement(sql)) {
        st.setString(1, id);
        try (ResultSet rs = st.executeQuery()) {
          if (!rs.next()) {
            return Optional.empty();
          }
          data = rs.getString(1);
        }
      } catch (SQLException e) {
        throw new DataAccessFailure(e);
      }
    }
    try {
      JsonNode node = json.readTree(data);
      return node instanceof ObjectNode object ? Optional.of(object) : Optional.empty();
    } catch (JacksonException e) {
      log.error("Failed to parse {} data for {}", kind, id, e);
      return Optional.empty();
    }
  }
}
