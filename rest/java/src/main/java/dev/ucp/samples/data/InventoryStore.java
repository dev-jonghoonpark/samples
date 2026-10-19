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
import java.util.OptionalLong;
import org.springframework.stereotype.Component;

/** Stock levels, with atomic reserve and release. */
@Component
public class InventoryStore {

  private final Connection db;

  public InventoryStore(Databases databases) {
    this.db = databases.transactions();
  }

  /** The available quantity for a product, or empty if the product has no inventory row. */
  public OptionalLong getInventory(String productId) {
    synchronized (db) {
      try (PreparedStatement st =
          db.prepareStatement("SELECT quantity FROM inventory WHERE product_id = ?")) {
        st.setString(1, productId);
        try (ResultSet rs = st.executeQuery()) {
          return rs.next() ? OptionalLong.of(rs.getLong(1)) : OptionalLong.empty();
        }
      } catch (SQLException e) {
        throw new DataAccessFailure(e);
      }
    }
  }

  /**
   * Decrements the stock only if enough is available. A single UPDATE is atomic in SQLite.
   *
   * @return true if the stock was reserved, false if there was insufficient stock
   */
  public boolean reserveStock(String productId, long quantity) {
    synchronized (db) {
      try (PreparedStatement st =
          db.prepareStatement(
              "UPDATE inventory SET quantity = quantity - ? WHERE product_id = ? AND quantity >= ?")) {
        st.setLong(1, quantity);
        st.setString(2, productId);
        st.setLong(3, quantity);
        return st.executeUpdate() > 0;
      } catch (SQLException e) {
        throw new DataAccessFailure(e);
      }
    }
  }

  /** Returns reserved stock to the inventory (rollbacks and cancellations). */
  public void releaseStock(String productId, long quantity) {
    synchronized (db) {
      try (PreparedStatement st =
          db.prepareStatement("UPDATE inventory SET quantity = quantity + ? WHERE product_id = ?")) {
        st.setLong(1, quantity);
        st.setString(2, productId);
        st.executeUpdate();
      } catch (SQLException e) {
        throw new DataAccessFailure(e);
      }
    }
  }

  /** Sets the stock level of a product (used by tests). */
  public void setInventory(String productId, long quantity) {
    synchronized (db) {
      try (PreparedStatement st =
          db.prepareStatement(
              "INSERT OR REPLACE INTO inventory (product_id, quantity) VALUES (?, ?)")) {
        st.setString(1, productId);
        st.setLong(2, quantity);
        st.executeUpdate();
      } catch (SQLException e) {
        throw new DataAccessFailure(e);
      }
    }
  }
}
