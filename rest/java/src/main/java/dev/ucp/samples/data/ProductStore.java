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
import org.springframework.stereotype.Component;

/** Read access to the product catalog. */
@Component
public class ProductStore {

  /** A catalog product. The price is in minor units (cents). */
  public record Product(String id, String title, long price, String imageUrl) {}

  private final Connection db;

  public ProductStore(Databases databases) {
    this.db = databases.products();
  }

  /** Looks up a product by id. */
  public Optional<Product> getProduct(String productId) {
    synchronized (db) {
      try (PreparedStatement st =
          db.prepareStatement("SELECT id, title, price, image_url FROM products WHERE id = ?")) {
        st.setString(1, productId);
        try (ResultSet rs = st.executeQuery()) {
          if (!rs.next()) {
            return Optional.empty();
          }
          return Optional.of(
              new Product(
                  rs.getString("id"),
                  rs.getString("title"),
                  rs.getLong("price"),
                  rs.getString("image_url")));
        }
      } catch (SQLException e) {
        throw new DataAccessFailure(e);
      }
    }
  }

  /** Inserts or replaces a product (used by tests). */
  public void upsertProduct(Product product) {
    synchronized (db) {
      try (PreparedStatement st =
          db.prepareStatement(
              "INSERT OR REPLACE INTO products (id, title, price, image_url) VALUES (?, ?, ?, ?)")) {
        st.setString(1, product.id());
        st.setString(2, product.title());
        st.setLong(3, product.price());
        st.setString(4, product.imageUrl());
        st.executeUpdate();
      } catch (SQLException e) {
        throw new DataAccessFailure(e);
      }
    }
  }
}
