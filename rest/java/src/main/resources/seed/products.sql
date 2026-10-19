-- Copyright 2026 UCP Authors
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- The flower-shop catalog, identical to rest/nodejs/databases/products.db.
INSERT OR IGNORE INTO products (id, title, price, image_url) VALUES
  ('bouquet_roses', 'Bouquet of Red Roses', 3500, 'https://example.com/roses.jpg'),
  ('pot_ceramic', 'Ceramic Pot', 1500, 'https://example.com/pot.jpg'),
  ('bouquet_sunflowers', 'Sunflower Bundle', 2500, 'https://example.com/sunflowers.jpg'),
  ('bouquet_tulips', 'Spring Tulips', 3000, 'https://example.com/tulips.jpg'),
  ('orchid_white', 'White Orchid', 4500, 'https://example.com/orchid.jpg'),
  ('gardenias', 'Gardenias', 2000, 'https://example.com/gardenias.jpg');
