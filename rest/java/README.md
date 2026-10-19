<!--
   Copyright 2026 UCP Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
-->

# UCP Java Server Reference Implementation

This directory contains a reference implementation of a Universal Commerce
Protocol (UCP) merchant server built with Java, Spring Boot and SQLite. It
implements the same flower-shop merchant as the
[Node.js server](../nodejs/README.md): capability discovery, checkout session
management, payment processing, order lifecycle, RFC 9421 request signatures,
and signed order webhooks.

## Prerequisites

- Java 17 or later (the Gradle wrapper downloads Gradle itself)

## Setup

1.  **Clone this repo**

    ```shell
    git clone https://github.com/Universal-Commerce-Protocol/samples.git
    cd samples/rest/java
    ```

2.  **Database Setup**

    Nothing to do. The server uses SQLite and, on startup, creates the
    `databases/products.db` and `databases/transactions.db` files with their
    tables and seeds the flower-shop catalog and stock levels (the same data
    the Node.js server ships). Seeding never overwrites existing rows, so stock
    consumed by completed checkouts survives a restart. Delete the `databases`
    directory to start over.

## Running the Server

To start the server in development mode:

```bash
./gradlew bootRun
```

To build an executable jar and run it:

```bash
./gradlew bootJar
java -jar build/libs/ucp-java-server.jar
```

The server starts on port **3000** by default. You can access the discovery
endpoint at:

```
http://localhost:3000/.well-known/ucp
```

A first checkout, end to end:

```bash
curl -s -X POST http://localhost:3000/checkout-sessions \
  -H 'Content-Type: application/json' \
  -d '{
    "line_items": [{"item": {"id": "bouquet_roses"}, "quantity": 1}],
    "buyer": {"email": "john.doe@example.com"},
    "fulfillment": {"methods": [{"type": "shipping", "selected_destination_id": "addr_1"}]},
    "discounts": {"codes": ["10OFF"]}
  }'
```

## Configuration

The server reads the same environment variables as the Node.js and Python
reference servers:

| Variable                      | Default                     | Effect                                                                                                                                                                                                             |
| ----------------------------- | --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `PORT`                        | `3000`                      | HTTP port.                                                                                                                                                                                                         |
| `REQUIRE_SIGNATURES`          | `false`                     | Reject requests whose signature is missing or invalid. When `false`, a present signature is still verified and the result logged, but unsigned or invalid requests are allowed — so existing clients keep working. |
| `ALLOW_INSECURE_PROFILE_URLS` | `false`                     | Permit `http` and loopback/private profile URLs when resolving keys. For localhost demos and CI only; it disables SSRF protections and must never be enabled in production.                                        |
| `WEBHOOK_SIGNING_KEY`         | (ephemeral)                 | Path to a PEM private key (EC P-256 or Ed25519, PKCS#8 or SEC1) to sign webhooks with. When unset, an ephemeral demo key is generated at startup and published in the profile.                                     |
| `SIMULATION_SECRET`           | `super-secret-sim-key`      | Value the `Simulation-Secret` header must carry on `/testing/*` endpoints.                                                                                                                                         |
| `PRODUCTS_DB_PATH`            | `databases/products.db`     | SQLite file holding the product catalog.                                                                                                                                                                           |
| `TRANSACTIONS_DB_PATH`        | `databases/transactions.db` | SQLite file holding inventory, checkouts, orders, request logs and idempotency keys.                                                                                                                               |

## Request Signatures (RFC 9421)

The server verifies UCP request signatures as defined in the specification's
[`signatures.md`](https://github.com/Universal-Commerce-Protocol/ucp/blob/main/docs/specification/signatures.md):
[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) HTTP Message Signatures
with an [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html) `Content-Digest`
over the raw body. The signer's public key is discovered from the profile URL in
the `UCP-Agent` header (its top-level `signing_keys[]`). `ES256` (fixed-width
raw `r||s`, not ASN.1/DER) is the baseline; `Ed25519` is also supported. Only
the JDK's built-in crypto providers are used for signing and verification.

When verification fails under enforcement, the server returns the spec's error
code: `401 signature_missing` / `signature_invalid` / `key_not_found`,
`400 digest_mismatch` / `algorithm_unsupported` / `invalid_profile_url`,
`424 profile_unreachable`, or `422 profile_malformed`.

To reject anything unsigned, start the server with enforcement on:

```bash
REQUIRE_SIGNATURES=true ./gradlew bootRun
```

Each verified request logs
`RFC 9421 signature verified (keyid=..., profile=...)`. The discovery profile
at `/.well-known/ucp` stays unverified: it is the public document a platform
must read before it can sign anything.

## Webhook Signing

Outbound order-event webhooks (`order_placed`, `order_shipped`) are signed as
the business, per the specification's `order.md` (Webhook Signature
Verification): every delivery carries `UCP-Agent` (this server's profile URL),
`Signature`, `Signature-Input`, and a `Content-Digest` over the exact raw body
bytes. The signed components cover the request-signing table plus the Standard
Webhooks event headers (`webhook-id`, `webhook-timestamp`) and `x-event-type`.
The matching public JWK is published in the served profile's `signing_keys[]`,
with the RFC 7638 thumbprint as its `kid`. Retried deliveries reuse the same
`Webhook-Id` and `Idempotency-Key` and are re-signed per attempt.

The platform's webhook URL is read from the `dev.ucp.shopping.order`
capability's `config.webhook_url` in the profile its `UCP-Agent` header points
to (an `https` URL or a `data:` URI).

## Running the Tests

```bash
./gradlew test
```

The tests boot the server on a random port against throwaway databases and
drive it over HTTP: the checkout lifecycle, idempotency, validation, the error
envelope, discovery, request-signature enforcement, and signed webhook
delivery.

## Running Conformance Tests

To verify that this server implementation complies with the UCP specifications,
use the official
[UCP Conformance Test Suite](https://github.com/Universal-Commerce-Protocol/conformance).
Follow the instructions in that repository and point it at:

```
http://localhost:3000
```

## Project Structure

- `src/main/java/dev/ucp/samples/api`: REST controllers (Discovery, Checkout,
  Order, Testing).
- `src/main/java/dev/ucp/samples/service`: Checkout business logic, request
  validation, platform profiles, and webhook delivery.
- `src/main/java/dev/ucp/samples/signing`: RFC 9421 signing and verification,
  JWK conversion, profile key resolution, and the webhook signing key.
- `src/main/java/dev/ucp/samples/web`: Servlet filters (body buffering, version
  negotiation, signature verification).
- `src/main/java/dev/ucp/samples/data`: SQLite access layer.
- `src/main/java/dev/ucp/samples/error`: The UCP error envelope.
- `src/main/resources/seed`: Catalog and inventory seed data.
