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

package dev.ucp.samples.signing;

import dev.ucp.samples.config.UcpProperties;
import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import tools.jackson.databind.node.ObjectNode;

/**
 * The business's webhook-signing identity.
 *
 * <p>Order-event webhooks MUST be signed by the business (order.md, Webhook Signature
 * Verification) with a key the business publishes in its profile's {@code signing_keys[]}.
 *
 * <ul>
 *   <li>WEBHOOK_SIGNING_KEY loads an operator-provided PEM private key (EC P-256 for ES256, or
 *       Ed25519; PKCS#8 or SEC1). When unset, an ephemeral demo key is generated at startup --
 *       the server signs correctly out of the box and no private-key file lives in the repository.
 *   <li>The kid is the RFC 7638 JWK thumbprint of the public key, so the same key always
 *       republishes under the same identifier across restarts.
 * </ul>
 *
 * <p>The key is loaded when the bean is created, so a misconfigured WEBHOOK_SIGNING_KEY aborts
 * the boot loudly instead of silently degrading every webhook delivery.
 */
@Component
public class WebhookSigningKey {

  private final PrivateKey privateKey;
  private final PublicKey publicKey;
  private final String kid;

  public WebhookSigningKey(UcpProperties properties) {
    KeyPair pair =
        StringUtils.hasText(properties.getWebhookSigningKey())
            ? load(Path.of(properties.getWebhookSigningKey()))
            : generateEphemeral();
    this.privateKey = pair.getPrivate();
    this.publicKey = pair.getPublic();
    this.kid = Jwks.thumbprint(publicKey);
  }

  public PrivateKey privateKey() {
    return privateKey;
  }

  public String kid() {
    return kid;
  }

  /** The public JWK to publish in the profile's {@code signing_keys[]}. */
  public ObjectNode publicJwk() {
    return Jwks.fromPublicKey(publicKey, kid);
  }

  private static KeyPair generateEphemeral() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(new ECGenParameterSpec("secp256r1"));
      return generator.generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Cannot generate an ephemeral P-256 key", e);
    }
  }

  /**
   * Loads a PEM private key and derives its public key. A path that cannot be read or holds an
   * unsupported key type fails loudly -- silently signing with a different identity than the
   * operator configured would be wrong.
   */
  static KeyPair load(Path path) {
    PrivateKeyInfo info;
    try (Reader reader = Files.newBufferedReader(path);
        PEMParser parser = new PEMParser(reader)) {
      Object pem = parser.readObject();
      if (pem instanceof PEMKeyPair keyPair) {
        info = keyPair.getPrivateKeyInfo();
      } else if (pem instanceof PrivateKeyInfo privateKeyInfo) {
        info = privateKeyInfo;
      } else {
        throw new IllegalStateException(
            "WEBHOOK_SIGNING_KEY must be a PEM private key; found "
                + (pem == null ? "nothing" : pem.getClass().getSimpleName()));
      }
    } catch (IOException e) {
      throw new IllegalStateException("Cannot read WEBHOOK_SIGNING_KEY " + path, e);
    }

    try {
      // Re-encode through Bouncy Castle so SEC1 keys (curve parameters inside the key) become
      // the PKCS#8 form the JDK's KeyFactory expects (curve in the algorithm identifier).
      AsymmetricKeyParameter keyParameters = PrivateKeyFactory.createKey(info);
      info = PrivateKeyInfoFactory.createPrivateKeyInfo(keyParameters);
      var algorithm = info.getPrivateKeyAlgorithm().getAlgorithm();
      String jcaName;
      if (algorithm.equals(X9ObjectIdentifiers.id_ecPublicKey)) {
        jcaName = "EC";
      } else if (algorithm.equals(EdECObjectIdentifiers.id_Ed25519)) {
        jcaName = "Ed25519";
      } else {
        throw new IllegalStateException(
            "WEBHOOK_SIGNING_KEY must be EC P-256 (ES256) or Ed25519; got " + algorithm);
      }
      KeyFactory factory = KeyFactory.getInstance(jcaName);
      PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(info.getEncoded()));
      if (privateKey instanceof ECPrivateKey ec && !Jwks.isP256(ec.getParams())) {
        throw new IllegalStateException(
            "WEBHOOK_SIGNING_KEY must be EC P-256 (ES256) or Ed25519; got an EC key on a "
                + ec.getParams().getCurve().getField().getFieldSize()
                + "-bit curve other than P-256");
      }
      byte[] spki =
          SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(derivePublic(keyParameters))
              .getEncoded();
      PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(spki));
      return new KeyPair(publicKey, privateKey);
    } catch (IOException | GeneralSecurityException e) {
      throw new IllegalStateException("Cannot load WEBHOOK_SIGNING_KEY " + path, e);
    }
  }

  private static AsymmetricKeyParameter derivePublic(AsymmetricKeyParameter key) {
    if (key instanceof Ed25519PrivateKeyParameters ed) {
      return ed.generatePublicKey();
    }
    if (key instanceof ECPrivateKeyParameters ec) {
      BigInteger d = ec.getD();
      return new ECPublicKeyParameters(
          ec.getParameters().getG().multiply(d).normalize(), ec.getParameters());
    }
    throw new IllegalStateException("Unsupported key " + key.getClass().getSimpleName());
  }
}
