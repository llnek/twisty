/* Licensed under the Apache License, Version 2.0 (the "License");
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
 *
 * Copyright (c) 2013-2016, Kenneth Leung. All rights reserved. */

package czlab.crypto;

import java.security.cert.X509Certificate;
import java.security.cert.Certificate;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;


/**
 * Abstraction of a key store.
 *
 * @author Kenneth Leung
 *
 */
public interface CryptoStoreAPI {

  /**
   * Get the private key.
   */
  public PKeyGist keyEntity(String alias, char[] pwd);

  /**
   * Get the only private key.
   */
  public PKeyGist keyEntity(char[] pwd);

  /**
   * Get the certificate.
   */
  public Certificate certEntity(String alias);

  /**/
  public Iterable<X509Certificate> intermediateCAs();

  /**/
  public Iterable<X509Certificate> rootCAs();

  /**/
  public Iterable<X509Certificate> trustedCerts();

  /**
   * Add a private key.
   */
  public void addKeyEntity(PKeyGist gist, char[] pwd);

  /**/
  public TrustManagerFactory trustManagerFactory();

  /**/
  public KeyManagerFactory keyManagerFactory();

  /**/
  public Iterable<String> certAliases();

  /**/
  public Iterable<String> keyAliases();

  /**
   * Add a certificate.
   */
  public void addCertEntity(Certificate cert);

  /**
   * Add a PKCS7 object.
   */
  public void addPKCS7Entity(byte[] pkcs7Bits);

  /**
   * Remove object from store.
   */
  public void removeEntity(String alias);

}


