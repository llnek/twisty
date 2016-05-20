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
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;


/**
 * Abstraction on top of a java key store.
 *
 * @author kenl
 *
 */
public interface CryptoStoreAPI {

  /**
   * Add a private key.
   *
   * @param keyBits
   * @param pwdObj
   */
  public void addKeyEntity(byte[] keyBits, PasswordAPI pwdObj);

  public TrustManagerFactory trustManagerFactory();
  public KeyManagerFactory keyManagerFactory();

  public Iterable<String> certAliases();
  public Iterable<String> keyAliases();

  /**
   * Add a certificate.
   *
   * @param certBits
   */
  public void addCertEntity(byte[] certBits);

  /**
   *
   * @param alias
   * @param pwdObj
   * @return
   */
  public KeyStore.PrivateKeyEntry keyEntity(String alias, PasswordAPI pwdObj);

  /**
   *
   * @param alias
   * @return
   */
  public KeyStore.TrustedCertificateEntry certEntity(String alias);

  public Iterable<X509Certificate> intermediateCAs();
  public Iterable<X509Certificate> rootCAs();
  public Iterable<X509Certificate> trustedCerts();

  /**
   *
   * @param pkcs7Bits
   */
  public void addPKCS7Entity(byte[] pkcs7Bits);

  /**
   *
   * @param alias
   */
  public void removeEntity(String alias);

}


