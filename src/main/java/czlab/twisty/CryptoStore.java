/**
 * Copyright (c) 2013-2017, Kenneth Leung. All rights reserved.
 * The use and distribution terms for this software are covered by the
 * Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
 * which can be found in the file epl-v10.html at the root of this distribution.
 * By using this software in any fashion, you are agreeing to be bound by
 * the terms of this license.
 * You must not remove this notice, or any other, from this software.
 */

package czlab.twisty;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.OutputStream;


/**
 * Abstraction of a key store.
 *
 * @author Kenneth Leung
 *
 */
public interface CryptoStore {

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
  public void addPKCS7Entity(Object arg);

  /**
   * Remove object from store.
   */
  public void removeEntity(String alias);

  /**
   * Get the internal implementation.
   */
  public KeyStore intern();

  /**
   * Get the store password.
   */
  public char[] password();

  /**
   */
  public void write(OutputStream out, char[] pwd);

  /**
   */
  public void write(OutputStream out);

}


