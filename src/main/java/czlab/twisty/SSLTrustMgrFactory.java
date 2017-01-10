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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManagerFactorySpi;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * A simple trust manager.
 *
 * @author Kenneth Leung
 *
 */
@SuppressWarnings("unused")
public abstract class SSLTrustMgrFactory extends TrustManagerFactorySpi {

  @Override
  public void engineInit(ManagerFactoryParameters p) {}

  @Override
  public void engineInit(KeyStore ks) {}

  public static void main(String[] args) {
    try {
      Security.addProvider(new BouncyCastleProvider());
      KeyStore s= KeyStore.getInstance("PKCS12", "BC");
      ByteArrayOutputStream baos= new ByteArrayOutputStream();
      s.load(null, null);
      try (InputStream inp= new FileInputStream("servercert.pem")) {
        CertificateFactory fac= CertificateFactory.getInstance( "X.509");
        Object cp= fac.generateCertificates(inp);
        Object obj= fac.getCertPathEncodings().next();

//        s.setCertificateEntry("aaa", c);
//        s.store(baos, "sesame".toCharArray());
//        //Object e= s.aliases();
        System.out.println( s.toString());
      }
      byte[] out= baos.toByteArray();
      ByteArrayInputStream inp= new ByteArrayInputStream(out);
      s= KeyStore.getInstance("PKCS12", "BC");
      s.load(inp, "sesame".toCharArray());
      Certificate c= s.getCertificate("aaa");
      System.out.println( c.toString());
      out=null;
    }
    catch (Throwable t) {
      t.printStackTrace();
    }
  }
}


