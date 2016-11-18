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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.KeyStore;
import java.security.Security;
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
      try (InputStream inp= new FileInputStream("/wdrive/myspace/crypto/artifacts/servercert.pem")) {
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
      out=out;
    }
    catch (Throwable t) {
      t.printStackTrace();
    }
  }
}


