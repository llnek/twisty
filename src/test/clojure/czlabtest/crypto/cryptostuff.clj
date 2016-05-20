;;
;; Licensed under the Apache License, Version 2.0 (the "License");
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.
;;
;; Copyright (c) 2013-2016, Kenneth Leung. All rights reserved.
;;


(ns

  testcljc.crypto.cryptostuff

  (:use [czlab.xlib.crypto.stores]
        [czlab.xlib.crypto.codec]
        [czlab.xlib.util.core]
        [czlab.xlib.util.str]
        [czlab.xlib.util.io]
        [clojure.test]
        [czlab.xlib.crypto.core])

  (:import  [java.security KeyPair Policy KeyStore SecureRandom MessageDigest
                           KeyStore$PrivateKeyEntry KeyStore$TrustedCertificateEntry]
            [org.apache.commons.codec.binary Base64]
            [com.zotohlab.frwk.crypto Cryptor CryptoStoreAPI PasswordAPI]
            [java.util Date GregorianCalendar]
            [java.io File]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(def ^:private ROOTPFX (ResBytes "com/zotohlab/frwk/crypto/test.pfx"))
(def ^:private ROOTJKS (ResBytes "com/zotohlab/frwk/crypto/test.jks"))
(def ^:private ENDDT (.getTime (GregorianCalendar. 2050 1 1)))
(def ^:private TESTPWD (Pwdify "secretsecretsecretsecretsecret"))
(def ^:private HELPME (Pwdify "helpme"))
(def ^:private SECRET (Pwdify "secret"))

(def ^CryptoStoreAPI ^:private ROOTCS (CryptoStore* (InitStore! (GetPkcsStore) ROOTPFX HELPME) HELPME))

(def ^CryptoStoreAPI ^:private ROOTKS (CryptoStore* (InitStore! (GetJksStore) ROOTJKS HELPME) HELPME))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(deftest testcrypto-cryptostuff

(is (not (= "heeloo, how are you?" (CaesarDecrypt (CaesarEncrypt "heeloo, how are you?" 709394) 666))))
(is (= "heeloo, how are you?" (CaesarDecrypt (CaesarEncrypt "heeloo, how are you?" 709394) 709394)))
(is (= "heeloo, how are you?" (CaesarDecrypt (CaesarEncrypt "heeloo, how are you?" 13) 13)))

(is (= "heeloo" (let [ c (JasyptCryptor*) ]
                      (.decrypt c (.encrypt c "heeloo")))))

(is (= "heeloo" (let [ c (JasyptCryptor*) pkey (.toCharArray (nsb SECRET)) ]
                      (.decrypt c pkey (.encrypt c pkey "heeloo")))))

(is (= "heeloo" (let [ c (JavaCryptor*) ]
                      (Stringify (.decrypt c (.encrypt c "heeloo"))))))

(is (= "heeloo" (let [ c (JavaCryptor*) pkey (Bytesify (nsb TESTPWD)) ]
                      (Stringify (.decrypt c pkey (.encrypt c pkey "heeloo"))))))

(is (= "heeloo" (let [ c (BouncyCryptor*) ]
                      (Stringify (.decrypt c (.encrypt c "heeloo"))))))

(is (= "heeloo" (let [ c (BouncyCryptor*) pkey (Bytesify (nsb TESTPWD)) ]
                      (Stringify (.decrypt c pkey (.encrypt c pkey "heeloo"))))))

(is (= "heeloo" (let [ pkey (Bytesify (nsb TESTPWD)) ]
                      (Stringify (BcDecr pkey (BcEncr pkey "heeloo" "AES") "AES")))))

(is (= "heeloo" (let [ kp (AsymKeyPair*  "RSA" 1024)
                       pu (.getEncoded (.getPublic kp))
                       pv (.getEncoded (.getPrivate kp)) ]
                      (Stringify (AsymDecr pv (AsymEncr pu (Bytesify "heeloo")))))))

(is (= (.length ^String (.text (StrongPwd* 16))) 16))
(is (= (.length (RandomStr* 64)) 64))

(is (instance? PasswordAPI (Pwdify "secret-text")))
(is (.startsWith ^String (.encoded ^PasswordAPI (Pwdify "secret-text")) "CRYPT:"))


(is (= "SHA-512" (.getAlgorithm (MsgDigest* SHA_512))))
(is (= "MD5" (.getAlgorithm (MsgDigest* MD_5))))

(is (> (NextSerial) 0))

(is (> (.length (NewAlias)) 0))

(is (= "PKCS12" (.getType (GetPkcsStore))))
(is (= "JKS" (.getType (GetJksStore))))

(is (instance? Policy (EasyPolicy*)))

(is (> (.length (GenMac (Bytesify "secret") "heeloo world")) 0))
(is (> (.length (GenHash "heeloo world")) 0))

(is (not (nil? (AsymKeyPair* "RSA" 1024))))

(is (let [ v (CsrReQ* 1024 "C=AU,ST=NSW,L=Sydney,O=Google,OU=HQ,CN=www.google.com" :PEM) ]
          (and (= (count v) 2) (> (alength ^bytes (first v)) 0) (> (alength ^bytes (nth v 1)) 0))) )

(is (let [ fout (TempFile "kenl" ".p12")]
      (SSv1PKCS12* "C=AU,ST=NSW,L=Sydney,O=Google" HELPME fout
                          { :start (Date.) :end ENDDT :keylen 1024 })
      (> (.length fout) 0)))

(is (let [ fout (TempFile "x" ".jks") ]
      (SSv1JKS* "C=AU,ST=NSW,L=Sydney,O=Google" SECRET fout
                          { :start (Date.) :end ENDDT :keylen 1024 })
            (> (.length fout) 0)))

(is (let [ ^KeyStore$PrivateKeyEntry pke
          (.keyEntity ROOTCS ^String (first (.keyAliases ROOTCS))
                           HELPME)
       fout (TempFile "x" ".p12")
       pk (.getPrivateKey pke)
       cs (.getCertificateChain pke) ]
            (SSv3PKCS12* "C=AU,ST=NSW,L=Sydney,O=Google" SECRET fout
                                { :start (Date.) :end ENDDT :issuerCerts (seq cs) :issuerKey pk })
              (> (.length fout) 0)))

(is (let [ ^KeyStore$PrivateKeyEntry pke (.keyEntity ROOTKS
                           ^String (first (.keyAliases ROOTKS))
                           HELPME)
       fout (TempFile "x" ".jks")
       pk (.getPrivateKey pke)
       cs (.getCertificateChain pke) ]
            (SSv3JKS* "C=AU,ST=NSW,L=Sydney,O=Google" SECRET fout
                                { :start (Date.) :end ENDDT :issuerCerts (seq cs) :issuerKey pk })
              (> (.length fout) 0)))

(is (let [ ^File fout (TempFile "x" ".p7b") ]
        (ExportPkcs7 (ResUrl "com/zotohlab/frwk/crypto/test.pfx") HELPME fout)
          (> (.length fout) 0)))


)

(def ^:private cryptostuff-eof nil)

;;(clojure.test/run-tests 'testcljc.crypto.cryptostuff)

