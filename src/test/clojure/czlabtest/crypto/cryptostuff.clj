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

(ns

  czlabtest.crypto.cryptostuff

  (:use [czlab.crypto.stores]
        [czlab.crypto.codec]
        [czlab.xlib.core]
        [czlab.xlib.str]
        [czlab.xlib.io]
        [clojure.test]
        [czlab.crypto.core])

  (:import [czlab.crypto PKeyGist Cryptor CryptoStoreAPI PasswordAPI]
           [java.util Date GregorianCalendar]
           [java.io File]
           [java.math BigInteger]
           [java.security
            KeyPair
            Policy
            KeyStore
            SecureRandom
            MessageDigest
            KeyStore$PrivateKeyEntry
            KeyStore$TrustedCertificateEntry]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(def ^:private ^chars C_KEY (.toCharArray "ed8xwl2XukYfdgR2aAddrg0lqzQjFhbs"))
(def ^:private ^bytes B_KEY (bytesify "ed8xwl2XukYfdgR2aAddrg0lqzQjFhbs"))
(def ^:private ^chars TESTPWD (.toCharArray "secretsecretsecretsecretsecret"))
(def ^:private ENDDT (.getTime (GregorianCalendar. 2050 1 1)))
(def ^:private ROOTPFX (resBytes "czlab/crypto/test.pfx"))
(def ^:private ROOTJKS (resBytes "czlab/crypto/test.jks"))
(def ^:private HELPME (.toCharArray "helpme"))
(def ^:private SECRET (.toCharArray "secret"))

(def ^:private ^CryptoStoreAPI
  ROOTCS (cryptoStore<> (initStore! (pkcsStore<>) ROOTPFX HELPME) HELPME))

(def ^:private ^CryptoStoreAPI
  ROOTKS (cryptoStore<> (initStore! (jksStore<>) ROOTJKS HELPME) HELPME))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(deftest czlabtestcrypto-cryptostuff

  (is (isSigned? "application/x-pkcs7-mime; signed-data"))
  (is (isSigned? "multipart/signed"))
  (is (not (isSigned? "text/plain")))

  (is (isEncrypted? "application/x-pkcs7-mime; enveloped-data"))
  (is (isEncrypted? "text/plain"))

  (is (isCompressed? "application/pkcs7-mime; compressed-data"))
  (is (isCompressed? "text/plain"))

  (is (not (jksFile? (resUrl "czlab/crypto/test.p12"))))
  (is (jksFile? (resUrl "czlab/crypto/test.jks")))

  (is (= "SHA-512" (.getAlgorithm (msgDigest "SHA-512"))))
  (is (= "MD5" (.getAlgorithm (msgDigest "MD5"))))

  (is (inst? BigInteger (nextSerial)))

  (is (not= (alias<>)(alias<>)))
  (is (string? (alias<>)))

  (is (= "PKCS12" (.getType (pkcsStore<>))))
  (is (= "JKS" (.getType (jksStore<>))))

  (is (let [a (.keyAliases ROOTCS)
            c (count a)
            n (first a)
            e (.keyEntity ROOTCS n HELPME)]
        (and (== 1 c)
             (string? n)
             (inst? PKeyGist e))))

  (is (let [a (.certAliases ROOTCS) c (count a)] (== 0 c)))

  (is (let [g (convPKey (resUrl
                          "czlab/crypto/test.p12")
                        HELPME
                        HELPME)
            t (tempFile)
            _ (exportPkcs7 g t)
            z (.length t)
            c (.cert g)
            b (exportCert c)]
        (deleteQ t)
        (and (> z 10)
             (hgl? (stringify b)))))

  (is (some? (easyPolicy<>)))

  (is (= (genMac B_KEY "hello world")
         (genMac B_KEY "hello world")))

  (is (not= (genMac B_KEY "hello maria")
            (genMac B_KEY "hello world")))

  (is (= (genHash "hello world")
         (genHash "hello world")))

  (is (not= (genHash "hello maria")
            (genHash "hello world")))

  (is (let [kp (asymKeyPair<> "RSA" 1024)
            b (exportPEM kp SECRET)
            pub (.getPublic kp)
            prv (.getPrivate kp)
            b1 (exportPrivateKey prv SECRET)
            b2 (exportPublicKey pub)]
        (and (hgl? (stringify b))
             (hgl? (stringify b1))
             (hgl? (stringify b2)))))

  (is (let [[a b]
            (cereq<> "C=AU,O=Org,OU=OUnit,CN=joe" 1024)]
        (and (instBytes? a)
             (instBytes? b))))

  (is (let [s (session<> "joe" "123")
            s0 (session<>)
            b (resBytes "czlab/xlib/mime.eml")
            m (mimeMsg<> (streamify b))
            c (.getContent m)
            z (isDataCompressed? c)
            g (isDataSigned? c)
            e (isDataEncrypted? c)]
        (and (not z)(not g)(not e))))



  (is (some? (getCharset "text/plain; charset=utf-16")))

  (is (not= (digest<sha1> "hello world")
            (digest<md5> "hello world")))

  (is (= (digest<sha1> "hello world")
         (digest<sha1> "hello world")))

  (is (= (digest<md5> "hello world")
         (digest<md5> "hello world")))

  (is (some? (simpleTrustMgr<>)))




(is (not= "heeloo, how are you?"
          (caesarDecrypt 666 (caesarEncrypt 709394 "heeloo, how are you?" ) )))

(is (= "heeloo, how are you?"
       (caesarDecrypt 709394 (caesarEncrypt 709394 "heeloo, how are you?" ) )))

(is (= "heeloo, how are you?"
       (caesarDecrypt 13 (caesarEncrypt 13 "heeloo, how are you?" ) )))

(is (= "heeloo" (let [c (jasyptCryptor<>)]
                  (.decrypt c C_KEY (.encrypt c C_KEY "heeloo")))))

(is (= "heeloo" (let [c (jasyptCryptor<>)
                      pkey SECRET]
                  (.decrypt c pkey (.encrypt c pkey "heeloo")))))

(is (= "heeloo" (let [c (javaCryptor<>)]
                  (stringify (.decrypt c B_KEY (.encrypt c B_KEY "heeloo"))))))

(is (= "heeloo" (let [c (javaCryptor<>)
                      pkey (bytesify (String. ^chars TESTPWD))]
                  (stringify (.decrypt c pkey (.encrypt c pkey "heeloo"))))))

(is (= "heeloo" (let [c (bcastleCryptor<>)]
                  (stringify (.decrypt c B_KEY (.encrypt c B_KEY "heeloo"))))))

(is (= "heeloo" (let [c (bcastleCryptor<>)
                      pkey (bytesify (String. ^chars TESTPWD))]
                  (stringify (.decrypt c pkey (.encrypt c pkey "heeloo"))))))

(is (= "heeloo" (let [kp (asymKeyPair<> "RSA" 1024)
                      pu (.getEncoded (.getPublic kp))
                      pv (.getEncoded (.getPrivate kp))]
                  (stringify (asymDecr pv
                                       (asymEncr pu
                                                 (bytesify "heeloo")))))))

(is (= (.length ^String (.text (strongPwd<> 16))) 16))
(is (= (.length (randomStr 64)) 64))

(is (instance? PasswordAPI (passwd<> "secret-text")))
(is (.startsWith ^String (.encoded ^PasswordAPI
                                   (passwd<> "secret-text")) "crypt:"))



(is (let [v (csreq<>
              (str "C=AU,ST=NSW,L=Sydney,"
                   "O=Google,OU=HQ,CN=www.google.com" 1024 SECRET))]
      (and (= (count v) 2)
           (> (alength ^bytes (first v)) 0)
           (> (alength ^bytes (nth v 1)) 0))) )

(is (let [fout (tempFile "Joe Blogg" ".p12")]
      (ssv1PKCS12 "C=AU,ST=NSW,L=Sydney,O=Google"
                  SECRET
                  {:end ENDDT :keylen 1024 }
                  fout
                  HELPME)
      (> (.length fout) 0)))

(is (let [fout (tempFile "x" ".jks")]
      (ssv1JKS "C=AU,ST=NSW,L=Sydney,O=Google"
               SECRET
               {:end ENDDT }
               fout
               HELPME)
      (> (.length fout) 0)))

(is (let [^PKeyGist
          pke
          (.keyEntity ROOTCS HELPME)
          fout (tempFile "x" ".p12")]
      (ssv3PKCS12
        pke "C=AU,ST=NSW,L=Sydney,O=Google" SECRET
        fout {:end ENDDT} HELPME)
      (> (.length fout) 0)))

(is (let [^PKeyGist pke
          (.keyEntity ROOTKS HELPME)
          fout (tempFile "x" ".jks")]
      (ssv3JKS
        pke "C=AU,ST=NSW,L=Sydney,O=Google" SECRET
        fout { :end ENDDT} HELPME)
      (> (.length fout) 0)))

(is (let [^PKeyGist
          pke
          (.keyEntity ROOTCS HELPME)
          ^File fout (tempFile "x" ".p7b")]
      (exportPkcs7 pke fout)
      (> (.length fout) 0)))

)

;;(clojure.test/run-tests 'czlabtest.crypto.cryptostuff)

