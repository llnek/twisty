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

  (:import
    [czlab.crypto PKeyGist Cryptor CryptoStoreAPI PasswordAPI]
    [java.security KeyPair Policy
     KeyStore
     SecureRandom
     MessageDigest
     KeyStore$PrivateKeyEntry
     KeyStore$TrustedCertificateEntry]
    [java.util Date GregorianCalendar]
    [java.io File]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(def ^:private ^chars C_KEY (.toCharArray "ed8xwl2XukYfdgR2aAddrg0lqzQjFhbs"))
(def ^:private ^chars B_KEY (bytesify "ed8xwl2XukYfdgR2aAddrg0lqzQjFhbs"))
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

(is (not (= "heeloo, how are you?" (caesarDecrypt (caesarEncrypt "heeloo, how are you?" 709394) 666))))
(is (= "heeloo, how are you?" (caesarDecrypt (caesarEncrypt "heeloo, how are you?" 709394) 709394)))
(is (= "heeloo, how are you?" (caesarDecrypt (caesarEncrypt "heeloo, how are you?" 13) 13)))

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

(is (= (.length ^String (.text (strongPwd 16))) 16))
(is (= (.length (randomStr 64)) 64))

(is (instance? PasswordAPI (passwd<> "secret-text")))
(is (.startsWith ^String (.encoded ^PasswordAPI
                                   (passwd<> "secret-text")) "crypt:"))

(is (= "SHA-512" (.getAlgorithm (msgDigest "SHA-512"))))
(is (= "MD5" (.getAlgorithm (msgDigest "MD5"))))

(is (> (nextSerial) 0))

(is (= "PKCS12" (.getType (pkcsStore<>))))
(is (= "JKS" (.getType (jksStore<>))))

(is (instance? Policy (easyPolicy<>)))

(is (> (.length (genMac (bytesify "secret") (bytesify "heeloo world"))) 0))
(is (> (.length (genHash (bytesify "heeloo world"))) 0))

(is (not (nil? (asymKeyPair<> "RSA" 1024))))

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
          (.keyEntity ROOTCS
                      ^String (first (.keyAliases ROOTCS)) HELPME)
          fout (tempFile "x" ".p12")]
      (ssv3PKCS12
        pke "C=AU,ST=NSW,L=Sydney,O=Google" SECRET
        fout {:end ENDDT} HELPME)
      (> (.length fout) 0)))

(is (let [^PKeyGist pke
          (.keyEntity ROOTKS
                      ^String (first (.keyAliases ROOTKS)) HELPME)
          fout (tempFile "x" ".jks")]
      (ssv3JKS
        pke "C=AU,ST=NSW,L=Sydney,O=Google" SECRET
        fout { :end ENDDT} HELPME)
      (> (.length fout) 0)))

(is (let [^PKeyGist
          pke
          (.keyEntity ROOTCS
                      ^String (first (.keyAliases ROOTCS)) HELPME)
          ^File fout (tempFile "x" ".p7b")]
      (exportPkcs7 pke fout)
      (> (.length fout) 0)))

)

;;(clojure.test/run-tests 'czlabtest.crypto.cryptostuff)

