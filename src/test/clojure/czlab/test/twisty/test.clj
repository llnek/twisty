;; Copyright (c) 2013-2017, Kenneth Leung. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file epl-v10.html at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

(ns czlab.test.twisty.test

  (:require [czlab.twisty.store :as st]
            [czlab.twisty.codec :as cc]
            [czlab.twisty.ssl :as ss]
            [czlab.basal.core :as c]
            [czlab.basal.meta :as m]
            [czlab.basal.str :as s]
            [czlab.basal.io :as i]
            [czlab.twisty.core :as t])

  (:use [clojure.test])

  (:import [java.util Date GregorianCalendar]
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
(def ^:private end-date (.getTime (GregorianCalendar. 2050 1 1)))

(def
  ^{:private true :tag "[C"}
  c-key (c/charsit "ed8xwl2XukYfdgR2aAddrg0lqzQjFhbs"))

(def
  ^{:private true :tag "[B"}
  b-key (c/bytesit "ed8xwl2XukYfdgR2aAddrg0lqzQjFhbs"))

(def
  ^{:private true :tag "[C"}
  test-pwd (c/charsit "secretsecretsecretsecretsecret"))

(def
  ^{:private true :tag "[B"}
  root-pfx (c/resBytes "czlab/test/twisty/test.pfx"))
(def
  ^{:private true :tag "[B"}
  root-jks (c/resBytes "czlab/test/twisty/test.jks"))

(def
  ^{:private true :tag "[C"}
  help-me (c/charsit "helpme"))

(def
  ^{:private true :tag "[C"}
  secret (c/charsit "secret"))

(def ^:private
  root-cs (st/cryptoStore<> (t/pkcs12<> root-pfx help-me) help-me))

(def ^:private
  root-ks (st/cryptoStore<> (t/jks<> root-jks help-me) help-me))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(deftest czlabtesttwisty-test

  (testing
    "related to: checking content-type"
    (is (t/isSigned? "application/x-pkcs7-mime; signed-data"))
    (is (t/isSigned? "multipart/signed"))
    (is (not (t/isSigned? "text/plain")))

    (is (t/isEncrypted? "application/x-pkcs7-mime; enveloped-data"))
    (is (not (t/isEncrypted? "text/plain")))

    (is (t/isCompressed? "application/pkcs7-mime; compressed-data"))
    (is (not (t/isCompressed? "text/plain"))))

  (is (not (t/jksFile? (c/resUrl "czlab/test/twisty/test.p12"))))
  (is (t/jksFile? (c/resUrl "czlab/test/twisty/test.jks")))

  (is (= "SHA-512" (.getAlgorithm (t/msgDigest "SHA-512"))))
  (is (= "MD5" (.getAlgorithm (t/msgDigest "MD5"))))

  (is (c/ist? BigInteger (t/nextSerial)))

  (is (not= (t/alias<>)(t/alias<>)))
  (is (string? (t/alias<>)))

  (testing
    "related to: crypto stores"

    (is (= "PKCS12" (.getType (t/pkcs12<>))))
    (is (= "JKS" (.getType (t/jks<>))))

    (is (let [out (i/baos<>)
              x (c/charsit "a")
              _ (st/write-out root-cs out x)
              b (c/bytesit out)
              i (i/streamit b)
              s (st/cryptoStore<> (t/pkcs12<> i x) x)]
          (c/ist? KeyStore (:store s))))

    (is (let [a (st/key-aliases root-cs)
              c (count a)
              n (first a)
              e (st/key-entity root-cs n help-me)]
          (and (== 1 c)
               (string? n))))

    (is (let [a (st/cert-aliases root-cs) c (count a)] (== 0 c)))

    (is (let [g (t/convPKey (c/resUrl
                              "czlab/test/twisty/test.p12")
                            help-me
                            help-me)
              t (i/tempFile)
              t (t/exportPkcs7File g t)
              z (.length t)
              c (:cert g)
              b (t/exportCert c)]
          (i/deleteQ t)
          (and (> z 10)
               (> (alength b) 10)))))

  (is (some? (t/easyPolicy<>)))

  (testing
    "related to: mac & hash"
    (is (= (t/genMac b-key "hello world")
           (t/genMac b-key "hello world")))

    (is (not= (t/genMac b-key "hello maria")
              (t/genMac b-key "hello world")))

    (is (= (t/genDigest "hello world")
           (t/genDigest "hello world")))

    (is (not= (t/genDigest "hello maria")
              (t/genDigest "hello world"))))

  (testing
    "related to: keypairs"
    (is (let [kp (t/asymKeyPair<> "RSA" 1024)
              b (t/exportPEM kp secret)
              pub (.getPublic kp)
              prv (.getPrivate kp)
              b1 (t/exportPrivateKey prv secret)
              b2 (t/exportPublicKey pub)]
          (and (s/hgl? (c/strit b))
               (s/hgl? (c/strit b1))
               (s/hgl? (c/strit b2))))))

  (testing
    "related to: cert service request"
    (is (let [[a b]
              (t/csreq<> "C=AU,O=Org,OU=OUnit,CN=joe" 1024)]
          (and (m/instBytes? a)
               (m/instBytes? b))))
    (is (let [v (t/csreq<>
                  "C=US,ST=CA,L=X,O=Z,OU=HQ,CN=joe" 1024 secret)]
          (and (= (count v) 2)
               (> (alength ^bytes (first v)) 0)
               (> (alength ^bytes (nth v 1)) 0)))))

  (is (let [s (t/session<> "joe" secret)
            s0 (t/session<>)
            b (c/resBytes "czlab/test/twisty/mime.eml")
            m (t/mimeMsg<> (i/streamit b))
            c (.getContent m)
            z (t/isDataCompressed? c)
            g (t/isDataSigned? c)
            e (t/isDataEncrypted? c)]
        (and (not z)(not g)(not e))))

  (is (some? (t/getCharset "text/plain; charset=utf-16")))

  (testing
    "related to: msg digest"
    (is (not= (t/fingerprint (c/bytesit "hello world") :sha-1)
              (t/fingerprint (c/bytesit "hello world") :md5)))

    (is (= (t/fingerprint (c/bytesit "hello world") :sha-1)
           (t/fingerprint (c/bytesit "hello world") :sha-1)))

    (is (= (t/fingerprint (c/bytesit "hello world") :md5)
           (t/fingerprint (c/bytesit "hello world") :md5))))

  (is (let [b (c/resBytes "czlab/test/twisty/cert.crt")
            c (t/convCert b)
            g (t/certGist<> c)
            ok? (t/validCert? c)]
        (and c g ok?)))

  (is (some? (ss/simpleTrustMgr<>)))

  (testing
    "related to: caesar crypto"
    (is (let [c (cc/caesar<>)]
          (not= "heeloo, how are you?"
                (.decrypt c
                          666
                          (.encrypt c
                                    709394
                                    "heeloo, how are you?")))))

    (is (let [c (cc/caesar<>)]
          (= "heeloo, how are you?"
             (.decrypt c
                       709394
                       (.encrypt c
                                 709394
                                 "heeloo, how are you?")))))

    (is (let [c (cc/caesar<>)]
          (= "heeloo, how are you?"
             (.decrypt c
                       13
                       (.encrypt c
                                 13 "heeloo, how are you?"))))))

  (testing
    "related to: jasypt crypto"
    (is (= "heeloo"
           (let [c (cc/jasypt<>)]
             (.decrypt c
                       c-key
                       (.encrypt c c-key "heeloo")))))

    (is (= "heeloo"
           (let [c (cc/jasypt<>)
                 pkey secret]
             (.decrypt c
                       pkey
                       (.encrypt c pkey "heeloo"))))))

  (testing
    "related to: java crypto"
    (is (= "heeloo"
           (let [c (cc/jcrypt<>)]
             (c/strit (.decrypt c
                                b-key
                                (.encrypt c b-key "heeloo"))))))

    (is (= "heeloo"
           (let [c (cc/jcrypt<>)
                 pkey (c/bytesit (String. test-pwd))]
             (c/strit (.decrypt c
                                pkey (.encrypt c pkey "heeloo")))))))

  (testing
    "related to: bouncycastle crypto"
    (is (= "heeloo"
           (let [c (cc/bcastle<>)]
             (c/strit (.decrypt c
                                b-key
                                (.encrypt c b-key "heeloo"))))))

    (is (= "heeloo"
           (let [c (cc/bcastle<>)
                 pkey (c/bytesit (String. test-pwd))]
             (c/strit (.decrypt c pkey (.encrypt c pkey "heeloo"))))))

    (is (= "heeloo"
           (let [kp (t/asymKeyPair<> "RSA" 1024)
                 pu (.getEncoded (.getPublic kp))
                 pv (.getEncoded (.getPrivate kp))
                 cc (cc/asym<>)]
             (c/strit (.decrypt cc
                                pv
                                (.encrypt cc
                                          pu (c/bytesit "heeloo"))))))))

  (testing
    "related to: passwords"
    (is (= (alength ^chars (cc/p-text (cc/strongPwd<> 16))) 16))
    (is (= (.length (cc/randomStr 64)) 64))

    (is (satisfies? czlab.twisty.codec/Password (cc/pwd<> "secret-text")))

    (is (.startsWith
          (c/strit (cc/p-encoded (cc/pwd<> "secret-text"))) "crypt:"))

    (is (= "hello joe!"
           (cc/stringify (cc/pwd<> (cc/p-encoded (cc/pwd<> "hello joe!")))))))

  (testing
    "related to: keystores"

    (is (let [ks (t/ssv1PKCS12<> "C=AU,ST=NSW,L=Sydney,O=Google"
                                 secret {:end end-date :keylen 1024 })
              fout (i/tempFile "Joe Blogg" ".p12")
              ok? (c/ist? KeyStore ks)
              f (t/spitKeyStore ks fout help-me)
              len (.length f)]
          (i/deleteQ f)
          (and ok? (> len 0))))

    (is (let [ks (t/ssv1JKS<> "C=AU,ST=WA,L=X,O=Z" secret {:end end-date})
              fout (i/tempFile "xxxx" ".jks")
              ok? (c/ist? KeyStore ks)
              f (t/spitKeyStore ks fout help-me)
              len (.length f)]
          (i/deleteQ f)
          (and ok? (> len 0))))

    (is (let [r (st/key-entity root-cs help-me)
              fout (i/tempFile "xxxx" ".p12")
              ks (t/ssv3PKCS12<> r
                                 "C=AU,ST=WA,L=Z,O=X"
                                 secret {:end end-date})
              ok? (c/ist? KeyStore ks)
              f (t/spitKeyStore ks fout help-me)
              len (.length f)]
          (i/deleteQ f)
          (and ok? (> len 0))))

    (is (let [r (st/key-entity root-ks help-me)
              fout (i/tempFile "xxxx" ".jks")
              ks (t/ssv3JKS<> r
                              "C=AU,ST=WA,L=Z,O=X"
                              secret {:end end-date})
              ok? (c/ist? KeyStore ks)
              f (t/spitKeyStore ks fout help-me)
              len (.length f)]
          (i/deleteQ f)
          (and ok? (> len 0))))

    (is (let [r (st/key-entity root-cs help-me)
              fout (i/tempFile "xxxx" ".p7b")
              b (t/exportPkcs7 r)
              f (t/exportPkcs7File r fout)
              len (.length f)]
          (and (m/instBytes? b) (> len 0)))))

  (is (string? "That's all folks!")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF

