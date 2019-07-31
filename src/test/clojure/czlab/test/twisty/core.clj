;; Copyright ©  2013-2019, Kenneth Leung. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file epl-v10.html at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

(ns ^{:doc ""
      :author "Kenneth Leung"}

  czlab.test.twisty.core

  (:require [czlab.twisty.codec :as cc]
            [czlab.twisty.store :as st]
            [clojure.java.io :as io]
            [czlab.twisty.ssl :as ss]
            [czlab.twisty.core :as t]
            [clojure.test :as ct]
            [czlab.basal.io :as i]
            [czlab.basal.str :as s]
            [czlab.basal.core
             :refer [ensure?? ensure-thrown??] :as c])

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
(def ^:private end-date (.getTime (GregorianCalendar. 2050 1 1)))

(def
  ^{:private true :tag "[C"}
  c-key (i/x->chars "ed8xwl2XukYfdgR2aAddrg0lqzQjFhbs"))

(def
  ^{:private true :tag "[B"}
  b-key (i/x->bytes "ed8xwl2XukYfdgR2aAddrg0lqzQjFhbs"))

(def
  ^{:private true :tag "[C"}
  test-pwd (i/x->chars "secretsecretsecretsecretsecret"))

(def
  ^{:private true :tag "[B"}
  root-pfx (i/res->bytes "czlab/test/twisty/test.pfx"))

(def
  ^{:private true :tag "[B"}
  root-jks (i/res->bytes "czlab/test/twisty/test.jks"))

(def
  ^{:private true :tag "[C"}
  help-me (i/x->chars "helpme"))

(def
  ^{:private true :tag "[C"}
  secret (i/x->chars "secret"))

(def ^:private
  root-cs (st/crypto-store<> (t/pkcs12<> root-pfx help-me) help-me))

(def ^:private
  root-ks (st/crypto-store<> (t/jks<> root-jks help-me) help-me))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(c/deftest test-core

  (ensure?? "is-signed?"
            (and (t/is-signed? "application/x-pkcs7-mime; signed-data")
                 (t/is-signed? "multipart/signed")
                 (not (t/is-signed? "text/plain"))))

  (ensure?? "is-encrypted?"
            (and (t/is-encrypted? "application/x-pkcs7-mime; enveloped-data")
                 (not (t/is-encrypted? "text/plain"))))

  (ensure?? "is-compressed?"
            (and (t/is-compressed? "application/pkcs7-mime; compressed-data")
                 (not (t/is-compressed? "text/plain"))))

  (ensure?? "is-jksfile?"
            (and (not (t/is-jksfile? (i/res->url "czlab/test/twisty/test.p12")))
                 (t/is-jksfile? (i/res->url "czlab/test/twisty/test.jks"))))

  (ensure?? "msg-digest" (= "SHA-512" (.getAlgorithm (t/msg-digest "SHA-512"))))
  (ensure?? "msg-digest" (= "MD5" (.getAlgorithm (t/msg-digest "MD5"))))

  (ensure?? "next-serial" (c/is? BigInteger (t/next-serial)))

  (ensure?? "alias" (and (string? (t/alias<>))
                         (not= (t/alias<>) (t/alias<>))))

  (ensure?? "pkcs12<>" (= "PKCS12" (.getType (t/pkcs12<>))))

  (ensure?? "jks<>" (= "JKS" (.getType (t/jks<>))))

  (ensure?? "crypto-store<>"
            (let [x (i/x->chars "a")
                  out (i/baos<>)
                  _ (st/write-out root-cs out x)
                  [del? inp] (i/input-stream?? out)
                  s (st/crypto-store<> (t/pkcs12<> inp x) x)]
              (if del? (i/klose inp))
              (c/is? KeyStore (st/keystore s))))

  (ensure?? "key-entity,key-aliases"
            (let [a (st/key-aliases root-cs)
                  c (count a)
                  n (first a)
                  e (st/key-entity root-cs n help-me)]
              (and (= 1 c) (string? n))))

  (ensure?? "cert-aliases"
            (let [a (st/cert-aliases root-cs) c (count a)] (zero? c)))

  (ensure?? "x->pkey"
            (let [g (t/x->pkey (i/res->url
                                 "czlab/test/twisty/test.p12")
                               help-me help-me)
                  t (t/export-pkcs7-file g (i/temp-file))
                  z (i/fsize t)
                  b (t/export-cert (:cert g))]
              (i/fdelete t)
              (and (> z 10)
                   (> (alength b) 10))))

  (ensure?? "easy-policy<>" (some? (t/easy-policy<>)))

  (ensure?? "gen-mac" (= (t/gen-mac b-key "hello world")
                         (t/gen-mac b-key "hello world")))

  (ensure?? "gen-mac" (not= (t/gen-mac b-key "hello maria")
                            (t/gen-mac b-key "hello world")))

  (ensure?? "gen-digest" (= (t/gen-digest "hello world")
                            (t/gen-digest "hello world")))

  (ensure?? "gen-digest" (not= (t/gen-digest "hello maria")
                               (t/gen-digest "hello world")))

  (ensure?? "asym-key-pair<>"
            (let [kp (t/asym-key-pair<> "RSA" 512)
                  b (t/export-pem kp secret)
                  pub (.getPublic kp)
                  prv (.getPrivate kp)
                  b1 (t/export-private-key prv secret)
                  b2 (t/export-public-key pub)]
              (and (s/hgl? (i/x->str b))
                   (s/hgl? (i/x->str b1))
                   (s/hgl? (i/x->str b2)))))

  (ensure?? "csreq<>"
            (let [[a b]
                  (t/csreq<> "C=AU,O=Org,OU=OUnit,CN=joe" 512)]
              (and (bytes? a) (bytes? b))))

  (ensure?? "csreq<>"
            (let [[v1 v2 :as v]
                  (t/csreq<>
                    "C=US,ST=CA,L=X,O=Z,OU=HQ,CN=joe" 512 secret)]
              (and (= (count v) 2)
                   (pos? (alength ^bytes v1))
                   (pos? (alength ^bytes v2)))))

  (ensure?? "session<>"
            (let [s (t/session<> "joe" secret)
                  s0 (t/session<>)
                  b (i/res->bytes "czlab/test/twisty/mime.eml")
                  inp (io/input-stream b)
                  m (t/mime-msg<> inp)
                  c (.getContent m)
                  z (t/is-data-compressed? c)
                  g (t/is-data-signed? c)
                  e (t/is-data-encrypted? c)]
              (i/klose inp)
              (and (not z)(not g)(not e))))

  (ensure?? "charset??"
            (some? (t/charset?? "text/plain; charset=utf-16")))

  (ensure?? "fingerprint"
            (not= (t/fingerprint (i/x->bytes "hello world") :sha-1)
                  (t/fingerprint (i/x->bytes "hello world") :md5)))

  (ensure?? "fingerprint"
            (= (t/fingerprint (i/x->bytes "hello world") :sha-1)
               (t/fingerprint (i/x->bytes "hello world") :sha-1)))

  (ensure?? "fingerprint"
            (= (t/fingerprint (i/x->bytes "hello world") :md5)
               (t/fingerprint (i/x->bytes "hello world") :md5)))

  (ensure?? "is-valid-cert?"
            (let [b (i/res->bytes "czlab/test/twisty/cert.crt")
                  c (t/x->cert b)
                  g (t/cert-gist<> c)]
              (and c g (t/is-valid-cert? c))))

  (ensure?? "simple-trust-mgr<>" (some? (ss/simple-trust-mgr<>)))

  (ensure?? "caesar<>"
            (let [c (cc/caesar<>)]
              (not= "heeloo, how are you?"
                    (cc/decrypt c
                                666
                                (cc/encrypt c
                                            709394
                                            "heeloo, how are you?")))))

  (ensure?? "caesar<>"
            (let [c (cc/caesar<>)]
              (= "heeloo, how are you?"
                 (cc/decrypt c
                             709394
                             (cc/encrypt c
                                         709394
                                         "heeloo, how are you?")))))

  (ensure?? "caesar<>"
            (let [c (cc/caesar<>)]
              (= "heeloo, how are you?"
                 (cc/decrypt c
                             13
                             (cc/encrypt c
                                         13 "heeloo, how are you?")))))

  (ensure?? "jasypt<>"
            (= "heeloo"
               (let [c (cc/jasypt<>)]
                 (cc/decrypt c
                             c-key
                             (cc/encrypt c c-key "heeloo")))))

  (ensure?? "jasypt<>"
            (= "heeloo"
               (let [c (cc/jasypt<>)
                     pkey secret]
                 (cc/decrypt c
                             pkey
                             (cc/encrypt c pkey "heeloo")))))

  (ensure?? "jcrypt<>"
            (= "heeloo"
               (let [c (cc/jcrypt<>)]
                 (i/x->str (cc/decrypt c
                                       b-key
                                       (cc/encrypt c b-key "heeloo"))))))

  (ensure?? "jcrypt<>"
            (= "heeloo"
               (let [c (cc/jcrypt<>)
                     pkey (i/x->bytes (i/x->str test-pwd))]
                 (i/x->str (cc/decrypt c
                                       pkey (cc/encrypt c pkey "heeloo"))))))

  (ensure?? "bcastle<>"
            (= "heeloo"
               (let [c (cc/bcastle<>)]
                 (i/x->str (cc/decrypt c
                                       b-key
                                       (cc/encrypt c b-key "heeloo"))))))

  (ensure?? "bcastle<>"
            (= "heeloo"
               (let [c (cc/bcastle<>)
                     pkey (i/x->bytes (i/x->str test-pwd))]
                 (i/x->str (cc/decrypt c pkey (cc/encrypt c pkey "heeloo"))))))

  (ensure?? "asym-key-pair<>"
            (= "heeloo"
               (let [kp (t/asym-key-pair<> "RSA" 512)
                     pu (.getEncoded (.getPublic kp))
                     pv (.getEncoded (.getPrivate kp))
                     cc (cc/asym<>)]
                 (i/x->str (cc/decrypt cc
                                       pv
                                       (cc/encrypt cc
                                                   pu (i/x->bytes "heeloo")))))))

  (ensure?? "strong-pwd<>"
            (= (alength ^chars (cc/p-text (cc/strong-pwd<> 16))) 16))

  (ensure?? "random-str" (= (.length (cc/random-str 64)) 64))

  (ensure?? "pwd<>"
            (satisfies? czlab.twisty.codec/Password (cc/pwd<> "secret-text")))

  (ensure?? "pwd<>"
            (.startsWith
              (i/x->str (cc/p-encoded (cc/pwd<> "secret-text"))) "crypt:"))

  (ensure?? "pwd<>"
            (= "hello joe!"
               (cc/stringify (cc/pwd<> (cc/p-encoded (cc/pwd<> "hello joe!"))))))

  (ensure?? "ssv1-pkcs12<>"
            (let [ks (t/ssv1-pkcs12<> "C=AU,ST=NSW,L=Sydney,O=Google"
                                      secret {:end end-date :keylen 512 })
                  fout (i/temp-file "Joe Blogg" ".p12")
                  ok? (c/is? KeyStore ks)
                  f (t/spit-key-store ks fout help-me)
                  len (i/fsize f)]
              (i/fdelete f)
              (and ok? (pos? len))))

  (ensure?? "ssv1-jks<>"
            (let [ks (t/ssv1-jks<> "C=AU,ST=WA,L=X,O=Z"
                                   secret {:keylen 512 :end end-date})
                  fout (i/temp-file "xxxx" ".jks")
                  ok? (c/is? KeyStore ks)
                  f (t/spit-key-store ks fout help-me)
                  len (i/fsize f)]
              (i/fdelete f)
              (and ok? (pos? len))))

  (ensure?? "ssv3-pkcs12<>"
            (let [r (st/key-entity root-cs help-me)
                  fout (i/temp-file "xxxx" ".p12")
                  ks (t/ssv3-pkcs12<> r
                                      "C=AU,ST=WA,L=Z,O=X"
                                      secret {:keylen 512 :end end-date})
                  ok? (c/is? KeyStore ks)
                  f (t/spit-key-store ks fout help-me)
                  len (i/fsize f)]
              (i/fdelete f)
              (and ok? (pos? len))))

  (ensure?? "ssv3-jks<>"
            (let [r (st/key-entity root-ks help-me)
                  fout (i/temp-file "xxxx" ".jks")
                  ks (t/ssv3-jks<> r
                                   "C=AU,ST=WA,L=Z,O=X"
                                   secret {:keylen 512 :end end-date})
                  ok? (c/is? KeyStore ks)
                  f (t/spit-key-store ks fout help-me)
                  len (i/fsize f)]
              (i/fdelete f)
              (and ok? (pos? len))))

  (ensure?? "export-pkcs7,export-pkcs7-file"
            (let [r (st/key-entity root-cs help-me)
                  fout (i/temp-file "xxxx" ".p7b")
                  b (t/export-pkcs7 r)
                  f (t/export-pkcs7-file r fout)
                  len (i/fsize f)]
              (and (bytes? b) (pos? len))))


  (ensure?? "test-end" (= 1 1)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(ct/deftest ^:test-core twisty-test-core
  (ct/is (let [[ok? r]
               (c/runtest test-core "test-core")] (println r) ok?)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


