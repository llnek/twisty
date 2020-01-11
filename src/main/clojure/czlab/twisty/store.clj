;; Copyright © 2013-2020, Kenneth Leung. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file epl-v10.html at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

(ns czlab.twisty.store

  "A Crypto store."

  (:require [czlab.basal.core :as c]
            [czlab.basal.io :as i]
            [czlab.basal.util :as u]
            [czlab.twisty.core :as t])

  (:import [java.io File FileInputStream IOException InputStream]
           [javax.net.ssl KeyManagerFactory TrustManagerFactory]
           [java.security.cert
            CertificateFactory
            X509Certificate
            Certificate]
           [java.security
            KeyStore
            PrivateKey
            KeyStore$TrustedCertificateEntry
            KeyStore$ProtectionParameter
            KeyStore$PasswordProtection
            KeyStore$PrivateKeyEntry]
           [javax.security.auth.x500 X500Principal]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;(set! *warn-on-reflection* false)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defprotocol CryptoStore
  "Higher abstraction over a Java Key Store."
  (key-entity [_ pwd]
              [_ alias pwd] "Get the 1st/named key entity.")
  (cert-entity [_ alias] "Get the named certificate.")
  (trusted-certs [_] "Get all trusted certificates.")
  (add-key-entity [_ gist pwd] "")
  (trust-manager-factory [_] "")
  (key-manager-factory [_] "")
  (cert-aliases [_] "")
  (key-aliases [_]  "")
  (add-cert-entity [_ cert]  "")
  (add-pkcs7 [_ arg] "Add a PKCS7 into store.")
  (remove-entity [_ alias] "")
  (keystore [_] "Get the underlying keystore object.")
  (cs-password [_] "Password for the store.")
  (write-out [_ out]
             [_ out pwd] "Write out to file."))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn crypto-store<>

  "Create a crypto store."
  {:arglists '([]
               [pwd]
               [ks pwd])}

  ([pwd]
   (crypto-store<> nil pwd))

  ([]
   (crypto-store<> nil))

  ([ks pwd]
   (let [_passwd (i/x->chars pwd)
         ^KeyStore _store (or ks (t/pkcs12<>))]
    (reify CryptoStore
      (add-key-entity [_ gist pwd]
        (c/let#nil [{:keys [pkey chain]} gist]
          (.setKeyEntry _store
                        (t/alias<>) pkey (i/x->chars pwd) chain)))
      (add-cert-entity [_ cert]
        (c/do#nil
          (.setCertificateEntry _store (t/alias<>) cert)))
      (trust-manager-factory [_]
        (doto (TrustManagerFactory/getInstance
                (TrustManagerFactory/getDefaultAlgorithm))
          (.init _store)))
      (key-manager-factory [_]
        (doto (KeyManagerFactory/getInstance
                (KeyManagerFactory/getDefaultAlgorithm))
          (.init _store _passwd)))
      (cert-aliases [_]
        (t/filter-entries _store :certs))
      (key-aliases [_]
        (t/filter-entries _store :keys))
      (key-entity [_ nm pwd]
        (t/pkey-gist<> _store nm (i/x->chars pwd)))
      (key-entity [me pwd]
        (let [[f & more] (key-aliases me)]
          (if (and f (empty? more))
            (key-entity me (str f) pwd)
            (u/throw-BadArg "Store has many keys."))))
      (cert-entity [_ nm] (t/tcert<> _store nm))
      (remove-entity [_ nm]
        (let [a (str nm)]
          (if (.containsAlias _store a)
            (.deleteEntry _store a))))
      (cs-password [_] _passwd)
      (keystore [_] _store)
      (write-out [_ out pwd]
        (.store _store out (i/x->chars pwd)))
      (write-out [me out]
        (write-out me out _passwd))
      (trusted-certs [me]
        (mapv #(cert-entity me (str %)) (cert-aliases me)))
      (add-pkcs7 [me arg]
        (doseq [c (t/x->certs arg)]
          (.setCertificateEntry _store
                                (t/alias<>)
                                ^Certificate c)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF

