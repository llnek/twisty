;; Copyright © 2013-2019, Kenneth Leung. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file epl-v10.html at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

(ns ^{:doc "A Crypto store."
      :author "Kenneth Leung"}

  czlab.twisty.store

  (:require [czlab.basal.core :as c]
            [czlab.basal.log :as l]
            [czlab.basal.str :as s]
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
(defprotocol CryptoStore ""
  (cs-key-entity [_ pwd] [_ alias pwd] "")
  (cs-cert-entity [_ alias] "")
  (cs-trusted-certs [_] "")
  (cs-add-key-entity [_ gist pwd] "")
  (cs-trust-manager-factory [_] "")
  (cs-key-manager-factory [_] "")
  (cs-cert-aliases [_] "")
  (cs-key-aliases [_]  "")
  (cs-add-cert-entity [_ cert]  "")
  (cs-add-pkcs7 [_ arg] "")
  (cs-remove-entity [_ alias] "")
  (cs-keystore [_] "")
  (cs-password [_] "")
  (cs-write-out [_ out] [_ out pwd] ""))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- mkstore [^KeyStore _store _passwd]
  (reify CryptoStore
    (cs-add-key-entity [_ gist pwd]
      (c/let#nil [{:keys [pkey chain]} gist]
        (.setKeyEntry _store
                      (t/alias<>) pkey (i/x->chars pwd) chain)))
    (cs-add-cert-entity [_ cert]
      (c/do#nil
        (.setCertificateEntry _store (t/alias<>) cert)))
    (cs-trust-manager-factory [_]
      (doto (TrustManagerFactory/getInstance
              (TrustManagerFactory/getDefaultAlgorithm))
        (.init _store)))
    (cs-key-manager-factory [_]
      (doto (KeyManagerFactory/getInstance
              (KeyManagerFactory/getDefaultAlgorithm))
        (.init _store _passwd)))
    (cs-cert-aliases [_]
      (t/filter-entries _store :certs))
    (cs-key-aliases [_]
      (t/filter-entries _store :keys))
    (cs-key-entity [_ nm pwd]
      (t/pkey-gist<> _store nm (i/x->chars pwd)))
    (cs-key-entity [me pwd]
      (let [[f & more] (cs-key-aliases me)]
        (if (and f (empty? more))
          (cs-key-entity me (str f) pwd)
          (u/throw-BadArg "Store has many keys."))))
    (cs-cert-entity [_ nm] (t/tcert<> _store nm))
    (cs-remove-entity [_ nm]
      (let [a (str nm)]
        (if (.containsAlias _store a)
          (.deleteEntry _store a))))
    (cs-password [_] _passwd)
    (cs-keystore [_] _store)
    (cs-write-out [_ out pwd]
      (.store _store out (i/x->chars pwd)))
    (cs-write-out [me out]
      (cs-write-out me out _passwd))
    (cs-trusted-certs [me]
      (mapv #(cs-cert-entity me (str %)) (cs-cert-aliases me)))
    (cs-add-pkcs7 [me arg]
      (doseq [c (t/x->certs arg)]
        (.setCertificateEntry _store
                              (t/alias<>)
                              ^Certificate c)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn crypto-store<>
  ""
  ([pwd] (crypto-store<> nil pwd))
  ([] (crypto-store<> nil))
  ([ks pwd]
   (mkstore (or ks (t/pkcs12<>)) (i/x->chars pwd))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF

