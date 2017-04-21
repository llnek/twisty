;; Copyright (c) 2013-2017, Kenneth Leung. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file epl-v10.html at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

(ns ^{:doc "A Crypto store."
      :author "Kenneth Leung"}

  czlab.twisty.store

  (:require [czlab.basal.logging :as log])

  (:use [czlab.twisty.core]
        [czlab.basal.core]
        [czlab.basal.str])

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
;;
(defprotocol CryptoStore
  (key-entity [_ pwd] [_ alias pwd] )
  (cert-entity [_ alias] )
  (trusted-certs [_] )
  (add-key-entity [_ gist pwd])
  (trust-manager-factory [_] )
  (key-manager-factory [_] )
  (cert-aliases [_])
  (key-aliases [_] )
  (add-cert-entity [_ cert] )
  (add-pkcs7 [_ arg] )
  (remove-entity [_ alias] )
  (pass-word [_] )
  (write-out [_ out] [_ out pwd] ))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(decl-object CryptoStoreObj
  CryptoStore
  (add-key-entity [me gist pwd]
    (do->nil
      (.setKeyEntry ^KeyStore
                    (:store me)
                    (alias<>)
                    (:pkey gist)
                    (charsit pwd) (:chain gist))))
  (add-cert-entity [me cert]
    (do->nil
      (.setCertificateEntry ^KeyStore
                            (:store me) (alias<>) cert)))

  (trust-manager-factory [me]
    (doto (TrustManagerFactory/getInstance
            (TrustManagerFactory/getDefaultAlgorithm))
      (.init ^KeyStore (:store me))))

  (key-manager-factory [me]
    (doto (KeyManagerFactory/getInstance
            (KeyManagerFactory/getDefaultAlgorithm))
      (.init ^KeyStore (:store me) (:passwd me))))

  (cert-aliases [me] (filterEntries (:store me) :certs))
  (key-aliases [me] (filterEntries (:store me) :keys))
  (key-entity [me nm pwd] (pkeyGist<>
                          (:store me) nm (charsit pwd)))
  (key-entity [me pwd]
    (let [[f & more] (key-aliases me)]
      (if (and f (empty? more))
        (key-entity me (str f) pwd)
        (throwBadArg "Store has many keys"))))

  (cert-entity [me nm] (tcert<> (:store me) nm))
  (remove-entity [me nm]
    (let [a (str nm)
          {:keys [^KeyStore store]} me]
      (if (.containsAlias store a)
        (.deleteEntry store a))))

  (pass-word [me] (:passwd me))
  (write-out [me out pwd] (.store ^KeyStore (:store me) out (charsit pwd)))
  (write-out [me out] (write-out me out (:passwd me)))

  (trusted-certs [me]
    (mapv #(cert-entity me (str %)) (cert-aliases me)))

  (add-pkcs7 [me arg]
    (let [{:keys [store]} me]
      (doseq [c (convCerts arg)]
        (.setCertificateEntry ^KeyStore
                              store
                              (alias<>)
                              ^Certificate c)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn cryptoStore<> ""

  ([pwd] (cryptoStore<> nil pwd))
  ([] (cryptoStore<> nil))
  ([ks pwd]
   (object<> CryptoStoreObj
             {:store (or ks (pkcs12<>))
              :passwd (charsit pwd)})))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF

