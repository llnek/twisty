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
(defprotocol ICryptoStore
  (keyEntity [_ pwd] [_ alias pwd] )
  (certEntity [_ alias] )
  (intermediateCAs [_] )
  (rootCAs [_] )
  (trustedCerts [_] )
  (addKeyEntity [_ gist pwd])
  (trustManagerFactory [_] )
  (keyManagerFactory [_] )
  (certAliases [_])
  (keyAliases [_] )
  (addCertEntity [_ cert] )
  (addPKCS7Entity [_ arg] )
  (removeEntity [_ alias] )
  (password [_] )
  (write [_ out] [_ out pwd] ))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defstateful CryptoStore
  ICryptoStore
  (addKeyEntity [_ gist pwd]
    (do->nil
      (.setKeyEntry ^KeyStore
                    (:store @data)
                    (alias<>)
                    (:pkey @gist)
                    (charsit pwd) (:chain @gist))))
  (addCertEntity [_ cert]
    (do->nil
      (.setCertificateEntry ^KeyStore
                            (:store @data) (alias<>) cert)))

  (trustManagerFactory [_]
    (doto (TrustManagerFactory/getInstance
            (TrustManagerFactory/getDefaultAlgorithm))
      (.init ^KeyStore (:store @data))))

  (keyManagerFactory [_]
    (doto (KeyManagerFactory/getInstance
            (KeyManagerFactory/getDefaultAlgorithm))
      (.init ^KeyStore (:store @data) (:passwd @data))))

  (certAliases [_] (filterEntries (:store @data) :certs))
  (keyAliases [_] (filterEntries (:store @data) :keys))
  (keyEntity [_ nm pwd] (pkeyGist<>
                          (:store @data) nm (charsit pwd)))
  (keyEntity [me pwd]
    (let [[f & more] (.keyAliases me)]
      (if (and f (empty? more))
        (.keyEntity me (str f) pwd)
        (throwBadArg "Store has many keys"))))

  (certEntity [_ nm] (tcert<> (:store @data) nm))
  (removeEntity [_ nm]
    (let [a (str nm)
          {:keys [^KeyStore store]} @data]
      (if (.containsAlias store a)
        (.deleteEntry store a))))

  (intermediateCAs [_] nil) ;;(getCAs keystore true false))
  (rootCAs [_] nil) ;;(getCAs keystore false true))
  (password [_] (:passwd @data))
  (write [_ out pwd] (.store ^KeyStore (:store @data) out (charsit pwd)))
  (write [me out] (.write me out (:passwd @data)))

  (trustedCerts [me]
    (mapv #(.certEntity me (str %)) (.certAliases me)))

  (addPKCS7Entity [_ arg]
    (let [{:keys [store]} @data]
      (doseq [c (convCerts arg)]
        (.setCertificateEntry ^KeyStore
                              store
                              (alias<>)
                              ^Certificate c)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn cryptoStore<>
  "" {:tag czlab.twisty.store.CryptoStore}

  ([pwd] (cryptoStore<> nil pwd))
  ([] (cryptoStore<> nil))
  ([ks pwd]
   (entity<> CryptoStore
              {:store (or ks (pkcs12<>))
               :passwd (charsit pwd)})))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF

