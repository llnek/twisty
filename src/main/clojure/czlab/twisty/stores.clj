;; Copyright (c) 2013-2017, Kenneth Leung. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file epl-v10.html at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

(ns ^{:doc "A Crypto store."
      :author "Kenneth Leung"}

  czlab.twisty.stores

  (:require [czlab.basal.logging :as log])

  (:use [czlab.twisty.core]
        [czlab.basal.core]
        [czlab.basal.str])

  (:import [java.io File FileInputStream IOException InputStream]
           [javax.net.ssl KeyManagerFactory TrustManagerFactory]
           [czlab.twisty CryptoStore PKeyGist]
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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn cryptoStore<>
  "Create a crypto store" {:tag CryptoStore}

  ([pwd] (cryptoStore<> (pkcsStore<> nil pwd)))
  ([] (cryptoStore<> (pkcsStore<>)))
  ([^KeyStore store ^chars passwd]
   {:pre [(some? store)]}
   (reify CryptoStore
     (addKeyEntity [_ gist pwd]
       (.setKeyEntry store
                     (alias<>) (.pkey gist) pwd (.chain gist)))
     (addCertEntity [_ cert]
       (.setCertificateEntry store (alias<>) cert))
     (trustManagerFactory [_]
       (doto (-> (TrustManagerFactory/getDefaultAlgorithm)
                 TrustManagerFactory/getInstance)
             (.init store)))
     (keyManagerFactory [_]
       (doto (-> (KeyManagerFactory/getDefaultAlgorithm)
                 KeyManagerFactory/getInstance)
             (.init store passwd)))
     (certAliases [_] (filterEntries store :certs))
     (keyAliases [_] (filterEntries store :keys))
     (keyEntity [_ nm pwd] (pkeyGist<> store nm pwd))
     (keyEntity [this pwd]
       (let [[f & more] (.keyAliases this)]
         (if (and f (empty? more))
           (.keyEntity this (str f) pwd)
           (throwBadArg "Store has many keys"))))
     (certEntity [_ nm] (tcert<> store nm))
     (removeEntity [_ nm]
       (if (.containsAlias store ^String nm)
         (.deleteEntry store ^String nm)))
     (intermediateCAs [_] nil) ;;(getCAs keystore true false))
     (rootCAs [_] nil) ;;(getCAs keystore false true))
     (intern [_] store)
     (password [_] passwd)
     (write [_ out pwd] (.store store out pwd))
     (write [me out] (.write me out passwd))
     (trustedCerts [me]
       (mapv #(.certEntity me (str %)) (.certAliases me)))
     (addPKCS7Entity [_ arg]
       (doseq [c (convCerts arg)]
         (.setCertificateEntry store
                               (alias<>)
                               ^Certificate c))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF

