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

(ns ^{:doc "A Crypto store."
      :author "Kenneth Leung" }

  czlab.crypto.stores

  (:require [czlab.xlib.logging :as log])

  (:use [czlab.crypto.core]
        [czlab.xlib.core]
        [czlab.xlib.str])

  (:import [java.io File FileInputStream IOException InputStream]
           [javax.net.ssl KeyManagerFactory TrustManagerFactory]
           [czlab.crypto CryptoStoreAPI PKeyGist]
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
  "Create a crypto store"
  ^CryptoStoreAPI
  [^KeyStore store ^chars passwd]

  (reify CryptoStoreAPI

    (addKeyEntity [_ gist pwd]
      (.setKeyEntry store
                    (alias<>) (.pkey gist) pwd (.chain gist)))

    (addCertEntity [_ cert]
      (.setCertificateEntry store (alias<>) cert))

    (trustManagerFactory [_]
      (doto (TrustManagerFactory/getInstance
              (TrustManagerFactory/getDefaultAlgorithm))
            (.init store)))

    (keyManagerFactory [_]
      (doto (KeyManagerFactory/getInstance
              (KeyManagerFactory/getDefaultAlgorithm))
            (.init store passwd)))

    (certAliases [_] (filterEntries store :certs))
    (keyAliases [_] (filterEntries store :keys))

    (keyEntity [_ nm pwd] (pkeyGist<> store nm pwd))

    (keyEntity [this pwd]
      (let [a (.keyAliases this)]
        (if (== 1 (count a))
          (.keyEntity this (str (first a)) pwd)
          (throwBadArg "Store has many keys"))))

    (certEntity [_ nm] (tcert<> store nm))

    (removeEntity [_ nm]
      (if (.containsAlias store ^String nm)
        (.deleteEntry store ^String nm)))

    (intermediateCAs [_] nil) ;;(getCAs keystore true false))
    (rootCAs [_] nil) ;;(getCAs keystore false true))

    (trustedCerts [me]
      (map #(.certEntity me (str %1)) (.certAliases me)))

    (addPKCS7Entity [_ bits]
      (let [fac (CertificateFactory/getInstance "X.509")
            certs (.generateCertificates fac bits)]
        (doseq [c (seq certs)]
          (.setCertificateEntry store
                                (alias<>)
                                ^Certificate c))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


