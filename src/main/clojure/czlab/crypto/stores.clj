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


(ns ^{:doc ""
      :author "kenl" }

  czlab.crypto.stores

  (:require
    [czlab.xlib.core :refer [throwBadArg]]
    [czlab.crypto.core
     :refer [newAlias certAliases
             pkeyAliases
             getPKey getCert
             getPkcsStore getJksStore]]
    [czlab.xlib.logging :as log]
    [czlab.xlib.str :refer [hgl?]])

  (:import
    [java.security.cert CertificateFactory X509Certificate Certificate]
    [czlab.crypto PasswordAPI CryptoStoreAPI]
    [java.io File FileInputStream IOException InputStream]
    [javax.net.ssl KeyManagerFactory TrustManagerFactory]
    [java.security KeyStore PrivateKey
    KeyStore$TrustedCertificateEntry
    KeyStore$ProtectionParameter
    KeyStore$PasswordProtection
    KeyStore$PrivateKeyEntry]
    [javax.security.auth.x500 X500Principal]))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;(set! *warn-on-reflection* false)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- onNewKey

  "Insert private key & certs into this keystore"

  [^KeyStore keystore
   ^String nm
   ^KeyStore$PrivateKeyEntry pkey
   ^chars pwd]

  (when-some [cc (.getCertificateChain pkey)]
    (doseq [^Certificate c cc]
      (.setCertificateEntry keystore (newAlias) c))
    (->> (KeyStore$PasswordProtection. pwd)
         (.setEntry keystore nm pkey ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- getCAs ""

  [^KeyStore keystore tca root]

  (loop [en (.aliases keystore)
         rc (transient []) ]
    (if (not (.hasMoreElements en))
      (persistent! rc)
      (if-some [^KeyStore$TrustedCertificateEntry
               ce (getCert keystore (.nextElement en)) ]
        (let [^X509Certificate cert (.getTrustedCertificate ce)
              issuer (.getIssuerX500Principal cert)
              subj (.getSubjectX500Principal cert)
              matched (and (some? issuer)
                           (= issuer subj)) ]
          (if (or (and root (not matched)) (and tca matched))
            (recur en rc)
            (recur en (conj! rc cert))))
        (recur en rc)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- mkstore ""

  ^KeyStore
  [^KeyStore keystore]

  (condp = (.getType keystore)
    "PKCS12" (getPkcsStore)
    "JKS" (getJksStore)
    (throwBadArg "wrong keystore type.")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn cryptoStore

  "Create a crypto store"

  ^CryptoStoreAPI
  [^KeyStore keystore ^PasswordAPI passwdObj]

  (reify

    CryptoStoreAPI

    (addKeyEntity [this bits pwdObj]
      ;; we load the p12 content into an empty keystore, then extract the entry
      ;; and insert it into the current one.
      (let [ch (.toCharArray ^PasswordAPI pwdObj)
            tmp (doto (mkstore keystore) (.load bits ch))
            pkey (getPKey tmp (-> (.aliases tmp)
                                  (.nextElement)) ch) ]
        (onNewKey this (newAlias) pkey ch)))

    (addCertEntity [_ bits]
      (let [fac (CertificateFactory/getInstance "X.509")
            ^X509Certificate c (.generateCertificate fac bits) ]
        (.setCertificateEntry keystore (newAlias) c)))

    (trustManagerFactory [_]
      (doto (TrustManagerFactory/getInstance (TrustManagerFactory/getDefaultAlgorithm))
            (.init keystore)))

    (keyManagerFactory [_]
      (doto (KeyManagerFactory/getInstance (KeyManagerFactory/getDefaultAlgorithm))
            (.init keystore  (.toCharArray passwdObj))))

    (certAliases [_] (certAliases keystore))
    (keyAliases [_] (pkeyAliases keystore))

    (keyEntity [_ nm pwdObj]
      (let [ca (.toCharArray ^PasswordAPI pwdObj) ]
        (getPKey keystore nm ca)))

    (certEntity [_ nm]
      (getCert keystore nm))

    (removeEntity [_ nm]
      (when (.containsAlias keystore ^String nm)
        (.deleteEntry keystore ^String nm)))

    (intermediateCAs [_] (getCAs keystore true false))
    (rootCAs [_] (getCAs keystore false true))

    (trustedCerts [me]
      (map #(let [^KeyStore$TrustedCertificateEntry
                  tc (.certEntity me (str %1)) ]
              (.getTrustedCertificate tc))
           (.certAliases me)))

    (addPKCS7Entity [_ bits]
      (let [fac (CertificateFactory/getInstance "X.509")
            certs (.generateCertificates fac bits) ]
        (doseq [^X509Certificate c (seq certs) ]
          (.setCertificateEntry keystore (newAlias) c))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


