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

(ns ^{:doc "SSL helpers."
      :author "Kenneth Leung" }

  czlab.crypto.ssl

  (:require
    [czlab.crypto.stores :refer [cryptoStore<>]]
    [czlab.xlib.core :refer [srandom<>]]
    [czlab.xlib.str :refer [stror]]
    [czlab.xlib.logging :as log]
    [czlab.crypto.core
     :refer [jksFile?
             jksStore<>
             pkcsStore<>]])

  (:import
    [javax.net.ssl X509TrustManager TrustManager]
    [javax.net.ssl SSLEngine SSLContext]
    [czlab.crypto
     PasswordAPI
     CryptoStoreAPI
     SSLTrustMgrFactory]
    [java.net URL]
    [javax.net.ssl KeyManagerFactory TrustManagerFactory]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;(set! *warn-on-reflection* false)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn sslContext

  "Make a server-side SSLContext"

  ^SSLContext
  [^URL keyUrl ^chars pwd & [flavor]]

  (let
    [ks (with-open
          [inp (.openStream keyUrl)]
          (if (jksFile? keyUrl)
            (getJksStore inp pwd)
            (getPkcsStore inp pwd)))
     cs (cryptoStore<> ks pwd)
     tmf (.trustManagerFactory cs)
     kmf (.keyManagerFactory cs)
     ctx (-> ^String
             (stror flavor "TLS")
             (SSLContext/getInstance ))]
    (.init ctx
           (.getKeyManagers kmf)
           (.getTrustManagers tmf)
           (srandom<>))
    ctx))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn sslClientCtx

  "Make a client-side SSLContext"
  ^SSLContext
  [ssl?]

  (when ssl?
    (doto (SSLContext/getInstance "TLS")
          (.init nil (SSLTrustMgrFactory/getTrustManagers) (srandom<>)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


