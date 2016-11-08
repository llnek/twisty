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

  (:require [czlab.crypto.stores :refer [cryptoStore<>]]
            [czlab.xlib.logging :as log])

  (:use [czlab.crypto.core]
        [czlab.xlib.str]
        [czlab.xlib.core])

  (:import [java.net URL]
           [javax.net.ssl
            TrustManager
            SSLEngine
            SSLContext
            X509TrustManager
            KeyManagerFactory
            TrustManagerFactory]
           [czlab.crypto
            PasswordAPI
            PKeyGist
            CryptoStoreAPI
            SSLTrustMgrFactory]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;(set! *warn-on-reflection* false)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn sslContext<>
  "Make a server-side SSLContext"
  {:tag SSLContext}

  ([pkey pwd] (sslContext<> pkey pwd nil))

  ([^PKeyGist pkey ^chars pwd flavor]
   (let
     [cs (-> (pkcsStore<>)
             (cryptoStore<> nil))
      ctx (-> (stror flavor "TLS")
              (SSLContext/getInstance ))]
     (.addKeyEntity cs pkey pwd)
     (.init ctx
            (-> (.keyManagerFactory cs)
                (.getKeyManagers ))
            (-> (.trustManagerFactory cs)
                (.getTrustManagers ))
            (rand<> true))
     ctx)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn sslClientCtx<>
  "A client-side SSLContext"
  ^SSLContext
  [ssl?]
  (if ssl?
    (doto (SSLContext/getInstance "TLS")
          (.init nil (SSLTrustMgrFactory/getTrustManagers) (rand<>)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


