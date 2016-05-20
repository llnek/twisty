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

  czlab.crypto.ssl

  (:require
    [czlab.crypto.stores :refer [cryptoStore]]
    [czlab.xlib.core :refer [newRandom]]
    [czlab.xlib.logging :as log]
    [czlab.crypto.core
     :refer [pkcsFile? getJksStore getPkcsStore]])

  (:import
    [javax.net.ssl X509TrustManager TrustManager]
    [javax.net.ssl SSLEngine SSLContext]
    [czlab.crypto SSLTrustMgrFactory
     PasswordAPI CryptoStoreAPI]
    [java.net URL]
    [javax.net.ssl KeyManagerFactory TrustManagerFactory]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;(set! *warn-on-reflection* false)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn sslContext

  "Make a server-side SSLContext"

  ^SSLContext
  [^URL keyUrl
   ^PasswordAPI pwdObj & [flavor]]

  (let
    [ks (with-open
          [inp (.openStream keyUrl)]
          (if (pkcsFile? keyUrl)
            (getPkcsStore inp pwdObj)
            (getJksStore inp pwdObj)))
     cs (cryptoStore ks pwdObj)
     tmf (.trustManagerFactory cs)
     kmf (.keyManagerFactory cs)
     ctx (->> (str (or flavor "TLS"))
              (SSLContext/getInstance ))]
    (.init ctx
           (.getKeyManagers kmf)
           (.getTrustManagers tmf)
           (newRandom))
    ctx))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn sslClientCtx

  "Make a client-side SSLContext"

  ^SSLContext
  [ssl]

  (when ssl
    (doto (SSLContext/getInstance "TLS")
          (.init nil (SSLTrustMgrFactory/getTrustManagers) (newRandom)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


