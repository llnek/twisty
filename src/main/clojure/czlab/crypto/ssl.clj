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

  czlab.xlib.crypto.ssl

  (:require
    [czlab.xlib.crypto.stores :refer [CryptoStore*]]
    [czlab.xlib.util.core :refer [NewRandom]]
    [czlab.xlib.util.logging :as log]
    [czlab.xlib.crypto.core
    :refer [PkcsFile? GetJksStore GetPkcsStore ]])

  (:import
    [javax.net.ssl X509TrustManager TrustManager]
    [javax.net.ssl SSLEngine SSLContext]
    [com.zotohlab.frwk.net SSLTrustMgrFactory]
    [com.zotohlab.frwk.crypto PasswordAPI CryptoStoreAPI]
    [java.net URL]
    [javax.net.ssl KeyManagerFactory TrustManagerFactory]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;(set! *warn-on-reflection* false)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn SslContext*

  "Make a server-side SSLContext"

  ^SSLContext
  [^URL keyUrl
   ^PasswordAPI pwdObj & [flavor] ]

  (let
    [ks (with-open
          [inp (.openStream keyUrl) ]
          (if (PkcsFile? keyUrl)
            (GetPkcsStore inp pwdObj)
            (GetJksStore inp pwdObj)))
     cs (CryptoStore* ks pwdObj)
     tmf (.trustManagerFactory cs)
     kmf (.keyManagerFactory cs)
     ctx (->> (str (or flavor "TLS"))
              (SSLContext/getInstance )) ]
    (.init ctx
           (.getKeyManagers kmf)
           (.getTrustManagers tmf)
           (NewRandom))
    ctx))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn SslClientCtx*

  "Make a client-side SSLContext"

  ^SSLContext
  [ssl]

  (when ssl
    (doto (SSLContext/getInstance "TLS")
          (.init nil (SSLTrustMgrFactory/getTrustManagers) (NewRandom)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF

