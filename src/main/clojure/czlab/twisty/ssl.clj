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
;; Copyright © 2013-2022, Kenneth Leung. All rights reserved.

(ns czlab.twisty.ssl

  "SSL helpers."

  (:require [czlab.twisty.core :as t]
            [czlab.twisty.store :as st]
            [czlab.basal.util :as u]
            [czlab.basal.core :as c])

  (:import [java.security.cert X509Certificate]
           [czlab.twisty SSLTrustMgrFactory]
           [java.security KeyStore]
           [java.net URL]
           [javax.net.ssl
            TrustManager
            SSLEngine
            SSLContext
            X509TrustManager
            KeyManagerFactory
            TrustManagerFactory]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;(set! *warn-on-reflection* false)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(c/def- x-tmgr
  (reify X509TrustManager
    (checkClientTrusted [_ chain authType]
      (c/warn "skipcheck: client certificate: %s."
              (some-> ^X509Certificate
                      (first chain) .getSubjectDN)))
    (checkServerTrusted [_ chain authType]
      (c/warn "skipcheck: server certificate: %s."
              (some-> ^X509Certificate
                      (first chain) .getSubjectDN)))
    (getAcceptedIssuers [_] (c/vargs X509Certificate []))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn simple-trust-mgr<>

  "Checks nothing, a pass through."
  {:arglists '([])
   :tag X509TrustManager}
  []

  x-tmgr)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- simple-trust-managers

  [] (c/vargs TrustManager [(simple-trust-mgr<>)]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn ssl-trust-mgr-factory<>

  "Create a SSL Trust Manager Factory."
  {:arglists '([])}
  []

  (proxy [SSLTrustMgrFactory][]
    (engineGetTrustManagers [] (simple-trust-managers))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn ssl-context<>

  "Create a server-side ssl-context."
  {:tag SSLContext
   :arglists '([pkey pwd]
               [pkey pwd flavor])}

  ([pkey pwd]
   (ssl-context<> pkey pwd nil))

  ([pkey pwd flavor]
   (c/do-with
     [ctx (SSLContext/getInstance
            (c/stror flavor "TLS"))]
     (let [cs (st/crypto-store<>)]
       (st/add-key-entity cs pkey pwd)
       (.init ctx
              (.getKeyManagers ^KeyManagerFactory
                               (st/key-manager-factory cs))
              (.getTrustManagers ^TrustManagerFactory
                                 (st/trust-manager-factory cs))
              (u/rand<> true))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn ssl-client-ctx<>

  "Create a client-side SSLContext."
  {:tag SSLContext
   :arglists '([ssl?])}
  [ssl?]

  (if ssl?
    (doto (SSLContext/getInstance "TLS")
          (.init nil (simple-trust-managers) (u/rand<>)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


