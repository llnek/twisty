;; Copyright © 2013-2020, Kenneth Leung. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file epl-v10.html at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

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


