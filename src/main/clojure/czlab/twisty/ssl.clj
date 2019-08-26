;; Copyright © 2013-2019, Kenneth Leung. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file epl-v10.html at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

(ns ^{:doc "SSL helpers."
      :author "Kenneth Leung"}

  czlab.twisty.ssl

  (:require [czlab.twisty.store :as st]
            [czlab.basal.log :as l]
            [czlab.twisty.core :as t]
            [czlab.basal.str :as s]
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
(def ^:private
  x-tmgr
  (reify X509TrustManager
    (checkClientTrusted [_ chain authType]
      (l/warn "skipcheck: client certificate: %s."
              (some-> ^X509Certificate
                      (first chain) .getSubjectDN)))
    (checkServerTrusted [_ chain authType]
      (l/warn "skipcheck: server certificate: %s."
              (some-> ^X509Certificate
                      (first chain) .getSubjectDN)))
    (getAcceptedIssuers [_] (c/vargs X509Certificate []))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn simple-trust-mgr<>
  "Checks nothing." ^X509TrustManager [] x-tmgr)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- simple-trust-managers
  [] (c/vargs TrustManager [(simple-trust-mgr<>)]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn ssl-trust-mgr-factory<> []
  (proxy [SSLTrustMgrFactory][]
    (engineGetTrustManagers [] (simple-trust-managers))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn ssl-context<>
  "Create a server-side ssl-context"
  {:tag SSLContext}
  ([pkey pwd]
   (ssl-context<> pkey pwd nil))
  ([pkey pwd flavor]
   (c/do-with
     [ctx (SSLContext/getInstance
            (s/stror flavor "TLS"))]
     (let [cs (st/crypto-store<>)]
       (st/cs-add-key-entity cs pkey pwd)
       (.init ctx
              (.getKeyManagers ^KeyManagerFactory
                               (st/cs-key-manager-factory cs))
              (.getTrustManagers ^TrustManagerFactory
                                 (st/cs-trust-manager-factory cs))
              (u/rand<> true))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn ssl-client-ctx<>
  "A client-side SSLContext"
  ^SSLContext
  [ssl?]
  (if ssl?
    (doto (SSLContext/getInstance "TLS")
          (.init nil (simple-trust-managers) (u/rand<>)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


