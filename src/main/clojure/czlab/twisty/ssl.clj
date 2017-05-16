;; Copyright (c) 2013-2017, Kenneth Leung. All rights reserved.
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
            [czlab.basal.log :as log]
            [czlab.twisty.core :as t]
            [czlab.basal.str :as s]
            [czlab.basal.core :as c])

  (:import [java.security.cert X509Certificate]
           [czlab.jasal SSLTrustMgrFactory]
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
;;
(def ^:private
  x-tmgr
  (reify X509TrustManager
    (checkClientTrusted [_ chain authType]
      (log/warn "skipcheck: client certificate: %s"
                (some-> ^X509Certificate
                        (first chain) .getSubjectDN)))
    (checkServerTrusted [_ chain authType]
      (log/warn "skipcheck: server certificate: %s"
                (some-> ^X509Certificate
                        (first chain) .getSubjectDN)))
    (getAcceptedIssuers [_] (c/vargs X509Certificate []))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn simpleTrustMgr<> "Checks nothing" ^X509TrustManager [] x-tmgr)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- simpleTrustManagers
  "" [] (c/vargs TrustManager [(simpleTrustMgr<>)]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn sslTrustMgrFactory<> "" []
  (proxy [SSLTrustMgrFactory][]
    (engineGetTrustManagers [] (simpleTrustManagers))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn sslContext<>
  "Create a server-side ssl-context" {:tag SSLContext}

  ([pkey pwd] (sslContext<> pkey pwd nil))

  ([pkey pwd flavor]
   (let
     [ctx (SSLContext/getInstance
            (s/stror flavor "TLS"))
      cs (st/cryptoStore<>)]
     (st/add-key-entity cs pkey pwd)
     (.init ctx
            (.getKeyManagers ^KeyManagerFactory (st/key-manager-factory cs))
            (.getTrustManagers ^TrustManagerFactory (st/trust-manager-factory cs))
            (c/rand<> true))
     ctx)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn sslClientCtx<>
  "A client-side SSLContext"
  ^SSLContext
  [ssl?]
  (if ssl?
    (doto (SSLContext/getInstance "TLS")
          (.init nil (simpleTrustManagers) (c/rand<>)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


