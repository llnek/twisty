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

  (:require [czlab.twisty.stores :refer [cryptoStore<>]]
            [czlab.basal.logging :as log])

  (:use [czlab.twisty.core]
        [czlab.basal.str]
        [czlab.basal.core])

  (:import [java.security.cert X509Certificate]
           [java.security KeyStore]
           [java.net URL]
           [czlab.twisty
            IPassword
            PKeyGist
            CryptoStore
            SSLTrustMgrFactory]
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
(def
  ^:private
  ^X509TrustManager
  x-tmgr
  (reify X509TrustManager
    (checkClientTrusted [_ chain authType]
      (log/warn "SkipCheck: CLIENT CERTIFICATE: %s"
                (some-> ^X509Certificate
                        (first chain) .getSubjectDN)))
    (checkServerTrusted [_ chain authType]
      (log/warn "SkipCheck: SERVER CERTIFICATE: %s"
                (some-> ^X509Certificate
                        (first chain) .getSubjectDN)))
    (getAcceptedIssuers [_] (vargs X509Certificate []))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn simpleTrustMgr<> "Checks nothing" ^X509TrustManager [] x-tmgr)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- simpleTrustManagers
  "" [] (vargs TrustManager [(simpleTrustMgr<>)]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn sslTrustMgrFactory<>
  ""
  []
  (proxy [SSLTrustMgrFactory][]
    (engineGetTrustManagers []
      (simpleTrustManagers))))

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
              SSLContext/getInstance)]
     (.addKeyEntity cs pkey pwd)
     (.init ctx
            (-> (.keyManagerFactory cs)
                .getKeyManagers )
            (-> (.trustManagerFactory cs)
                .getTrustManagers )
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
          (.init nil (simpleTrustManagers) (rand<>)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


