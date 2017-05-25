;; Copyright (c) 2013-2017, Kenneth Leung. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file epl-v10.html at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

(ns czlab.test.twisty.mime

  (:require [czlab.twisty.store :as st]
            [czlab.twisty.codec :as cc]
            [czlab.twisty.smime :as sm]
            [czlab.twisty.core :as t]
            [czlab.basal.core :as c]
            [czlab.basal.io :as i]
            [czlab.basal.meta :as m])

  (:use [clojure.test])

  (:import [javax.mail.internet MimeBodyPart MimeMessage MimeMultipart]
           [java.io File InputStream ByteArrayOutputStream]
           [org.bouncycastle.cms CMSAlgorithm]
           [java.security Policy
            KeyStore
            KeyStore$PrivateKeyEntry
            KeyStore$TrustedCertificateEntry SecureRandom]
           [javax.activation DataHandler DataSource]
           [java.util Date GregorianCalendar]
           [javax.mail Multipart BodyPart]
           [czlab.jasal XData SDataSource]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(def ^:private root-pfx (c/resBytes "czlab/test/twisty/test.pfx"))
(def ^:private help-me (c/charsit "helpme"))
(def ^:private des-ede3-cbc CMSAlgorithm/DES_EDE3_CBC)
(def ^:private
  root-cs
  (st/cryptoStore<> (t/pkcs12<> root-pfx help-me) help-me))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(deftest czlabtesttwisty-mime

  (testing
    "related to: smime"
    (is (with-open [inp (c/resStream "czlab/test/twisty/mime.eml")]
          (let [msg (t/mimeMsg<> nil nil inp)
                ^Multipart mp (.getContent msg)]
            (and (>= (.indexOf
                       (.getContentType msg)
                       "multipart/mixed") 0)
                 (== (.getCount mp) 2)
                 (not (t/isDataSigned? mp))
                 (not (t/isDataCompressed? mp))
                 (not (t/isDataEncrypted? mp))))))

    (is (with-open [inp (c/resStream "czlab/test/twisty/mime.eml")]
          (let [g (st/key-entity root-cs help-me)
                msg (t/mimeMsg<> nil nil inp)
                rc (sm/smimeDigSig (:pkey g)
                                   msg
                                   t/sha-512-rsa
                                   (into [] (:chain g)))]
            (t/isDataSigned? rc))))

    (is (with-open [inp (c/resStream "czlab/test/twisty/mime.eml")]
          (let [g (st/key-entity root-cs help-me)
                msg (t/mimeMsg<> nil nil inp)
                rc (sm/smimeDigSig (:pkey g)
                                   (.getContent msg)
                                   t/sha-512-rsa
                                   (into [] (:chain g)))]
            (t/isDataSigned? rc))))

    (is (with-open [inp (c/resStream "czlab/test/twisty/mime.eml")]
          (let [g (st/key-entity root-cs help-me)
                msg (t/mimeMsg<> nil nil inp)
                bp (-> ^Multipart
                       (.getContent msg)
                       (.getBodyPart 1))
                rc (sm/smimeDigSig (:pkey g)
                                bp
                                t/sha-512-rsa
                                (into [] (:chain g)))]
            (t/isDataSigned? rc))))

    (is (with-open [inp (c/resStream "czlab/test/twisty/mime.eml")]
          (let [g (st/key-entity root-cs help-me)
                mp (sm/smimeDigSig (:pkey g)
                                   (t/mimeMsg<> nil nil inp)
                                   t/sha-512-rsa
                                   (into [] (:chain g)))
                baos (i/baos<>)
                _ (doto (t/mimeMsg<> nil nil)
                    (.setContent (c/cast? Multipart mp))
                    .saveChanges
                    (.writeTo baos))
                msg3 (t/mimeMsg<> nil nil
                                  (i/streamit baos))
                mp3 (.getContent msg3)
                rc (sm/peekSmimeSignedContent mp3)]
            (c/ist? Multipart rc))))

    (is (with-open [inp (c/resStream "czlab/test/twisty/mime.eml")]
          (let [g (st/key-entity root-cs help-me)
                cs (into [] (:chain g))
                mp (sm/smimeDigSig (:pkey g)
                                   (t/mimeMsg<> nil nil inp)
                                   t/sha-512-rsa
                                   cs)
                baos (i/baos<>)
                _ (doto (t/mimeMsg<> nil nil)
                    (.setContent (c/cast? Multipart mp))
                    .saveChanges
                    (.writeTo baos))
                msg3 (t/mimeMsg<> nil nil
                                  (i/streamit baos))
                mp3 (.getContent msg3)
                rc (sm/testSmimeDigSig mp3 cs)]
            (and (map? rc)
                 (== (count rc) 2)
                 (c/ist? Multipart (:content rc))
                 (m/instBytes? (:digest rc))))))

    (is (let [s (SDataSource. (c/bytesit "yoyo-jojo") "text/plain")
              g (st/key-entity root-cs help-me)
              cs (into [] (:chain g))
              bp (doto (MimeBodyPart.)
                   (.setDataHandler (DataHandler. s)))
              ^BodyPart
              bp2 (sm/smimeEncrypt (first cs)
                                   des-ede3-cbc bp)
              baos (i/baos<>)
              _ (doto (t/mimeMsg<>)
                  (.setContent
                    (.getContent bp2)
                    (.getContentType bp2))
                  .saveChanges
                  (.writeTo baos))
              msg2 (t/mimeMsg<> (i/streamit baos))
              enc (t/isEncrypted? (.getContentType msg2))
              rc (sm/smimeDecrypt msg2 [(:pkey g)])]
          (and (m/instBytes? rc)
               (> (.indexOf
                    (c/strit rc) "yoyo-jojo") 0))))

    (is (let [g (st/key-entity root-cs help-me)
              s2 (SDataSource.
                   (c/bytesit "what's up dawg") "text/plain")
              s1 (SDataSource.
                   (c/bytesit "hello world") "text/plain")
              cs (into [] (:chain g))
              bp2 (doto (MimeBodyPart.)
                    (.setDataHandler (DataHandler. s2)))
              bp1 (doto (MimeBodyPart.)
                    (.setDataHandler (DataHandler. s1)))
              mp (doto (MimeMultipart.)
                   (.addBodyPart bp1)
                   (.addBodyPart bp2))
              msg (doto (t/mimeMsg<>) (.setContent mp))
              ^BodyPart
              bp3 (sm/smimeEncrypt (first cs) des-ede3-cbc msg)
              baos (i/baos<>)
              _ (doto (t/mimeMsg<>)
                  (.setContent
                    (.getContent bp3)
                    (.getContentType bp3))
                  .saveChanges
                  (.writeTo baos))
              msg3 (t/mimeMsg<> (i/streamit baos))
              enc (t/isEncrypted? (.getContentType msg3))
              rc (sm/smimeDecrypt msg3 [(:pkey g)])]
          (and (m/instBytes? rc)
               (> (.indexOf (c/strit rc) "what's up dawg") 0)
               (> (.indexOf (c/strit rc) "hello world") 0))))

    (is (let [data (i/xdata<> "heeloo world")
              g (st/key-entity root-cs help-me)
              cs (into [] (:chain g))
              sig (sm/pkcsDigSig (:pkey g) cs t/sha-512-rsa data)
              dg (sm/testPkcsDigSig (first cs) data sig)]
          (and dg (m/instBytes? dg))))

    (is (with-open [inp (c/resStream "czlab/test/twisty/mime.eml")]
          (let [msg (t/mimeMsg<> "" (char-array 0) inp)
                bp (sm/smimeDeflate msg)
                ^XData x (sm/smimeInflate bp)]
            (and x (> (alength (.getBytes x)) 0)))))

    (is (let [bp (sm/smimeDeflate "text/plain"
                                  (i/xdata<> "heeloo world"))
              baos (i/baos<>)
              ^XData x (sm/smimeInflate bp)]
          (and x (> (alength (.getBytes x)) 0))))

    (is (let [bp (sm/smimeDeflate "text/plain"
                                  (i/xdata<> "heeloo world")
                                  "blah-blah"
                                  "some-id")
              baos (i/baos<>)
              ^XData x (sm/smimeInflate bp)]
          (and x (> (alength (.getBytes x)) 0)))))

  (testing
    "related to: digest"
    (is (let [f (t/fingerprint (c/bytesit "heeloo world") :sha-1)]
          (and f (> (.length f) 0))))

    (is (let [f (t/fingerprint (c/bytesit "heeloo world") :md5)]
          (and f (> (.length f) 0))))

    (is (let [f (t/fingerprint (c/bytesit "heeloo world") :sha-1)
              g (t/fingerprint (c/bytesit "heeloo world") :md5)]
          (if (= f g) false true)))

    (is (let [f (t/fingerprint (c/bytesit "heeloo world") :sha-1)
              g (t/fingerprint (c/bytesit "heeloo world") :sha-1)]
          (= f g)))

    (is (let [f (t/fingerprint (c/bytesit "heeloo world") :md5)
              g (t/fingerprint (c/bytesit "heeloo world") :md5)]
          (= f g))))

  (is (string? "That's all folks!")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


