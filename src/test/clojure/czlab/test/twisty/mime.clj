;; Copyright (c) 2013-2017, Kenneth Leung. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file epl-v10.html at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

(ns czlab.test.twisty.mime

  (:use [czlab.twisty.store]
        [czlab.twisty.codec]
        [czlab.twisty.smime]
        [czlab.twisty.core]
        [czlab.basal.core]
        [czlab.basal.io]
        [czlab.basal.meta]
        [clojure.test])

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
(def ^:private root-pfx (resBytes "czlab/test/twisty/test.pfx"))
(def ^:private help-me (.toCharArray "helpme"))
(def ^:private des-ede3-cbc CMSAlgorithm/DES_EDE3_CBC)
(def ^:private
  ^czlab.twisty.store.CryptoStore
  root-cs
  (cryptoStore<> (pkcs12<> root-pfx help-me) help-me))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(deftest czlabtesttwisty-mime

  (testing
    "related to: smime"
    (is (with-open [inp (resStream "czlab/test/twisty/mime.eml")]
          (let [msg (mimeMsg<> nil nil inp)
                ^Multipart mp (.getContent msg)]
            (and (>= (.indexOf
                       (.getContentType msg)
                       "multipart/mixed") 0)
                 (== (.getCount mp) 2)
                 (not (isDataSigned? mp))
                 (not (isDataCompressed? mp))
                 (not (isDataEncrypted? mp))))))

    (is (with-open [inp (resStream "czlab/test/twisty/mime.eml")]
          (let [g (key-entity root-cs help-me)
                msg (mimeMsg<> nil nil inp)
                rc (smimeDigSig (:pkey g)
                                msg
                                sha-512-rsa
                                (into [] (:chain g)))]
            (isDataSigned? rc))))

    (is (with-open [inp (resStream "czlab/test/twisty/mime.eml")]
          (let [g (key-entity root-cs help-me)
                msg (mimeMsg<> nil nil inp)
                rc (smimeDigSig (:pkey g)
                                (.getContent msg)
                                sha-512-rsa
                                (into [] (:chain g)))]
            (isDataSigned? rc))))

    (is (with-open [inp (resStream "czlab/test/twisty/mime.eml")]
          (let [g (key-entity root-cs help-me)
                msg (mimeMsg<> nil nil inp)
                bp (-> ^Multipart
                       (.getContent msg)
                       (.getBodyPart 1))
                rc (smimeDigSig (:pkey g)
                                bp
                                sha-512-rsa
                                (into [] (:chain g)))]
            (isDataSigned? rc))))

    (is (with-open [inp (resStream "czlab/test/twisty/mime.eml")]
          (let [g (key-entity root-cs help-me)
                mp (smimeDigSig (:pkey g)
                                (mimeMsg<> nil nil inp)
                                sha-512-rsa
                                (into [] (:chain g)))
                baos (baos<>)
                _ (doto (mimeMsg<> nil nil)
                    (.setContent (cast? Multipart mp))
                    .saveChanges
                    (.writeTo baos))
                msg3 (mimeMsg<> nil nil
                                (streamit (.toByteArray baos)))
                mp3 (.getContent msg3)
                rc (peekSmimeSignedContent mp3)]
            (ist? Multipart rc))))

    (is (with-open [inp (resStream "czlab/test/twisty/mime.eml")]
          (let [g (key-entity root-cs help-me)
                cs (into [] (:chain g))
                mp (smimeDigSig (:pkey g)
                                (mimeMsg<> nil nil inp)
                                sha-512-rsa
                                cs)
                baos (baos<>)
                _ (doto (mimeMsg<> nil nil)
                    (.setContent (cast? Multipart mp))
                    .saveChanges
                    (.writeTo baos))
                msg3 (mimeMsg<> nil nil
                                (streamit (.toByteArray baos)))
                mp3 (.getContent msg3)
                rc (testSmimeDigSig mp3 cs)]
            (and (map? rc)
                 (== (count rc) 2)
                 (ist? Multipart (:content rc))
                 (instBytes? (:digest rc))))))

    (is (let [s (SDataSource. (bytesit "yoyo-jojo") "text/plain")
              g (key-entity root-cs help-me)
              cs (into [] (:chain g))
              bp (doto (MimeBodyPart.)
                   (.setDataHandler (DataHandler. s)))
              ^BodyPart
              bp2 (smimeEncrypt (first cs)
                                des-ede3-cbc bp)
              baos (baos<>)
              _ (doto (mimeMsg<>)
                  (.setContent
                    (.getContent bp2)
                    (.getContentType bp2))
                  .saveChanges
                  (.writeTo baos))
              msg2 (mimeMsg<> (streamit (.toByteArray baos)))
              enc (isEncrypted? (.getContentType msg2))
              rc (smimeDecrypt msg2 [(:pkey g)])]
          (and (instBytes? rc)
               (> (.indexOf
                    (strit rc) "yoyo-jojo") 0))))

    (is (let [g (key-entity root-cs help-me)
              s2 (SDataSource.
                   (bytesit "what's up dawg") "text/plain")
              s1 (SDataSource.
                   (bytesit "hello world") "text/plain")
              cs (into [] (:chain g))
              bp2 (doto (MimeBodyPart.)
                    (.setDataHandler (DataHandler. s2)))
              bp1 (doto (MimeBodyPart.)
                    (.setDataHandler (DataHandler. s1)))
              mp (doto (MimeMultipart.)
                   (.addBodyPart bp1)
                   (.addBodyPart bp2))
              msg (doto (mimeMsg<>) (.setContent mp))
              ^BodyPart
              bp3 (smimeEncrypt (first cs) des-ede3-cbc msg)
              baos (baos<>)
              _ (doto (mimeMsg<>)
                  (.setContent
                    (.getContent bp3)
                    (.getContentType bp3))
                  .saveChanges
                  (.writeTo baos))
              msg3 (mimeMsg<> (streamit (.toByteArray baos)))
              enc (isEncrypted? (.getContentType msg3))
              rc (smimeDecrypt msg3 [(:pkey g)])]
          (and (instBytes? rc)
               (> (.indexOf (strit rc) "what's up dawg") 0)
               (> (.indexOf (strit rc) "hello world") 0))))

    (is (let [data (xdata<> "heeloo world")
              g (key-entity root-cs help-me)
              cs (into [] (:chain g))
              sig (pkcsDigSig (:pkey g) cs sha-512-rsa data)
              dg (testPkcsDigSig (first cs) data sig)]
          (and dg (instBytes? dg))))

    (is (with-open [inp (resStream "czlab/test/twisty/mime.eml")]
          (let [msg (mimeMsg<> "" (char-array 0) inp)
                bp (smimeDeflate msg)
                ^XData x (smimeInflate bp)]
            (and x (> (alength (.getBytes x)) 0)))))

    (is (let [bp (smimeDeflate "text/plain"
                               (xdata<> "heeloo world"))
              baos (baos<>)
              ^XData x (smimeInflate bp)]
          (and x (> (alength (.getBytes x)) 0))))

    (is (let [bp (smimeDeflate "text/plain"
                                (xdata<> "heeloo world")
                                "blah-blah"
                                "some-id")
              baos (baos<>)
              ^XData x (smimeInflate bp)]
          (and x (> (alength (.getBytes x)) 0)))))

  (testing
    "related to: digest"
    (is (let [f (digest<> (bytesit "heeloo world") :sha-1)]
          (and f (> (.length f) 0))))

    (is (let [f (digest<> (bytesit "heeloo world") :md5)]
          (and f (> (.length f) 0))))

    (is (let [f (digest<> (bytesit "heeloo world") :sha-1)
              g (digest<> (bytesit "heeloo world") :md5)]
          (if (= f g) false true)))

    (is (let [f (digest<> (bytesit "heeloo world") :sha-1)
              g (digest<> (bytesit "heeloo world") :sha-1)]
          (= f g)))

    (is (let [f (digest<> (bytesit "heeloo world") :md5)
              g (digest<> (bytesit "heeloo world") :md5)]
          (= f g))))

  (is (string? "That's all folks!")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


