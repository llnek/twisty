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

(ns

  czlabtest.crypto.mime

  (:use [czlab.crypto.stores]
        [czlab.crypto.codec]
        [czlab.crypto.smime]
        [czlab.crypto.core]
        [czlab.xlib.core]
        [czlab.xlib.io]
        [czlab.xlib.meta]
        [clojure.test])

  (:import [javax.mail.internet MimeBodyPart MimeMessage MimeMultipart]
           [czlab.crypto PKeyGist IPassword CryptoStore]
           [java.io File InputStream ByteArrayOutputStream]
           [org.bouncycastle.cms CMSAlgorithm]
           [java.security Policy
            KeyStore
            KeyStore$PrivateKeyEntry
            KeyStore$TrustedCertificateEntry SecureRandom]
           [javax.activation DataHandler DataSource]
           [java.util Date GregorianCalendar]
           [javax.mail Multipart BodyPart]
           [czlab.xlib XData]
           [czlab.crypto SDataSource]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(def ^:private ROOTPFX (resBytes "czlab/crypto/test.pfx"))
(def ^:private HELPME (.toCharArray "helpme"))
(def ^:private DES_EDE3_CBC CMSAlgorithm/DES_EDE3_CBC)
(def ^:private
  ^CryptoStore
  ROOTCS
  (cryptoStore<> (initStore! (pkcsStore<>)
                             ROOTPFX HELPME) HELPME))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(deftest czlabtestcrypto-mimestuff

  (is (with-open [inp (resStream "czlab/crypto/mime.eml")]
        (let [msg (mimeMsg<> nil nil inp)
              ^Multipart mp (.getContent msg)]
          (and (>= (.indexOf
                     (.getContentType msg)
                     "multipart/mixed") 0)
               (== (.getCount mp) 2)
               (not (isDataSigned? mp))
               (not (isDataCompressed? mp))
               (not (isDataEncrypted? mp))))))

  (is (with-open [inp (resStream "czlab/crypto/mime.eml")]
        (let [g (.keyEntity ROOTCS HELPME)
              msg (mimeMsg<> nil nil inp)
              rc (smimeDigSig (.pkey g)
                              msg
                              SHA512RSA
                              (into [] (.chain g)))]
          (isDataSigned? rc))))

  (is (with-open [inp (resStream "czlab/crypto/mime.eml")]
        (let [g (.keyEntity ROOTCS HELPME)
              msg (mimeMsg<> nil nil inp)
              rc (smimeDigSig (.pkey g)
                              (.getContent msg)
                              SHA512RSA
                              (into [] (.chain g)))]
          (isDataSigned? rc))))

  (is (with-open [inp (resStream "czlab/crypto/mime.eml")]
        (let [g (.keyEntity ROOTCS HELPME)
              msg (mimeMsg<> nil nil inp)
              bp (-> ^Multipart
                     (.getContent msg)
                     (.getBodyPart 1))
              rc (smimeDigSig (.pkey g)
                              bp
                              SHA512RSA
                              (into [] (.chain g)))]
          (isDataSigned? rc))))

  (is (with-open [inp (resStream "czlab/crypto/mime.eml")]
        (let [g (.keyEntity ROOTCS HELPME)
              mp (smimeDigSig (.pkey g)
                              (mimeMsg<> nil nil inp)
                              SHA512RSA
                              (into [] (.chain g)))
              baos (baos<>)
              _ (doto (mimeMsg<> nil nil)
                  (.setContent (cast? Multipart mp))
                  (.saveChanges)
                  (.writeTo baos))
              msg3 (mimeMsg<> nil nil
                              (streamify (.toByteArray baos)))
              mp3 (.getContent msg3)
              rc (peekSmimeSignedContent mp3)]
          (inst? Multipart rc))))

  (is (with-open [inp (resStream "czlab/crypto/mime.eml")]
        (let [g (.keyEntity ROOTCS HELPME)
              cs (into [] (.chain g))
              mp (smimeDigSig (.pkey g)
                              (mimeMsg<> nil nil inp)
                              SHA512RSA
                              cs)
              baos (baos<>)
              _ (doto (mimeMsg<> nil nil)
                  (.setContent (cast? Multipart mp))
                  (.saveChanges)
                  (.writeTo baos))
              msg3 (mimeMsg<> nil nil
                              (streamify (.toByteArray baos)))
              mp3 (.getContent msg3)
              rc (testSmimeDigSig mp3 cs)]
          (and (map? rc)
               (== (count rc) 2)
               (inst? Multipart (:content rc))
               (instBytes? (:digest rc))))))

  (is (let [s (SDataSource. (bytesify "yoyo-jojo") "text/plain")
            g (.keyEntity ROOTCS HELPME)
            cs (into [] (.chain g))
            bp (doto (MimeBodyPart.)
                 (.setDataHandler (DataHandler. s)))
            ^BodyPart
            bp2 (smimeEncrypt (first cs)
                              DES_EDE3_CBC bp)
            baos (baos<>)
            _ (doto (mimeMsg<>)
                (.setContent
                  (.getContent bp2)
                  (.getContentType bp2))
                (.saveChanges)
                (.writeTo baos))
            msg2 (mimeMsg<> (streamify (.toByteArray baos)))
            enc (isEncrypted? (.getContentType msg2))
            rc (smimeDecrypt msg2 [(.pkey g)])]
        (and (instBytes? rc)
             (> (.indexOf
                  (stringify rc) "yoyo-jojo") 0))))

  (is (let [g (.keyEntity ROOTCS HELPME)
            s2 (SDataSource.
                 (bytesify "what's up dawg") "text/plain")
            s1 (SDataSource.
                 (bytesify "hello world") "text/plain")
            cs (into [] (.chain g))
            bp2 (doto (MimeBodyPart.)
                  (.setDataHandler (DataHandler. s2)))
            bp1 (doto (MimeBodyPart.)
                  (.setDataHandler (DataHandler. s1)))
            mp (doto (MimeMultipart.)
                 (.addBodyPart bp1)
                 (.addBodyPart bp2))
            msg (doto (mimeMsg<>) (.setContent mp))
            ^BodyPart
            bp3 (smimeEncrypt (first cs) DES_EDE3_CBC msg)
            baos (baos<>)
            _ (doto (mimeMsg<>)
                (.setContent
                  (.getContent bp3)
                  (.getContentType bp3))
                (.saveChanges)
                (.writeTo baos))
            msg3 (mimeMsg<> (streamify (.toByteArray baos)))
            enc (isEncrypted? (.getContentType msg3))
            rc (smimeDecrypt msg3 [(.pkey g)])]
        (and (instBytes? rc)
             (> (.indexOf (stringify rc) "what's up dawg") 0)
             (> (.indexOf (stringify rc) "hello world") 0))))

  (is (let [data (xdata<> "heeloo world")
            g (.keyEntity ROOTCS HELPME)
            cs (into [] (.chain g))
            sig (pkcsDigSig (.pkey g) cs SHA512RSA data)
            dg (testPkcsDigSig (first cs) data sig)]
        (and (some? dg)
             (instBytes? dg))))

  (is (with-open [inp (resStream "czlab/crypto/mime.eml")]
        (let [msg (mimeMsg<> "" (char-array 0) inp)
              bp (smimeDeflate msg)
              ^XData x (smimeInflate bp)]
          (and (some? x)
               (> (alength (.getBytes x)) 0)))))

  (is (let [bp (smimeDeflate "text/plain"
                             (xdata<> "heeloo world"))
            baos (baos<>)
            ^XData x (smimeInflate bp)]
        (and (some? x)
             (> (alength (.getBytes x)) 0))))

  (is (let [bp (smimeDeflate "text/plain"
                              (xdata<> "heeloo world")
                              "blah-blah"
                              "some-id")
            baos (baos<>)
            ^XData x (smimeInflate bp)]
        (and (some? x)
             (> (alength (.getBytes x)) 0))))

  (is (let [f (digest<sha1> (bytesify "heeloo world"))]
        (and (some? f) (> (.length f) 0))))

  (is (let [f (digest<md5> (bytesify "heeloo world"))]
        (and (some? f) (> (.length f) 0))))

  (is (let [f (digest<sha1> (bytesify "heeloo world"))
            g (digest<md5> (bytesify "heeloo world"))]
        (if (= f g) false true)))

  (is (let [f (digest<sha1> (bytesify "heeloo world"))
            g (digest<sha1> (bytesify "heeloo world"))]
        (= f g)))

  (is (let [f (digest<md5> (bytesify "heeloo world"))
            g (digest<md5> (bytesify "heeloo world"))]
        (= f g)))

  (is (string? "That's all folks!")))



;;(clojure.test/run-tests 'czlabtest.crypto.mimestuff)

