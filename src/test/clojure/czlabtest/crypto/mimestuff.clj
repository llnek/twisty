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

  czlabtest.crypto.mimestuff

  (:use [czlab.crypto.stores]
        [czlab.crypto.codec]
        [czlab.crypto.smime]
        [czlab.crypto.core]
        [czlab.xlib.core]
        [czlab.xlib.io]
        [czlab.xlib.meta]
        [clojure.test])

  (:import
    [javax.mail.internet MimeBodyPart MimeMessage MimeMultipart]
    [java.io File InputStream ByteArrayOutputStream]
    [org.bouncycastle.cms CMSAlgorithm]
    [java.security Policy
     KeyStore
     KeyStore$PrivateKeyEntry
     KeyStore$TrustedCertificateEntry SecureRandom]
    [czlab.crypto PKeyGist PasswordAPI CryptoStoreAPI]
    [javax.activation DataHandler DataSource]
    [java.util Date GregorianCalendar]
    [javax.mail Multipart BodyPart]
    [czlab.xlib XData]
    [czlab.crypto SDataSource]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(def ^:private ROOTPFX (resBytes "czlab/crypto/test.pfx"))
(def ^:private HELPME (.toCharArray "helpme"))
(def ^:private ^CryptoStoreAPI
  ROOTCS
  (cryptoStore<> (initStore! (pkcsStore<>) ROOTPFX HELPME) HELPME))
(defonce ^:private DES_EDE3_CBC CMSAlgorithm/DES_EDE3_CBC)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(deftest czlabtestcrypto-mimestuff

(is (with-open [inp (resStream "czlab/xlib/mime.eml")]
      (let [msg (mimeMsg<> "" (char-array 0) inp)
            ^Multipart mp (.getContent msg)]
        (and (>= (.indexOf (.getContentType msg) "multipart/mixed") 0)
             (== (.getCount mp) 2)
             (not (isSigned? mp))
             (not (isCompressed? mp))
             (not (isEncrypted? mp)) ))))

(is (with-open [inp (resStream "czlab/xlib/mime.eml")]
      (let [^PKeyGist pke
            (.keyEntity ROOTCS
                        ^String (first (.keyAliases ROOTCS)) HELPME)
            msg (mimeMsg<> "" (char-array 0) inp)
            cs (into [] (.chain pke))
            pk (.pkey pke)
            rc (smimeDigSig  pk msg SHA512RSA cs)]
        (isSigned? rc))))

(is (with-open [inp (resStream "czlab/xlib/mime.eml")]
      (let [^PKeyGist pke
            (.keyEntity ROOTCS
                        ^String (first (.keyAliases ROOTCS)) HELPME)
            msg (mimeMsg<> "" (char-array 0) inp)
            mp (.getContent msg)
            cs (into [] (.chain pke))
            pk (.pkey pke)
            rc (smimeDigSig  pk mp SHA512RSA cs)]
        (isSigned? rc))))

(is (with-open [inp (resStream "czlab/xlib/mime.eml")]
      (let [^PKeyGist
            pke (.keyEntity ROOTCS
                            ^String (first (.keyAliases ROOTCS))
                            HELPME)
            msg (mimeMsg<> "" (char-array 0) inp)
            ^Multipart mp (.getContent msg)
            bp (.getBodyPart mp 1)
            cs (into [] (.chain pke))
            pk (.pkey pke)
            rc (smimeDigSig  pk bp SHA512RSA cs)]
        (isSigned? rc))))

(is (with-open [inp (resStream "czlab/xlib/mime.eml")]
      (let [^PKeyGist
            pke (.keyEntity ROOTCS
                            ^String (first (.keyAliases ROOTCS)) HELPME)
            msg (mimeMsg<> "" (char-array 0) inp)
            cs (into [] (.chain pke))
            pk (.pkey pke)
            mp (smimeDigSig  pk msg SHA512RSA cs)
            baos (baos<>)
            msg2 (doto (mimeMsg<> "" (char-array 0))
                   (.setContent (cast Multipart mp))
                   (.saveChanges)
                   (.writeTo baos))
            msg3 (mimeMsg<> "" (char-array 0) (streamify (.toByteArray baos)))
            mp3 (.getContent msg3)
            rc (peekSmimeSignedContent mp3)]
        (instance? Multipart rc))))

(is (with-open [inp (resStream "czlab/xlib/mime.eml")]
      (let [^PKeyGist pke
            (.keyEntity ROOTCS
                        ^String (first (.keyAliases ROOTCS)) HELPME)
            msg (mimeMsg<> "" (char-array 0) inp)
            cs (into [] (.chain pke))
            pk (.pkey pke)
            mp (smimeDigSig  pk msg SHA512RSA cs)
            baos (baos<>)
            msg2 (doto (mimeMsg<> "" (char-array 0))
                   (.setContent (cast? Multipart mp))
                   (.saveChanges)
                   (.writeTo baos))
            msg3 (mimeMsg<> "" "" (streamify (.toByteArray baos)))
            mp3 (.getContent msg3)
            rc (testSmimeDigSig mp3 cs)]
        (if (and (not (nil? rc))
                 (== (count rc) 2))
          (and (instance? Multipart (nth rc 0))
               (instance? (bytesClass) (nth rc 1)))
          false))))

(is (let [^PKeyGist pke
          (.keyEntity ROOTCS
                      ^String (first (.keyAliases ROOTCS)) HELPME)
          s (SDataSource. (bytesify "hello world") "text/plain")
          cs (into [] (.chain pke))
          pk (.pkey pke)
          bp (doto (MimeBodyPart.)
               (.setDataHandler (DataHandler. s)))
          ^BodyPart bp2 (smimeEncrypt (nth cs 0) DES_EDE3_CBC bp)
          baos (baos<>)
          msg (doto (mimeMsg<>)
                (.setContent (.getContent bp2) (.getContentType bp2))
                (.saveChanges)
                (.writeTo baos))
          msg2 (mimeMsg<> (streamify (.toByteArray baos)))
          enc (isEncrypted? (.getContentType msg2))
          rc (smimeDecrypt msg2 [pk] )]
      ;; rc is a bodypart
      (and (not (nil? rc))
           (> (.indexOf (stringify rc) "hello world") 0))))

(is (let [^PKeyGist pke
          (.keyEntity ROOTCS
                      ^String (first (.keyAliases ROOTCS)) HELPME)
          s2 (SDataSource. (bytesify "what's up dawg") "text/plain")
          s1 (SDataSource. (bytesify "hello world") "text/plain")
          cs (into [] (.chain pke))
          pk (.pkey pke)
          bp2 (doto (MimeBodyPart.)
                (.setDataHandler (DataHandler. s2)))
          bp1 (doto (MimeBodyPart.)
                (.setDataHandler (DataHandler. s1)))
          mp (doto (MimeMultipart.)
               (.addBodyPart bp1)
               (.addBodyPart bp2))
          msg (doto (mimeMsg<>) (.setContent mp))
          ^BodyPart bp3 (smimeEncrypt (nth cs 0) DES_EDE3_CBC msg)
          baos (baos<>)
          msg2 (doto (mimeMsg<>)
                 (.setContent (.getContent bp3) (.getContentType bp3))
                 (.saveChanges)
                 (.writeTo baos))
          msg3 (mimeMsg<> (streamify (.toByteArray baos)))
          enc (isEncrypted? (.getContentType msg3))
          rc (smimeDecrypt msg3 [pk] )]
      ;; rc is a multipart
      (and (not (nil? rc))
           (> (.indexOf (stringify rc) "what's up dawg") 0)
           (> (.indexOf (stringify rc) "hello world") 0))))

(is (let [^PKeyGist pke
          (.keyEntity ROOTCS
                      ^String (first (.keyAliases ROOTCS)) HELPME)
          cs (into [] (.chain pke))
          pk (.pkey pke)
          data (xdata<> "heeloo world")
          sig (pkcsDigSig pk cs SHA512RSA data)
          dg (testPkcsDigSig (nth cs 0) data sig)]
      (if (and (not (nil? dg))
               (instance? (bytesClass) dg))
        true
        false)))

(is (with-open [inp (resStream "czlab/xlib/mime.eml")]
      (let [msg (mimeMsg<> "" (char-array 0) inp)
            bp (smimeCompress msg)
            ^XData x (smimeDecompress bp)]
        (if (and (not (nil? x))
                 (> (alength ^bytes (.getBytes x)) 0))
          true
          false))))

(is (let [bp (smimeCompress "text/plain" (xdata<> "heeloo world"))
          baos (baos<>)
          ^XData x (smimeDecompress bp)]
      (if (and (not (nil? x))
               (> (alength ^bytes (.getBytes x)) 0) )
        true
        false)))

(is (let [bp (smimeCompress "text/plain"
                            "blah-blah"
                            "some-id" (xdata<> "heeloo world"))
          baos (baos<>)
          ^XData x (smimeDecompress bp)]
      (if (and (not (nil? x))
               (> (alength ^bytes (.getBytes x)) 0) )
        true
        false)))

(is (let [f (digest<sha1> (bytesify "heeloo world"))]
  (if (and (not (nil? f)) (> (.length f) 0))
    true
    false)) )

(is (let [f (digest<md5> (bytesify "heeloo world"))]
  (if (and (not (nil? f)) (> (.length f) 0))
    true
    false)) )

(is (let [f (digest<sha1> (bytesify "heeloo world"))
          g (digest<md5> (bytesify "heeloo world")) ]
  (if (= f g) false true)))

(is (let [f (digest<sha1> (bytesify "heeloo world"))
          g (digest<sha1> (bytesify "heeloo world")) ]
  (= f g)))

(is (let [f (digest<md5> (bytesify "heeloo world"))
          g (digest<md5> (bytesify "heeloo world")) ]
  (= f g)))


)

;;(clojure.test/run-tests 'czlabtest.crypto.mimestuff)

