;;
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
;;


(ns

  testcljc.crypto.mimestuff

  (:use [czlab.xlib.crypto.codec]
        [czlab.xlib.crypto.stores]
        [czlab.xlib.util.core]
        [czlab.xlib.util.io]
        [czlab.xlib.util.meta]
        [czlab.xlib.crypto.core]
        [clojure.test])

  (:import  [org.apache.commons.io FileUtils IOUtils]
            [java.security Policy KeyStore KeyStore$PrivateKeyEntry
                           KeyStore$TrustedCertificateEntry SecureRandom]
            [java.util Date GregorianCalendar]
            [java.io File InputStream ByteArrayOutputStream]
            [javax.mail Multipart BodyPart]
            [com.zotohlab.frwk.crypto PasswordAPI CryptoStoreAPI]
            [javax.mail.internet MimeBodyPart MimeMessage MimeMultipart]
            [javax.activation DataHandler DataSource]
            [com.zotohlab.frwk.crypto SDataSource]
            [com.zotohlab.frwk.io XData]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(def ^:private ROOTPFX (ResBytes "com/zotohlab/frwk/crypto/test.pfx"))
(def ^PasswordAPI ^:private HELPME (Pwdify "helpme"))
(def ^CryptoStoreAPI ^:private ROOTCS (CryptoStore*
                                        (InitStore! (GetPkcsStore)
                                                    ROOTPFX HELPME) HELPME))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(deftest testcrypto-mimestuff

(is (with-open [ inp (ResStream "com/zotohlab/frwk/mime/mime.eml") ]
        (let [ msg (NewMimeMsg "" "" inp) ^Multipart mp (.getContent msg) ]
               (and (>= (.indexOf (.getContentType msg) "multipart/mixed") 0)
                    (== (.getCount mp) 2)
                    (not (IsSigned? mp))
                    (not (IsCompressed? mp))
                    (not (IsEncrypted? mp)) ))))

(is (with-open [ inp (ResStream "com/zotohlab/frwk/mime/mime.eml") ]
      (let [ ^KeyStore$PrivateKeyEntry pke (.keyEntity ROOTCS
                             ^String (first (.keyAliases ROOTCS))
                             HELPME)
               msg (NewMimeMsg "" "" inp)
               cs (.getCertificateChain pke)
               pk (.getPrivateKey pke)
               rc (SmimeDigSig  pk cs SHA512 msg) ]
        (IsSigned? rc))))

(is (with-open [ inp (ResStream "com/zotohlab/frwk/mime/mime.eml") ]
      (let [ ^KeyStore$PrivateKeyEntry pke (.keyEntity ROOTCS ^String (first (.keyAliases ROOTCS)) HELPME)
               msg (NewMimeMsg "" "" inp)
               mp (.getContent msg)
               cs (.getCertificateChain pke)
               pk (.getPrivateKey pke)
               rc (SmimeDigSig  pk cs SHA512 mp) ]
        (IsSigned? rc))))

(is (with-open [ inp (ResStream "com/zotohlab/frwk/mime/mime.eml") ]
      (let [ ^KeyStore$PrivateKeyEntry pke (.keyEntity ROOTCS ^String (first (.keyAliases ROOTCS)) HELPME)
               msg (NewMimeMsg "" "" inp)
               ^Multipart mp (.getContent msg)
               bp (.getBodyPart mp 1)
               cs (.getCertificateChain pke)
               pk (.getPrivateKey pke)
               rc (SmimeDigSig  pk cs SHA512 bp) ]
        (IsSigned? rc))))

(is (with-open [ inp (ResStream "com/zotohlab/frwk/mime/mime.eml") ]
      (let [ ^KeyStore$PrivateKeyEntry pke (.keyEntity ROOTCS ^String (first (.keyAliases ROOTCS)) HELPME)
               msg (NewMimeMsg "" "" inp)
               cs (.getCertificateChain pke)
               pk (.getPrivateKey pke)
               mp (SmimeDigSig  pk cs SHA512 msg)
               baos (ByteOS)
               msg2 (doto (NewMimeMsg "" "")
                      (.setContent (cast Multipart mp))
                      (.saveChanges)
                      (.writeTo baos))
               msg3 (NewMimeMsg "" "" (Streamify (.toByteArray baos)))
               mp3 (.getContent msg3)
               rc (PeekSmimeSignedContent mp3) ]
        (instance? Multipart rc))))

(is (with-open [ inp (ResStream "com/zotohlab/frwk/mime/mime.eml") ]
      (let [ ^KeyStore$PrivateKeyEntry pke (.keyEntity ROOTCS ^String (first (.keyAliases ROOTCS)) HELPME)
               msg (NewMimeMsg "" "" inp)
               cs (.getCertificateChain pke)
               pk (.getPrivateKey pke)
               mp (SmimeDigSig  pk cs SHA512 msg)
               baos (ByteOS)
               msg2 (doto (NewMimeMsg "" "")
                      (.setContent (cast Multipart mp))
                      (.saveChanges)
                      (.writeTo baos))
               msg3 (NewMimeMsg "" "" (Streamify (.toByteArray baos)))
               mp3 (.getContent msg3)
               rc (TestSmimeDigSig mp3 cs) ]
        (if (and (not (nil? rc)) (== (count rc) 2))
          (and (instance? Multipart (nth rc 0)) (instance? (BytesClass) (nth rc 1)))
          false))))

(is (let [ ^KeyStore$PrivateKeyEntry pke (.keyEntity ROOTCS ^String (first (.keyAliases ROOTCS)) HELPME)
                s (SDataSource. (Bytesify "hello world") "text/plain")
                cs (.getCertificateChain pke)
                pk (.getPrivateKey pke)
                bp (doto (MimeBodyPart.)
                    (.setDataHandler (DataHandler. s)))
                ^BodyPart bp2 (SmimeEncrypt (nth cs 0) DES_EDE3_CBC bp)
                baos (ByteOS)
                msg (doto (NewMimeMsg)
                        (.setContent (.getContent bp2) (.getContentType bp2))
                        (.saveChanges)
                        (.writeTo baos))
                msg2 (NewMimeMsg (Streamify (.toByteArray baos)))
                enc (IsEncrypted? (.getContentType msg2))
                rc (SmimeDecrypt [pk] msg2) ]
      ;; rc is a bodypart
           (and (not (nil? rc))
              (> (.indexOf (Stringify rc) "hello world") 0))))

(is (let [ ^KeyStore$PrivateKeyEntry pke (.keyEntity ROOTCS ^String (first (.keyAliases ROOTCS)) HELPME)
                s2 (SDataSource. (Bytesify "what's up dawg") "text/plain")
                s1 (SDataSource. (Bytesify "hello world") "text/plain")
                cs (.getCertificateChain pke)
                pk (.getPrivateKey pke)
                bp2 (doto (MimeBodyPart.)
                      (.setDataHandler (DataHandler. s2)))
                bp1 (doto (MimeBodyPart.)
                      (.setDataHandler (DataHandler. s1)))
                mp (doto (MimeMultipart.)
                     (.addBodyPart bp1)
                     (.addBodyPart bp2))
                msg (doto (NewMimeMsg) (.setContent  mp))
                ^BodyPart bp3 (SmimeEncrypt (nth cs 0) DES_EDE3_CBC msg)
                baos (ByteOS)
                msg2 (doto (NewMimeMsg)
                        (.setContent (.getContent bp3) (.getContentType bp3))
                        (.saveChanges)
                        (.writeTo baos))
                msg3 (NewMimeMsg (Streamify (.toByteArray baos)))
                enc (IsEncrypted? (.getContentType msg3))
                rc (SmimeDecrypt [pk] msg3) ]
      ;; rc is a multipart
           (and (not (nil? rc))
              (> (.indexOf (Stringify rc) "what's up dawg") 0)
              (> (.indexOf (Stringify rc) "hello world") 0))))

(is (let [ ^KeyStore$PrivateKeyEntry pke (.keyEntity ROOTCS ^String (first (.keyAliases ROOTCS)) HELPME)
             cs (.getCertificateChain pke)
             pk (.getPrivateKey pke)
             data (XData. "heeloo world")
             sig (PkcsDigSig pk cs SHA512 data)
             dg (TestPkcsDigSig (nth cs 0) data sig) ]
        (if (and (not (nil? dg)) (instance? (BytesClass) dg))
          true
          false)))

(is (with-open [ inp (ResStream "com/zotohlab/frwk/mime/mime.eml") ]
        (let [ msg (NewMimeMsg "" "" inp)
               bp (SmimeCompress msg)
               ^XData x (SmimeDecompress bp) ]
          (if (and (not (nil? x))
                    (> (alength ^bytes (.javaBytes x)) 0) )
            true
            false))))

(is (let [ bp (SmimeCompress "text/plain" (XData. "heeloo world"))
           baos (ByteOS)
           ^XData x (SmimeDecompress bp) ]
          (if (and (not (nil? x))
                    (> (alength ^bytes (.javaBytes x)) 0) )
            true
            false)))

(is (let [ bp (SmimeCompress "text/plain" "blah-blah" "some-id" (XData. "heeloo world"))
           baos (ByteOS)
           ^XData x (SmimeDecompress bp) ]
          (if (and (not (nil? x))
                    (> (alength ^bytes (.javaBytes x)) 0) )
            true
            false)))

(is (let [ f (FingerprintSHA1 (Bytesify "heeloo world")) ]
  (if (and (not (nil? f)) (> (.length f) 0))
    true
    false)) )

(is (let [ f (FingerprintMD5 (Bytesify "heeloo world")) ]
  (if (and (not (nil? f)) (> (.length f) 0))
    true
    false)) )

(is (let [f (FingerprintSHA1 (Bytesify "heeloo world"))
          g (FingerprintMD5 (Bytesify "heeloo world")) ]
  (if (= f g) false true)))

)

(def ^:private mimestuff-eof nil)

;;(clojure.test/run-tests 'testcljc.crypto.mimestuff)

