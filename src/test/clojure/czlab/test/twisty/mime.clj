;; Copyright ©  2013-2019, Kenneth Leung. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file epl-v10.html at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

(ns ^{:doc ""
      :author "Kenneth Leung"}

  czlab.test.twisty.mime

  (:require [czlab.twisty.smime :as sm]
            [czlab.twisty.store :as st]
            [clojure.java.io :as io]
            [czlab.twisty.ssl :as ss]
            [czlab.twisty.core :as t]
            [clojure.test :as ct]
            [czlab.basal.io :as i]
            [czlab.basal.str :as s]
            [czlab.basal.core
             :refer [ensure?? ensure-thrown??] :as c])

  (:import [javax.mail.internet MimeBodyPart MimeMessage MimeMultipart]
           [java.io File InputStream ByteArrayOutputStream]
           [org.bouncycastle.cms CMSAlgorithm]
           [java.security Policy
            KeyStore
            KeyStore$PrivateKeyEntry
            KeyStore$TrustedCertificateEntry SecureRandom]
           [javax.activation DataHandler DataSource]
           [java.util Date GregorianCalendar]
           [javax.mail Multipart BodyPart]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(def ^:private root-pfx (i/res->bytes "czlab/test/twisty/test.pfx"))
(def ^:private help-me (i/x->chars "helpme"))
(def ^:private des-ede3-cbc CMSAlgorithm/DES_EDE3_CBC)
(def ^:private
  root-cs
  (st/crypto-store<> (t/pkcs12<> root-pfx help-me) help-me))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(c/deftest test-mime

  (ensure?? "mime-msg<>"
            (c/wo* [inp (i/res->stream "czlab/test/twisty/mime.eml")]
              (let [msg (t/mime-msg<> nil nil inp)
                    ^Multipart mp (.getContent msg)]
                (and (>= (.indexOf (.getContentType msg)
                                   "multipart/mixed") 0)
                     (= (.getCount mp) 2)
                     (not (t/is-data-signed? mp))
                     (not (t/is-data-compressed? mp))
                     (not (t/is-data-encrypted? mp))))))

  (ensure?? "smime-digsig"
            (c/wo* [inp (i/res->stream "czlab/test/twisty/mime.eml")]
              (let [g (st/cs-key-entity root-cs help-me)
                    msg (t/mime-msg<> nil nil inp)
                    rc (sm/smime-digsig (:pkey g)
                                        msg
                                        t/sha-512-rsa
                                        (c/vec-> (:chain g)))]
                (t/is-data-signed? rc))))

  (ensure?? "smime-digsig"
            (c/wo* [inp (i/res->stream "czlab/test/twisty/mime.eml")]
              (let [g (st/cs-key-entity root-cs help-me)
                    msg (t/mime-msg<> nil nil inp)
                    rc (sm/smime-digsig (:pkey g)
                                        (.getContent msg)
                                        t/sha-512-rsa
                                        (c/vec-> (:chain g)))]
                (t/is-data-signed? rc))))

  (ensure?? "smime-digsig"
            (c/wo* [inp (i/res->stream "czlab/test/twisty/mime.eml")]
              (let [g (st/cs-key-entity root-cs help-me)
                    msg (t/mime-msg<> nil nil inp)
                    bp (-> ^Multipart
                           (.getContent msg)
                           (.getBodyPart 1))
                    rc (sm/smime-digsig (:pkey g)
                                        bp
                                        t/sha-512-rsa
                                        (c/vec-> (:chain g)))]
                (t/is-data-signed? rc))))

  (ensure?? "peek-signed-content"
            (c/wo* [inp (i/res->stream "czlab/test/twisty/mime.eml")]
              (let [g (st/cs-key-entity root-cs help-me)
                    mp (sm/smime-digsig (:pkey g)
                                        (t/mime-msg<> nil nil inp)
                                        t/sha-512-rsa
                                        (c/vec-> (:chain g)))
                    baos (i/baos<>)
                    _ (doto (t/mime-msg<> nil nil)
                        (.setContent (c/cast? Multipart mp))
                        .saveChanges
                        (.writeTo baos))
                    [del? inp] (i/input-stream?? baos)
                    msg3 (t/mime-msg<> nil nil inp)
                    mp3 (.getContent msg3)
                    rc (sm/peek-signed-content mp3)]
                (if del? (i/klose inp))
                (c/is? Multipart rc))))

  (ensure?? "smime-digsig??"
            (c/wo* [inp (i/res->stream "czlab/test/twisty/mime.eml")]
              (let [g (st/cs-key-entity root-cs help-me)
                    cs (c/vec-> (:chain g))
                    mp (sm/smime-digsig (:pkey g)
                                        (t/mime-msg<> nil nil inp)
                                        t/sha-512-rsa
                                        cs)
                    baos (i/baos<>)
                    _ (doto (t/mime-msg<> nil nil)
                        (.setContent (c/cast? Multipart mp))
                        .saveChanges
                        (.writeTo baos))
                    [del? inp] (i/input-stream?? baos)
                    msg3 (t/mime-msg<> nil nil inp)
                    mp3 (.getContent msg3)
                    rc (sm/smime-digsig?? mp3 cs)]
                (if del? (i/klose inp))
                (and (map? rc)
                     (= (count rc) 2)
                     (c/is? Multipart (:content rc))
                     (bytes? (:digest rc))))))

  (ensure?? "smime-decrypt"
            (let [s (sm/data-source<> "text/plain"
                                      (i/x->bytes "yoyo-jojo"))
                  g (st/cs-key-entity root-cs help-me)
                  cs (c/vec-> (:chain g))
                  bp (doto (MimeBodyPart.)
                       (.setDataHandler (DataHandler. s)))
                  ^BodyPart
                  bp2 (sm/smime-encrypt (c/_1 cs) des-ede3-cbc bp)
                  baos (i/baos<>)
                  _ (doto (t/mime-msg<>)
                      (.setContent
                        (.getContent bp2)
                        (.getContentType bp2))
                      .saveChanges
                      (.writeTo baos))
                  [del? inp] (i/input-stream?? baos)
                  msg2 (t/mime-msg<> inp)
                  enc (t/is-encrypted? (.getContentType msg2))
                  rc (sm/smime-decrypt msg2 [(:pkey g)])]
              (if del? (i/klose inp))
              (and (bytes? rc)
                   (pos? (.indexOf (i/x->str rc) "yoyo-jojo")))))

  (ensure?? "smime-decrypt"
            (let [g (st/cs-key-entity root-cs help-me)
                  s2 (sm/data-source<> "text/plain"
                                       (i/x->bytes "what's up dawg"))
                  s1 (sm/data-source<> "text/plain"
                                       (i/x->bytes "hello world"))
                  cs (c/vec-> (:chain g))
                  bp2 (doto (MimeBodyPart.)
                        (.setDataHandler (DataHandler. s2)))
                  bp1 (doto (MimeBodyPart.)
                        (.setDataHandler (DataHandler. s1)))
                  mp (doto (MimeMultipart.)
                       (.addBodyPart bp1)
                       (.addBodyPart bp2))
                  msg (doto (t/mime-msg<>) (.setContent mp))
                  ^BodyPart
                  bp3 (sm/smime-encrypt (c/_1 cs) des-ede3-cbc msg)
                  baos (i/baos<>)
                  _ (doto (t/mime-msg<>)
                      (.setContent
                        (.getContent bp3)
                        (.getContentType bp3))
                      .saveChanges
                      (.writeTo baos))
                  [del? inp] (i/input-stream?? baos)
                  msg3 (t/mime-msg<> inp)
                  enc (t/is-encrypted? (.getContentType msg3))
                  rc (sm/smime-decrypt msg3 [(:pkey g)])]
              (if del? (i/klose inp))
              (and (bytes? rc)
                   (pos? (.indexOf (i/x->str rc) "what's up dawg"))
                   (pos? (.indexOf (i/x->str rc) "hello world")))))

  (ensure?? "pkcs-digsig"
            (let [data (i/x->bytes "heeloo world")
                  g (st/cs-key-entity root-cs help-me)
                  cs (c/vec-> (:chain g))
                  sig (sm/pkcs-digsig (:pkey g) cs t/sha-512-rsa data)
                  dg (sm/pkcs-digsig?? (c/_1 cs) data sig)]
              (bytes? dg)))

  (ensure?? "smime-inflate,smime-deflate"
            (c/wo* [inp (i/res->stream "czlab/test/twisty/mime.eml")]
              (let [msg (t/mime-msg<> "" (char-array 0) inp)
                    bp (sm/smime-deflate msg)
                    ^bytes x (sm/smime-inflate bp)]
                (and x (pos? (alength x))))))

  (ensure?? "smime-inflate"
            (let [bp (sm/smime-deflate "text/plain"
                                       (i/x->bytes "heeloo world"))
                  baos (i/baos<>)
                  ^bytes x (sm/smime-inflate bp)]
              (and x (pos? (alength x)))))

  (ensure?? "smime-inflate"
            (let [bp (sm/smime-deflate "text/plain"
                                       (i/x->bytes "heeloo world")
                                       "blah-blah"
                                       "some-id")
                  baos (i/baos<>)
                  ^bytes
                  x (sm/smime-inflate bp)]
              (and x (pos? (alength x)))))

  (ensure?? "test-end" (= 1 1)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(ct/deftest
  ^:test-mime twisty-test-mime
  (ct/is (c/clj-test?? test-mime)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


