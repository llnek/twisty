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
;; Copyright © 2013-2024, Kenneth Leung. All rights reserved.

(ns czlab.test.twisty.mime

  (:require [clojure.java.io :as io]
            [clojure.test :as ct]
            [czlab.twisty.smime :as sm]
            [czlab.twisty.ssl :as ss]
            [czlab.twisty.core :as t]
            [czlab.twisty.store :as st]
            [czlab.basal.io :as i]
            [czlab.basal.core
              :refer [ensure?? ensure-thrown??] :as c])

  (:import [jakarta.mail.internet MimeBodyPart MimeMessage MimeMultipart]
           [java.io File InputStream ByteArrayOutputStream]
           [org.bouncycastle.cms CMSAlgorithm]
           [java.security Policy
            KeyStore
            KeyStore$PrivateKeyEntry
            KeyStore$TrustedCertificateEntry SecureRandom]
           [jakarta.activation DataHandler DataSource]
           [java.util Date GregorianCalendar]
           [jakarta.mail Multipart BodyPart]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(c/def- root-pfx (i/res->bytes "czlab/test/twisty/test.pfx"))
(c/def- help-me (i/x->chars "helpme"))
(c/def- des-ede3-cbc CMSAlgorithm/DES_EDE3_CBC)
(c/def-
  root-cs
  (st/crypto-store<> (t/pkcs12* root-pfx help-me) help-me))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(c/deftest test-mime

  (ensure?? "mime-msg<>"
            (c/wo* [inp (i/res->stream "czlab/test/twisty/mime.eml")]
              (let [msg (t/mime-msg<> nil nil inp)
                    ^Multipart mp (.getContent msg)]
                (and (>= (.indexOf (.getContentType msg)
                                   "multipart/mixed") 0)
                     (== 2 (.getCount mp))
                     (not (t/is-data-signed? mp))
                     (not (t/is-data-compressed? mp))
                     (not (t/is-data-encrypted? mp))))))

  (ensure?? "smime-digsig"
            (c/wo* [inp (i/res->stream "czlab/test/twisty/mime.eml")]
              (let [g (st/key-entity root-cs help-me)
                    msg (t/mime-msg<> nil nil inp)
                    rc (sm/smime-digsig msg
                                        (:pkey g)
                                        t/sha-512-rsa
                                        (c/vec-> (:chain g)))]
                (t/is-data-signed? rc))))

  (ensure?? "smime-digsig"
            (c/wo* [inp (i/res->stream "czlab/test/twisty/mime.eml")]
              (let [g (st/key-entity root-cs help-me)
                    msg (t/mime-msg<> nil nil inp)
                    rc (sm/smime-digsig (.getContent msg)
                                        (:pkey g)
                                        t/sha-512-rsa
                                        (c/vec-> (:chain g)))]
                (t/is-data-signed? rc))))

  (ensure?? "smime-digsig"
            (c/wo* [inp (i/res->stream "czlab/test/twisty/mime.eml")]
              (let [g (st/key-entity root-cs help-me)
                    msg (t/mime-msg<> nil nil inp)
                    bp (-> ^Multipart
                           (.getContent msg)
                           (.getBodyPart 1))
                    rc (sm/smime-digsig bp
                                        (:pkey g)
                                        t/sha-512-rsa
                                        (c/vec-> (:chain g)))]
                (t/is-data-signed? rc))))

  (ensure?? "peek-signed-content"
            (c/wo* [inp (i/res->stream "czlab/test/twisty/mime.eml")]
              (let [g (st/key-entity root-cs help-me)
                    mp (sm/smime-digsig (t/mime-msg<> nil nil inp)
                                        (:pkey g)
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
              (let [g (st/key-entity root-cs help-me)
                    cs (c/vec-> (:chain g))
                    mp (sm/smime-digsig (t/mime-msg<> nil nil inp)
                                        (:pkey g)
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
                     (== 2 (count rc))
                     (c/is? Multipart (:content rc))
                     (bytes? (:digest rc))))))

  (ensure?? "smime-decrypt"
            (let [s (sm/data-source<> "text/plain"
                                      (i/x->bytes "yoyo-jojo"))
                  g (st/key-entity root-cs help-me)
                  cs (c/vec-> (:chain g))
                  bp (doto (MimeBodyPart.)
                       (.setDataHandler (DataHandler. s)))
                  ^BodyPart
                  bp2 (sm/smime-encrypt bp des-ede3-cbc (c/_1 cs))
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
            (let [g (st/key-entity root-cs help-me)
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
                  bp3 (sm/smime-encrypt msg des-ede3-cbc (c/_1 cs))
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
                  g (st/key-entity root-cs help-me)
                  cs (c/vec-> (:chain g))
                  sig (sm/pkcs-digsig data (:pkey g) t/sha-512-rsa cs)
                  dg (sm/pkcs-digsig?? (c/_1 cs) data sig)]
              (bytes? dg)))

  (ensure?? "smime-inflate,smime-deflate"
            (c/wo* [inp (i/res->stream "czlab/test/twisty/mime.eml")]
              (let [msg (t/mime-msg<> "" (char-array 0) inp)
                    bp (sm/smime-deflate* msg)
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

  (ensure?? "test-end" (== 1 1)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(ct/deftest
  ^:test-mime twisty-test-mime
  (ct/is (c/clj-test?? test-mime)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


