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

(ns czlab.twisty.smime

  "S/MIME helpers."

  (:require [clojure.java.io :as io]
            [clojure.string :as cs]
            [czlab.basal.io :as i]
            [czlab.basal.core :as c]
            [czlab.basal.util :as u]
            [czlab.twisty.core :as t])

  (:import [jakarta.mail BodyPart MessagingException Multipart Session]
           [org.bouncycastle.operator.bc BcDigestCalculatorProvider]
           [java.security.cert Certificate X509Certificate]
           [org.bouncycastle.mail.smime SMIMEEnvelopedParser]
           [org.bouncycastle.cert X509CertificateHolder]
           [org.bouncycastle.asn1
            ASN1EncodableVector
            ASN1ObjectIdentifier]
           [org.bouncycastle.cert.jcajce JcaCertStore]
           [org.bouncycastle.asn1.x500 X500Name]
           [jakarta.activation DataSource DataHandler]
           [clojure.lang APersistentMap]
           [czlab.basal XData]
           [org.bouncycastle.asn1.cms
            AttributeTable
            IssuerAndSerialNumber]
           [java.io
            PrintStream
            File
            InputStream
            IOException
            FileInputStream
            InputStreamReader
            ByteArrayInputStream
            ByteArrayOutputStream]
           [jakarta.mail.internet
            ContentType
            MimeBodyPart
            MimeMessage
            MimeMultipart
            MimeUtility]
           [java.security
            MessageDigest
            PrivateKey
            Provider
            PublicKey
            SecureRandom
            GeneralSecurityException]
           [org.bouncycastle.asn1.smime
            SMIMECapabilitiesAttribute
            SMIMECapability
            SMIMECapabilityVector
            SMIMEEncryptionKeyPreferenceAttribute]
           [org.bouncycastle.cms
            CMSCompressedDataParser
            CMSProcessable
            CMSProcessableByteArray
            CMSProcessableFile
            CMSSignedData
            CMSSignedDataGenerator
            CMSTypedStream
            Recipient
            RecipientInfoGenerator
            RecipientInformation
            SignerInformation
            DefaultSignedAttributeTableGenerator]
           [org.bouncycastle.cms.jcajce
            JcaSignerInfoGeneratorBuilder
            JcaSimpleSignerInfoVerifierBuilder
            JceCMSContentEncryptorBuilder
            JceKeyTransEnvelopedRecipient
            JceKeyTransRecipientInfoGenerator
            ZlibExpanderProvider]
           [org.bouncycastle.mail.smime
            SMIMECompressedGenerator
            SMIMEEnveloped
            SMIMEEnvelopedGenerator
            SMIMEException
            SMIMESigned
            SMIMESignedGenerator
            SMIMESignedParser]
           [org.bouncycastle.cms.jcajce
            ZlibCompressor
            JcaSignerInfoGeneratorBuilder]
           [org.bouncycastle.operator.jcajce
            JcaContentSignerBuilder
            JcaDigestCalculatorProviderBuilder]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn data-source<>

  "Create a Data Source."
  {:tag DataSource
   :arglists '([ctype content])}
  [ctype _content]

  (let [_ctype (c/stror ctype "")]
    (reify DataSource
      (getContentType [_] _ctype)
      (getName [_] "Unknown")
      (getOutputStream [_] (u/throw-UOE ""))
      (getInputStream [_] (.stream (XData. _content false))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn s->signing-algo

  "BC's internal value."
  {:tag String
   :arglists '([algo])}
  [algo]

  (case algo
    "SHA-512" SMIMESignedGenerator/DIGEST_SHA512
    "SHA-256" SMIMESignedGenerator/DIGEST_SHA256
    "SHA-384" SMIMESignedGenerator/DIGEST_SHA384
    "SHA-1" SMIMESignedGenerator/DIGEST_SHA1
    "MD5" SMIMESignedGenerator/DIGEST_MD5
    (u/throw-BadArg "Unsupported signing algo: %s." algo)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- signer-gentor<>

  ^SMIMESignedGenerator
  [^PrivateKey pkey algo certs]
  {:pre [(not-empty certs)]}

  (let
    [caps (doto
            (SMIMECapabilityVector.)
            (.addCapability SMIMECapability/dES_EDE3_CBC)
            (.addCapability SMIMECapability/rC2_CBC 128)
            (.addCapability SMIMECapability/dES_CBC))
     ^X509Certificate subj (c/_1 certs)
     ^X509Certificate
     issuer (or (c/_2 certs) subj)
     algo (c/ucase (c/kw->str algo))
     sas (doto
           (ASN1EncodableVector.)
           (.add (SMIMECapabilitiesAttribute. caps))
           (.add (new SMIMEEncryptionKeyPreferenceAttribute
                      (new IssuerAndSerialNumber
                           (-> issuer
                               .getSubjectX500Principal
                               .getEncoded
                               X500Name/getInstance)
                           (.getSerialNumber subj)))))
     bdr (doto
           (new JcaSignerInfoGeneratorBuilder
                (.build (t/with-BC
                          JcaDigestCalculatorProviderBuilder)))
           (.setDirectSignature true))
     cs (.build (t/with-BC1 JcaContentSignerBuilder algo) pkey)]
    (. bdr setSignedAttributeGenerator
       (->> (AttributeTable. sas)
            DefaultSignedAttributeTableGenerator.))
    (doto
      (SMIMESignedGenerator. "base64")
      (.addSignerInfoGenerator (.build bdr cs subj))
      (.addCertificates (JcaCertStore. certs)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn smime-digsig

  "Sign a mime-msg/multipart."
  {:arglists '([obj pkey algo certs])}
  [obj pkey algo certs]

  (c/condp?? instance? obj
    MimeMessage
    (do
      ;; force internal processing
      (.getContent ^MimeMessage obj)
      (-> (signer-gentor<> pkey algo certs)
          (.generate ^MimeMessage obj)))
    Multipart
    (smime-digsig
      (doto (t/mime-msg<>)
        (.setContent ^Multipart obj)) pkey algo certs)
    MimeBodyPart
    (-> (signer-gentor<> pkey algo certs) (.generate ^MimeBodyPart obj))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- to-cms

  ^CMSProcessable
  [xs]

  (if (c/is? File xs)
    (CMSProcessableFile. ^File xs)
    (CMSProcessableByteArray. (i/x->bytes xs))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn pkcs-digsig

  "Sign data PKCS style."
  {:tag "[B"
   :arglists '([xs pkey algo certs])}
  [xs pkey algo certs]

  (let [bdr (new JcaSignerInfoGeneratorBuilder
                 (.build (t/with-BC JcaDigestCalculatorProviderBuilder)))
        gen (CMSSignedDataGenerator.)
        cert (c/_1 certs)
        algo (c/ucase (c/kw->str algo))
        cs (.build (t/with-BC1 JcaContentSignerBuilder algo) ^PrivateKey pkey)]
    (.setDirectSignature bdr true)
    (doto gen
      (.addSignerInfoGenerator
        (.build bdr cs ^X509Certificate cert))
      (.addCertificates (JcaCertStore. certs)))
    (.getEncoded (.generate gen (to-cms xs) false))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- smime-dec

  "Smime decryption."
  ^CMSTypedStream
  [^PrivateKey pkey ^SMIMEEnveloped env]

  (loop
    [rec (t/with-BC1 JceKeyTransEnvelopedRecipient pkey)
     i (.. env getRecipientInfos getRecipients iterator)
     rc nil]
    (if (or rc (not (.hasNext i)))
      rc
      (recur rec i (-> ^RecipientInformation
                       (.next i)
                       (.getContentStream rec))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- smime-loop-dec

  ^bytes
  [^SMIMEEnveloped ev pkeys]

  (or (some #(if-some
               [cms (smime-dec %1 ev)]
               (i/x->bytes (.getContentStream cms))) pkeys)
      (c/trap! GeneralSecurityException "No matching decryption key.")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn smime-decrypt

  "Decrypt content by trying the keys."
  {:tag "[B"
   :arglists '([obj pkeys])}
  [obj pkeys]

  (c/condp?? instance? obj
    MimeMessage
    (-> (SMIMEEnveloped. ^MimeMessage obj)
        (smime-loop-dec pkeys))
    MimeBodyPart
    (-> (SMIMEEnveloped. ^MimeBodyPart obj)
        (smime-loop-dec pkeys))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- si-tester

  [^JcaCertStore cs ^SignerInformation si]

  (loop [c (.getMatches cs (.getSID si))
         it (some-> c .iterator) digest nil stop? false]
    (if (or stop?
            (nil? it)
            (not (.hasNext it)))
      digest
      (let [^X509CertificateHolder h (.next it)
            bdr (t/with-BC
                  JcaSimpleSignerInfoVerifierBuilder)
            dg (if (.verify si (.build bdr h))
                 (.getContentDigest si))]
        (if (nil? dg)
          (recur c it nil false) (recur c it dg true))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn pkcs-digsig??

  "Verify the signed object with the signature."
  {:arglists '([cert xs dig])}
  [cert xs sig]
  {:pre [(c/is? X509Certificate cert)]}

  (let [cs (JcaCertStore. [cert])
        sls (some-> (to-cms xs)
                    (CMSSignedData. ^bytes sig)
                    .getSignerInfos .getSigners)]
    (or (some (partial si-tester cs) (seq sls))
        (c/trap! GeneralSecurityException
                 "Decode signature: no matching cert."))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn smime-encrypt

  "Encrypt and returns BodyPart."
  {:arglists '([obj algo cert])}
  [obj ^ASN1ObjectIdentifier algo ^X509Certificate cert]

  (c/condp?? instance? obj
    MimeBodyPart
    (-> (doto
          (SMIMEEnvelopedGenerator.)
          (.addRecipientInfoGenerator
            (t/with-BC1 JceKeyTransRecipientInfoGenerator cert)))
        (.generate ^MimeBodyPart obj
                   (.build (t/with-BC1
                             JceCMSContentEncryptorBuilder algo))))
    MimeMessage
    (-> (doto
          (SMIMEEnvelopedGenerator.)
          (.addRecipientInfoGenerator
            (t/with-BC1 JceKeyTransRecipientInfoGenerator cert)))
        (.generate (doto ^MimeMessage obj .getContent)
                   (.build (t/with-BC1
                             JceCMSContentEncryptorBuilder algo))))
    MimeMultipart
    (smime-encrypt (doto
                     (t/mime-msg<>)
                     (.setContent MimeMultipart obj)) algo cert)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn smime-inflate

  "Decompress the content."
  {:tag "[B"
   :arglists '([obj])}
  [obj]

  (c/condp?? instance? obj
    InputStream
    (if-some [cms (-> ^InputStream obj
                      (CMSCompressedDataParser.)
                      (.getContent (ZlibExpanderProvider.)))]
      (i/slurpb (.getContentStream cms))
      (c/trap! GeneralSecurityException
               "Decompress stream: corrupt content."))
    BodyPart
    (c/wo* [inp (.getInputStream ^BodyPart obj)] (smime-inflate inp))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn smime-digsig??

  "Verify the signature and return content if ok."
  {:arglists '([mp certs]
               [mp certs cte])}

  ([mp certs]
   (smime-digsig?? mp certs nil))

  ([mp certs cte]
   {:pre [(c/is? MimeMultipart mp)]}
   (let [sc (if (c/nichts? cte)
              (SMIMESigned. ^MimeMultipart mp)
              (SMIMESigned. ^MimeMultipart mp cte))
         sns (.getSigners (.getSignerInfos sc))
         cs (JcaCertStore. certs)
         rc (some (partial si-tester cs) (seq sns))]
     (if (nil? rc)
       (c/trap! GeneralSecurityException
                "Verify signature: no matching cert.")
     (array-map :digest rc
                :content (some-> (.getContentAsMimeMessage
                                   sc
                                   (t/session<>)) .getContent))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn peek-signed-content

  "Get the content ignoring the signing stuff."
  {:arglists '([mp])}
  [mp]
  {:pre [(c/is? MimeMultipart mp)]}

  (some->
    (SMIMESignedParser.
      (BcDigestCalculatorProvider.)
      ^MimeMultipart mp
      (-> (.getContentType ^MimeMultipart mp)
          (t/charset?? "binary"))) .getContent .getContent))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn smime-deflate*

  "S/MIME compress a MIME message."
  {:arglists '([obj])}
  [obj]
  {:pre [(c/is? MimeMessage obj)]}

  (.getContent ^MimeMessage obj)
  (.generate (SMIMECompressedGenerator.)
             ^MimeMessage obj (ZlibCompressor.)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn smime-deflate

  "S/MIME compress content."
  {:arglists '([cType arg])}

  ([cType arg]
   {:pre [(string? cType)]}
   (let [ds (data-source<> cType arg)]
     (.generate (SMIMECompressedGenerator.)
                (doto (MimeBodyPart.)
                  (.setDataHandler
                    (DataHandler. ds)))
                (ZlibCompressor.))))

  ([cType arg ^String cloc ^String cid]
   {:pre [(string? cType)]}
   (let [ds (data-source<> cType arg)
         bp (doto
              (MimeBodyPart.)
              (.setHeader "content-location" ^String cloc)
              (.setHeader "content-id" ^String cid)
              (.setDataHandler (DataHandler. ds)))
         pos (cs/last-index-of cid \>)
         cid' (if (nil? pos)
                (str cid "--z")
                (str (subs cid 0 pos) "--z>"))]
     (doto
       (.generate (SMIMECompressedGenerator.)
                  bp
                  (ZlibCompressor.))
       (.setHeader "content-location" ^String cloc)
       (.setHeader "content-id" ^String cid')
       (.setHeader "content-transfer-encoding" "base64")))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF

