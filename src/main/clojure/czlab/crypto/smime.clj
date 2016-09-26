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

(ns ^{:doc "S/MIME helpers."
      :author "Kenneth Leung" }

  czlab.crypto.smime

  (:require
    [czlab.xlib.str :refer [stror lcase ucase strim hgl?]]
    [czlab.xlib.dates :refer [+months]]
    [czlab.xlib.io
     :refer [xdata<>
             toBytes
             streamify
             baos<>
             resetStream!]]
    [czlab.xlib.logging :as log]
    [clojure.string :as cs]
    [czlab.xlib.core
     :refer [throwBadArg
             seqint
             throwIOE
             srandom<>
             bytesify
             try!
             trap!
             cast?
             juid
             getClassname]])

  (:use [czlab.crypto.core])

  (:import
    [javax.mail BodyPart MessagingException Multipart Session]
    [org.bouncycastle.operator.bc BcDigestCalculatorProvider]
    [java.security.cert Certificate X509Certificate]
    [org.bouncycastle.mail.smime SMIMEEnvelopedParser]
    [org.bouncycastle.cert X509CertificateHolder]
    [org.bouncycastle.asn1 ASN1EncodableVector]
    [javax.activation DataHandler]
    [clojure.lang APersistentMap]
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
     ByteArrayOutputStream ]
    [javax.mail.internet
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
    [org.bouncycastle.asn1.x500 X500Name]
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
    [org.bouncycastle.operator.jcajce
     JcaContentSignerBuilder
     JcaDigestCalculatorProviderBuilder]
    [org.bouncycastle.cert.jcajce JcaCertStore ]
    [org.bouncycastle.cms.jcajce
     ZlibCompressor
     JcaSignerInfoGeneratorBuilder]
    [czlab.crypto
     PKeyGist
     SDataSource]
    [czlab.xlib XData]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn strSigningAlgo

  ""
  ^String
  [algo]

  (case algo
    "SHA-512" SMIMESignedGenerator/DIGEST_SHA512
    "SHA-1" SMIMESignedGenerator/DIGEST_SHA1
    "MD5" SMIMESignedGenerator/DIGEST_MD5
    (throwBadArg "Unsupported signing algo: %s" algo)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- signerGentor<>

  "Create a SignedGenerator"
  ^SMIMESignedGenerator
  [^PrivateKey pkey ^String algo certs]
  {:pre [(not (empty? certs))]}

  (let
    [gen (SMIMESignedGenerator. "base64")
     caps (doto (SMIMECapabilityVector.)
            (.addCapability SMIMECapability/dES_EDE3_CBC)
            (.addCapability SMIMECapability/rC2_CBC, 128)
            (.addCapability SMIMECapability/dES_CBC))
     signedAttrs
     (doto (ASN1EncodableVector.)
       (.add (SMIMECapabilitiesAttribute. caps)))
     ^X509Certificate subj (first certs)
     issuer (or (fnext certs) subj)
     issuerDN (-> ^X509Certificate issuer
                  (.getSubjectX500Principal ))
     ;; add an encryption key pref for encrypted resps -
     ;; normally this would be diff from the signing cert
     issAndSer (IssuerAndSerialNumber.
                 (->> (.getEncoded issuerDN)
                      (X500Name/getInstance))
                 (.getSerialNumber subj))
     dm1 (->> issAndSer
              (SMIMEEncryptionKeyPreferenceAttribute. )
              (.add signedAttrs ))
     bdr (doto
           (JcaSignerInfoGeneratorBuilder.
             (-> (withBC JcaDigestCalculatorProviderBuilder)
                 (.build)))
           (.setDirectSignature true))
     cs (-> (withBC1 JcaContentSignerBuilder algo)
            (.build pkey))]
    (->> signedAttrs
         (AttributeTable. )
         (DefaultSignedAttributeTableGenerator. )
         (.setSignedAttributeGenerator bdr ))
    (->> (.build bdr cs subj)
         (.addSignerInfoGenerator gen ))
    (->> (JcaCertStore. certs)
         (.addCertificates gen ))
    gen))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmulti smimeDigSig
  "Sign and returns a Multipart"
  ^Object (fn [a b & xs] (class b)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeDigSig

  MimeMessage
  [^PrivateKey pkey ^MimeMessage mmsg ^String algo certs]

  (let [g (signerGentor<> pkey algo certs)]
    ;; force internal processing, just in case
    (.getContent mmsg)
    (.generate g mmsg)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeDigSig

  Multipart
  [^PrivateKey pkey ^Multipart mp ^String algo certs]

  (smimeDigSig pkey
               (doto (mimeMsg<>)
                 (.setContent mp))
               algo
               certs))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeDigSig

  BodyPart
  [^PrivateKey pkey ^BodyPart bp ^String algo certs]

  (-> (signerGentor<> pkey algo certs)
      (.generate ^MimeBodyPart bp)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn peekSmimeSignedContent

  "Get the content ignoring the signing stuff"
  ^Object
  [^MimeMultipart mp]

  (some-> (SMIMESignedParser.
            (BcDigestCalculatorProvider.)
            mp
            (getCharset (.getContentType mp) "binary"))
          (.getContent)
          (.getContent)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- smimeDec

  "SMIME decryption"
  ^CMSTypedStream
  [^PrivateKey pkey ^SMIMEEnveloped env]

  (loop
    [rec (withBC1 JceKeyTransEnvelopedRecipient pkey)
     it (-> (.getRecipientInfos env)
            (.getRecipients)
            (.iterator))
     rc nil]
    (if (or (some? rc)
            (not (.hasNext it)))
      rc
      (recur rec it
             (-> ^RecipientInformation (.next it)
                 (.getContentStream rec))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- smimeLoopDec

  ""
  ^bytes
  [^SMIMEEnveloped ev pkeys]

  (let
    [rc (some #(if-some
                 [cms (smimeDec ^PrivateKey %1 ev)]
                 (toBytes (.getContentStream cms)) nil)
              pkeys)]
    (when (nil? rc)
      (trap! GeneralSecurityException "No matching decryption key"))
    rc))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmulti smimeDecrypt
  "Decrypt this object" ^bytes (fn [a b] (class a)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeDecrypt

  MimeMessage
  [^MimeMessage mimemsg pkeys]

  (smimeLoopDec (SMIMEEnveloped. mimemsg) pkeys))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeDecrypt

  MimeBodyPart
  [^MimeBodyPart part pkeys]

  (-> (SMIMEEnveloped. part)
      (smimeLoopDec pkeys)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmulti smimeEncrypt
  "Encrypt and returns BodyPart"
  ^MimeBodyPart (fn [a b c] (class c)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeEncrypt

  BodyPart
  [^X509Certificate cert ^String algo ^BodyPart bp]

  (let
    [gen (SMIMEEnvelopedGenerator.)]
    (.addRecipientInfoGenerator
      gen
      (withBC1 JceKeyTransRecipientInfoGenerator cert))
    (.generate
      gen
      ^MimeBodyPart
      bp (-> (withBC1 JceCMSContentEncryptorBuilder algo)
             (.build)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeEncrypt

  MimeMessage
  [^X509Certificate cert ^String algo ^MimeMessage msg]

  (let
    [gen (SMIMEEnvelopedGenerator.)]
    ;; force message to be processed, just in case.
    (.getContent msg)
    (.addRecipientInfoGenerator
      gen
      (withBC1 JceKeyTransRecipientInfoGenerator cert))
    (.generate
      gen
      msg
      (-> (withBC1 JceCMSContentEncryptorBuilder algo)
          (.build)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeEncrypt

  Multipart
  [^X509Certificate cert ^String algo ^Multipart mp]

  (let
    [gen (SMIMEEnvelopedGenerator.)]
    (.addRecipientInfoGenerator
      gen
      (withBC1 JceKeyTransRecipientInfoGenerator cert))
    (.generate
      gen
      (doto (mimeMsg<>) (.setContent mp))
      (-> (withBC1 JceCMSContentEncryptorBuilder algo)
          (.build)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmulti smimeInflate
  "Decompress content" ^XData (fn [a] (class a)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeInflate

  BodyPart
  [^BodyPart bp]

  (if (nil? bp)
    (xdata<>)
    (smimeInflate (.getInputStream bp))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeInflate

  InputStream
  [^InputStream inp]

  (if (nil? inp)
    (xdata<>)
    (if-some
      [cms (-> (CMSCompressedDataParser. inp)
               (.getContent (ZlibExpanderProvider.)))]
      (->> (.getContentStream cms)
           (toBytes )
           (xdata<> ))
      (trap! GeneralSecurityException
             "Decompress stream: corrupted content"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- siTester

  ""
  [^JcaCertStore cs ^SignerInformation si]

  (loop
    [c (.getMatches cs (.getSID si))
     it (some-> c (.iterator))
     digest nil
     stop false]
    (if (or stop
            (nil? it)
            (not (.hasNext it)))
      digest
      (let
        [^X509CertificateHolder
         h (.next it)
         bdr
         (withBC
           JcaSimpleSignerInfoVerifierBuilder)
         dg
         (when
           (.verify si (.build bdr h))
           (.getContentDigest si))]
        (if (nil? dg)
          (recur c it nil false)
          (recur c it dg true))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn testPkcsDigSig

  "Verify the signed object with the signature"
  ^bytes
  [^Certificate cert ^XData dx ^bytes signature]

  (let
    [^CMSProcessable
     p (if (.isFile dx)
         (CMSProcessableFile. (.fileRef dx))
         (CMSProcessableByteArray. (.getBytes dx)))
     sls (some-> (CMSSignedData. p signature)
                 (.getSignerInfos)
                 (.getSigners))
     cs (JcaCertStore. [cert])
     rc (some (partial siTester cs) (seq sls))]
    (when (nil? rc)
      (trap! GeneralSecurityException
             "Decode signature: no matching cert"))
    rc))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn testSmimeDigSig

  "Verify the signature and return content if ok"
  ^APersistentMap
  [^MimeMultipart mp certs & [^String cte]]

  (let
    [sc (if (hgl? cte)
          (SMIMESigned. mp cte)
          (SMIMESigned. mp))
     sns (-> (.getSignerInfos sc)
             (.getSigners))
     cs (JcaCertStore. certs)
     rc (some (partial siTester cs) (seq sns))]
    (when (nil? rc)
      (trap! GeneralSecurityException
             "Verify signature: no matching cert"))
    {:content
     (some-> sc
              (.getContentAsMimeMessage (session<>))
              (.getContent))
     :digest rc}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn pkcsDigSig

  "Sign some data"
  ^bytes
  [^PrivateKey pkey certs ^String algo ^XData xs]
  {:pre [(not (empty? certs))]}

  (let
    [bdr (-> (withBC JcaDigestCalculatorProviderBuilder)
             (.build)
             (JcaSignerInfoGeneratorBuilder.))
     cs (-> (withBC1 JcaContentSignerBuilder algo)
            (.build pkey))
     gen (CMSSignedDataGenerator.)
     cert (first certs)]
    (.setDirectSignature bdr true)
    (->> (.build bdr cs ^X509Certificate cert)
         (.addSignerInfoGenerator gen ))
    (->> (JcaCertStore. certs)
         (.addCertificates gen ))
    (-> (.generate
          gen
          ^CMSProcessable
          (if (.isFile xs)
            (CMSProcessableFile. (.fileRef xs))
            (CMSProcessableByteArray. (.getBytes xs)))
          false)
        (.getEncoded))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn smimeDeflate

  "Compress and return a BodyPart"
  (^MimeBodyPart
    [^String cType ^XData xs]
    (let [ds (if (.isFile xs)
               (SDataSource. (.fileRef xs) cType)
               (SDataSource. (.getBytes xs) cType))
          bp (MimeBodyPart.) ]
      (.setDataHandler bp (DataHandler. ds))
      (.generate (SMIMECompressedGenerator.)
                 bp
                 (ZlibCompressor.))))

  (^MimeBodyPart
    [^MimeMessage msg]
    ;; make sure it's processed, just in case
    (.getContent msg)
    (-> (SMIMECompressedGenerator.)
        (.generate msg (ZlibCompressor.))))

  (^MimeBodyPart
    [^String cType ^String contentLoc
     ^String cid ^XData xs]
    (let [ds (if (.isFile xs)
               (SDataSource. (.fileRef xs) cType)
               (SDataSource. (.getBytes xs) cType))
          bp (MimeBodyPart.) ]
      (when (hgl? contentLoc)
        (.setHeader bp "content-location" contentLoc))
      (when (hgl? cid)
        (.setHeader bp "content-id" cid))
      (.setDataHandler bp (DataHandler. ds))
      (let [zbp (-> (SMIMECompressedGenerator.)
                    (.generate bp (ZlibCompressor.)))
            pos (.lastIndexOf cid (int \>))
            cID (if (>= pos 0)
                  (str (.substring cid 0 pos) "--z>")
                  (str cid "--z")) ]
        (when (hgl? contentLoc)
          (.setHeader zbp "content-location" contentLoc))
        (.setHeader zbp "content-id" cID)
        ;; always base64
        ;;cte="base64"
        (.setHeader zbp "content-transfer-encoding" "base64")
        zbp))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


