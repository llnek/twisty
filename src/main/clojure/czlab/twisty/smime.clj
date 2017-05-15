;; Copyright (c) 2013-2017, Kenneth Leung. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file epl-v10.html at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

(ns ^{:doc "S/MIME helpers."
      :author "Kenneth Leung"}

  czlab.twisty.smime

  (:require [czlab.basal.log :as log]
            [clojure.string :as cs]
            [czlab.twisty.core :as t]
            [czlab.basal.core :as c]
            [czlab.basal.io :as i]
            [czlab.basal.str :as s])

  (:import [javax.mail BodyPart MessagingException Multipart Session]
           [org.bouncycastle.operator.bc BcDigestCalculatorProvider]
           [java.security.cert Certificate X509Certificate]
           [org.bouncycastle.mail.smime SMIMEEnvelopedParser]
           [org.bouncycastle.cert X509CertificateHolder]
           [org.bouncycastle.asn1
            ASN1EncodableVector
            ASN1ObjectIdentifier]
           [org.bouncycastle.cert.jcajce JcaCertStore]
           [org.bouncycastle.asn1.x500 X500Name]
           [czlab.jasal XData SDataSource]
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
            ByteArrayOutputStream]
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
;;
(defn strSigningAlgo "BC's internal value" ^String [algo]
  (case algo
    "SHA-512" SMIMESignedGenerator/DIGEST_SHA512
    "SHA-256" SMIMESignedGenerator/DIGEST_SHA256
    "SHA-384" SMIMESignedGenerator/DIGEST_SHA384
    "SHA-1" SMIMESignedGenerator/DIGEST_SHA1
    "MD5" SMIMESignedGenerator/DIGEST_MD5
    (c/throwBadArg "Unsupported signing algo: %s" algo)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- signerGentor<>
  "Create a SignedGenerator"
  ^SMIMESignedGenerator
  [^PrivateKey pkey algo certs]
  {:pre [(not-empty certs)]}

  (let
    [caps (doto (SMIMECapabilityVector.)
            (.addCapability SMIMECapability/dES_EDE3_CBC)
            (.addCapability SMIMECapability/rC2_CBC, 128)
            (.addCapability SMIMECapability/dES_CBC))
     ^X509Certificate subj (first certs)
     ^X509Certificate issuer (or (second certs) subj)
     signedAttrs (ASN1EncodableVector.)
     algo (s/ucase (s/strKW algo))
     _ (->> (SMIMECapabilitiesAttribute. caps)
            (.add signedAttrs))
     _ (->> (IssuerAndSerialNumber.
              (-> issuer
                  .getSubjectX500Principal
                  .getEncoded
                  X500Name/getInstance)
              (.getSerialNumber subj))
            SMIMEEncryptionKeyPreferenceAttribute.
            (.add signedAttrs ))
     bdr (doto
           (-> JcaDigestCalculatorProviderBuilder
               t/withBC
               .build
               JcaSignerInfoGeneratorBuilder.)
           (.setDirectSignature true))
     cs (-> JcaContentSignerBuilder (t/withBC1 algo) (.build pkey))]

    (. bdr setSignedAttributeGenerator
       (->> signedAttrs
            AttributeTable.
            DefaultSignedAttributeTableGenerator.))

    (doto (SMIMESignedGenerator. "base64")
      (.addSignerInfoGenerator (.build bdr cs subj))
      (.addCertificates (JcaCertStore. certs)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmulti smimeDigSig
  "Sign and returns a Multipart" (fn [a b & xs] (class b)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeDigSig
  MimeMessage
  [pkey ^MimeMessage mmsg algo certs]
  (let [g (signerGentor<> pkey algo certs)]
    (.getContent mmsg) ;; force internal processing, just in case
    (.generate g mmsg)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeDigSig
  Multipart
  [pkey mp algo certs]
  (smimeDigSig pkey
               (doto (t/mimeMsg<>)
                 (.setContent mp)) algo certs))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeDigSig
  BodyPart
  [pkey bp algo certs]
  (-> (signerGentor<> pkey algo certs)
      (.generate (c/cast? MimeBodyPart bp))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn peekSmimeSignedContent
  "Get the content ignoring the signing stuff"
  [^Multipart arg]
  (let [mp (c/cast? MimeMultipart arg)]
    (some-> (SMIMESignedParser.
              (BcDigestCalculatorProvider.)
              mp
              (t/getCharset (.getContentType mp) "binary"))
            .getContent
            .getContent)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- smimeDec
  "Smime decryption"
  ^CMSTypedStream
  [^PrivateKey pkey ^SMIMEEnveloped env]
  (loop
    [rec (t/withBC1 JceKeyTransEnvelopedRecipient pkey)
     it (.. env getRecipientInfos getRecipients iterator)
     rc nil]
    (if (or rc (not (.hasNext it)))
      rc
      (recur rec it
             (-> ^RecipientInformation (.next it)
                 (.getContentStream rec))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- smimeLoopDec
  "" ^bytes [^SMIMEEnveloped ev pkeys]

  (let
    [rc (some #(if-some
                 [cms (smimeDec %1 ev)]
                 (i/toBytes (.getContentStream cms)) ) pkeys)]
    (if (nil? rc)
      (c/trap! GeneralSecurityException
               "No matching decryption key"))
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
  (-> (SMIMEEnveloped. part) (smimeLoopDec pkeys)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmulti smimeEncrypt
  "Encrypt and returns BodyPart"
  ^MimeBodyPart (fn [a b c] (class c)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeEncrypt
  BodyPart
  [^X509Certificate cert ^ASN1ObjectIdentifier algo ^BodyPart bp]

  (->
    (doto (SMIMEEnvelopedGenerator.)
      (.addRecipientInfoGenerator
        (t/withBC1 JceKeyTransRecipientInfoGenerator cert)))
    (.generate
      (c/cast? MimeBodyPart bp)
      (.build (t/withBC1 JceCMSContentEncryptorBuilder algo)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeEncrypt
  MimeMessage
  [cert ^ASN1ObjectIdentifier algo ^MimeMessage msg]

  (->
    (doto (SMIMEEnvelopedGenerator.)
      (.addRecipientInfoGenerator
        (t/withBC1 JceKeyTransRecipientInfoGenerator cert)))
    (.generate
      (doto msg .getContent)
      (.build (t/withBC1 JceCMSContentEncryptorBuilder algo)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeEncrypt
  Multipart
  [cert ^ASN1ObjectIdentifier algo ^Multipart mp]
  (smimeEncrypt cert algo (doto (t/mimeMsg<>) (.setContent mp))))

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
    (i/xdata<>)
    (with-open [inp (.getInputStream bp)] (smimeInflate inp))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeInflate
  InputStream
  [^InputStream inp]
  (if (nil? inp)
    (i/xdata<>)
    (if-some
      [cms (-> (CMSCompressedDataParser. inp)
               (.getContent (ZlibExpanderProvider.)))]
      (i/rxBytes (.getContentStream cms))
      (c/trap! GeneralSecurityException
             "Decompress stream: corrupted content"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- siTester
  "" [^JcaCertStore cs ^SignerInformation si]
  (loop
    [c (.getMatches cs (.getSID si))
     it (some-> c .iterator)
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
         (t/withBC
           JcaSimpleSignerInfoVerifierBuilder)
         dg
         (if
           (.verify si (.build bdr h))
           (.getContentDigest si))]
        (if (nil? dg)
          (recur c it nil false)
          (recur c it dg true))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- toCMS
  "" ^CMSProcessable [^XData xs]
  (if (.isFile xs)
    (CMSProcessableFile. (.fileRef xs))
    (CMSProcessableByteArray. (.getBytes xs))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn testPkcsDigSig
  "Verify the signed object with the signature"
  ^bytes [^Certificate cert ^XData xs ^bytes sig]

  (let
    [sls (some-> (toCMS xs)
                 (CMSSignedData. sig)
                 .getSignerInfos
                 .getSigners)
     cs (JcaCertStore. [cert])
     rc (some (partial siTester cs) (seq sls))]
    (if (nil? rc)
      (c/trap! GeneralSecurityException
             "Decode signature: no matching cert"))
    rc))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn testSmimeDigSig
  "Verify the signature and return content if ok"
  {:tag APersistentMap}

  ([mp certs] (testSmimeDigSig mp certs nil))

  ([^MimeMultipart mp certs ^String cte]
   {:pre [(some? mp)]}
   (let
     [sc (if (s/hgl? cte)
           (SMIMESigned. mp cte)
           (SMIMESigned. mp))
      sns (-> (.getSignerInfos sc)
              .getSigners)
      cs (JcaCertStore. certs)
      rc (some (partial siTester cs) (seq sns))]
     (if (nil? rc)
       (c/trap! GeneralSecurityException
              "Verify signature: no matching cert"))
     {:content
      (some-> sc
              (.getContentAsMimeMessage (t/session<>))
              .getContent)
      :digest rc})))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn pkcsDigSig
  "Sign some data"
  ^bytes
  [^PrivateKey pkey certs algo ^XData xs]
  {:pre [(not-empty certs)]}

  (let
    [bdr (-> (t/withBC JcaDigestCalculatorProviderBuilder)
             .build
             JcaSignerInfoGeneratorBuilder.)
     algo (s/ucase (s/strKW algo))
     cs (-> (t/withBC1 JcaContentSignerBuilder algo)
            (.build pkey))
     gen (CMSSignedDataGenerator.)
     cert (first certs)]
    (.setDirectSignature bdr true)
    (doto gen
      (.addSignerInfoGenerator
        (.build bdr cs ^X509Certificate cert))
      (.addCertificates (JcaCertStore. certs)))
    (-> (.generate gen (toCMS xs) false) .getEncoded)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmulti smimeDeflate
  "Compress content" {:tag MimeBodyPart} (fn [a & xs] (class a)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeDeflate
  MimeMessage
  [^MimeMessage msg]
   ;; make sure it's processed, just in case
   (.getContent msg)
   (-> (SMIMECompressedGenerator.)
       (.generate msg (ZlibCompressor.))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeDeflate String

  ([^String cType ^XData xs]
   (let [ds (SDataSource. xs cType)]
     (-> (SMIMECompressedGenerator.)
         (.generate (doto
                      (MimeBodyPart.)
                      (.setDataHandler (DataHandler. ds)))
                    (ZlibCompressor.)))))

  ([^String cType ^XData xs ^String cloc ^String cid]
   {:pre [(s/hgl? cloc)(s/hgl? cid)]}
   (let [ds (SDataSource. xs cType)
         bp (doto (MimeBodyPart.)
              (.setHeader "content-location" cloc)
              (.setHeader "content-id" cid)
              (.setDataHandler (DataHandler. ds)))
         pos (.lastIndexOf cid (int \>))
         cid' (if (>= pos 0)
                (str (.substring cid 0 pos) "--z>")
                (str cid "--z"))]
     (doto
       (-> (SMIMECompressedGenerator.)
           (.generate bp (ZlibCompressor.)))
       (.setHeader "content-location" cloc)
       (.setHeader "content-id" cid')
       (.setHeader "content-transfer-encoding" "base64")))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


