;; Copyright © 2013-2019, Kenneth Leung. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file epl-v10.html at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

(ns ^{:doc "S/MIME helpers."
      :author "Kenneth Leung"}

  czlab.twisty.smime

  (:require [czlab.twisty.core :as t]
            [czlab.basal.log :as l]
            [clojure.java.io :as io]
            [clojure.string :as cs]
            [czlab.basal.core :as c]
            [czlab.basal.util :as u]
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
           [javax.activation DataSource DataHandler]
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
(defn data-source<>
  ^DataSource [ctype _content]
  (let [_ctype (s/stror ctype "")]
    (reify DataSource
      (getContentType [_] _ctype)
      (getName [_] "Unknown")
      (getOutputStream [_]
        (u/throw-IOE "Not implemented."))
      (getInputStream [_] (.stream (i/XData. _content false))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn s->signing-algo
  "BC's internal value." ^String [algo]
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
     algo (s/ucase (s/kw->str algo))
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
  "Sign and returns a Multipart."
  [pkey obj algo certs]
  (c/condp?? instance? obj
    MimeMessage (let [g (signer-gentor<> pkey algo certs)]
                  ;; force internal processing
                  (.getContent ^MimeMessage obj)
                  (.generate g ^MimeMessage obj))
    Multipart (smime-digsig pkey
                            (doto
                              (t/mime-msg<>)
                              (.setContent ^Multipart obj)) algo certs)
    BodyPart (-> (signer-gentor<> pkey algo certs)
                 (.generate (c/cast? MimeBodyPart obj)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn peek-signed-content
  "Get the content ignoring the signing stuff."
  [arg]
  (if-some [mp (c/cast? MimeMultipart arg)]
    (some-> (SMIMESignedParser.
              (BcDigestCalculatorProvider.)
              mp
              (t/charset?? (.getContentType mp) "binary")) .getContent .getContent)))

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
  ^bytes [^SMIMEEnveloped ev pkeys]
  (or (some #(if-some
               [cms (smime-dec %1 ev)]
               (i/x->bytes (.getContentStream cms))) pkeys)
      (c/trap! GeneralSecurityException "No matching decryption key.")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn smime-decrypt
  "Decrypt this object."
  ^bytes [obj pkeys]
  (c/condp?? instance? obj
    MimeMessage (smime-loop-dec (SMIMEEnveloped. ^MimeMessage obj) pkeys)
    MimeBodyPart (smime-loop-dec (SMIMEEnveloped. ^MimeBodyPart obj) pkeys)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn smime-encrypt
  "Encrypt and returns BodyPart."
  ^MimeBodyPart [^X509Certificate cert ^ASN1ObjectIdentifier algo obj]
  (c/condp?? instance? obj
    BodyPart (-> (doto
                   (SMIMEEnvelopedGenerator.)
                   (.addRecipientInfoGenerator
                     (t/with-BC1 JceKeyTransRecipientInfoGenerator cert)))
                 (.generate ^MimeBodyPart obj
                            (.build (t/with-BC1 JceCMSContentEncryptorBuilder algo))))
    MimeMessage (-> (doto
                      (SMIMEEnvelopedGenerator.)
                      (.addRecipientInfoGenerator
                        (t/with-BC1 JceKeyTransRecipientInfoGenerator cert)))
                    (.generate (doto ^MimeMessage obj .getContent)
                               (.build (t/with-BC1 JceCMSContentEncryptorBuilder algo))))
    Multipart (smime-encrypt cert
                             algo
                             (doto (t/mime-msg<>) (.setContent ^Multipart obj)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn smime-inflate
  "Decompress content." [obj]
  (c/condp?? instance? obj
    BodyPart (c/wo*
               [inp (.getInputStream ^BodyPart obj)] (smime-inflate inp))
    InputStream (if-some
                  [cms (-> (CMSCompressedDataParser. ^InputStream obj)
                           (.getContent (ZlibExpanderProvider.)))]
                  (i/slurpb (.getContentStream cms))
                  (c/trap! GeneralSecurityException
                           "Decompress stream: corrupt content."))))

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
          (recur c it nil false)
          (recur c it dg true))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- to-cms
  ^CMSProcessable [xs]
  (if (c/is? File xs)
    (CMSProcessableFile. ^File xs)
    (CMSProcessableByteArray. (i/x->bytes xs))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn pkcs-digsig??
  "Verify the signed object with the signature."
  ^bytes [cert xs sig]
  (let [sls (some-> (to-cms xs)
                    (CMSSignedData. ^bytes sig)
                    .getSignerInfos .getSigners)
        cs (JcaCertStore. [^Certificate cert])]
    (or (some (partial si-tester cs) (seq sls))
        (c/trap! GeneralSecurityException
                 "Decode signature: no matching cert."))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn smime-digsig??
  "Verify the signature and return content if ok."
  ([mp certs] (smime-digsig?? mp certs nil))
  ([^MimeMultipart mp certs ^String cte]
   {:pre [(some? mp)]}
   (let [sc (if (s/hgl? cte)
              (SMIMESigned. mp cte) (SMIMESigned. mp))
         sns (.getSigners (.getSignerInfos sc))
         cs (JcaCertStore. certs)
         rc (some (partial si-tester cs) (seq sns))]
     (if (nil? rc)
       (c/trap! GeneralSecurityException
                "Verify signature: no matching cert.")
       {:digest rc
        :content (some-> (.getContentAsMimeMessage
                           sc
                           (t/session<>)) .getContent)}))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn pkcs-digsig
  "Sign some data."
  ^bytes
  [^PrivateKey pkey certs algo xs]
  {:pre [(not-empty certs)]}
  (let [bdr (new JcaSignerInfoGeneratorBuilder
                 (.build (t/with-BC JcaDigestCalculatorProviderBuilder)))
        gen (CMSSignedDataGenerator.)
        cert (c/_1 certs)
        algo (s/ucase (s/kw->str algo))
        cs (.build (t/with-BC1 JcaContentSignerBuilder algo) pkey)]
    (.setDirectSignature bdr true)
    (doto gen
      (.addSignerInfoGenerator
        (.build bdr cs ^X509Certificate cert))
      (.addCertificates (JcaCertStore. certs)))
    (.getEncoded (.generate gen (to-cms xs) false))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn smime-deflate
  "Compress content."
  {:tag MimeBodyPart}
  ([obj]
   (c/condp?? instance? obj
     MimeMessage (do (.getContent ^MimeMessage obj)
                     (.generate (SMIMECompressedGenerator.)
                                ^MimeMessage obj (ZlibCompressor.)))))
  ([cType arg]
   (let [ds (data-source<> cType arg)]
     (.generate (SMIMECompressedGenerator.)
                (doto
                  (MimeBodyPart.)
                  (.setDataHandler (DataHandler. ds)))
                (ZlibCompressor.))))
  ([cType arg ^String cloc ^String cid]
   {:pre [(s/hgl? cloc) (s/hgl? cid)]}
   (let [ds (data-source<> cType arg)
         bp (doto
              (MimeBodyPart.)
              (.setHeader "content-location" cloc)
              (.setHeader "content-id" cid)
              (.setDataHandler (DataHandler. ds)))
         pos (cs/last-index-of cid \>)
         cid' (if pos
                (str (subs cid 0 pos) "--z>")
                (str cid "--z"))]
     (doto
       (.generate (SMIMECompressedGenerator.)
                  bp
                  (ZlibCompressor.))
       (.setHeader "content-location" cloc)
       (.setHeader "content-id" cid')
       (.setHeader "content-transfer-encoding" "base64")))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


