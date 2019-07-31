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
  ^DataSource [ctype content]
  (let [_content content
        _ctype (s/stror ctype "")]
    (reify DataSource
      (getContentType [_] _ctype)
      (getName [_] "Unknown")
      (getOutputStream [_]
        (u/throw-IOE "Not implemented"))
      (getInputStream [_]
        (io/input-stream content)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn str-signing-algo
  "BC's internal value" ^String [algo]
  (case algo
    "SHA-512" SMIMESignedGenerator/DIGEST_SHA512
    "SHA-256" SMIMESignedGenerator/DIGEST_SHA256
    "SHA-384" SMIMESignedGenerator/DIGEST_SHA384
    "SHA-1" SMIMESignedGenerator/DIGEST_SHA1
    "MD5" SMIMESignedGenerator/DIGEST_MD5
    (u/throw-BadArg "Unsupported signing algo: %s" algo)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- signer-gentor<>
  ^SMIMESignedGenerator
  [^PrivateKey pkey algo certs]
  {:pre [(not-empty certs)]}
  (let
    [caps (doto (SMIMECapabilityVector.)
            (.addCapability SMIMECapability/dES_EDE3_CBC)
            (.addCapability SMIMECapability/rC2_CBC 128)
            (.addCapability SMIMECapability/dES_CBC))
     ^X509Certificate subj (c/_1 certs)
     ^X509Certificate issuer (or (c/_2 certs) subj)
     signedAttrs (ASN1EncodableVector.)
     algo (s/ucase (s/kw->str algo))
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
               t/with-BC
               .build
               JcaSignerInfoGeneratorBuilder.)
           (.setDirectSignature true))
     cs (-> JcaContentSignerBuilder (t/with-BC1 algo) (.build pkey))]
    (. bdr setSignedAttributeGenerator
       (->> signedAttrs
            AttributeTable.
            DefaultSignedAttributeTableGenerator.))
    (doto (SMIMESignedGenerator. "base64")
      (.addSignerInfoGenerator (.build bdr cs subj))
      (.addCertificates (JcaCertStore. certs)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmulti smime-digsig
  "Sign and returns a Multipart" (fn [a b & xs] (class b)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmethod smime-digsig
  MimeMessage
  [pkey ^MimeMessage mmsg algo certs]
  (let [g (signer-gentor<> pkey algo certs)]
    (.getContent mmsg) ;; force internal processing, just in case
    (.generate g mmsg)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmethod smime-digsig
  Multipart
  [pkey mp algo certs]
  (smime-digsig pkey
               (doto (t/mime-msg<>)
                 (.setContent mp)) algo certs))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmethod smime-digsig
  BodyPart
  [pkey bp algo certs]
  (-> (signer-gentor<> pkey algo certs)
      (.generate (c/cast? MimeBodyPart bp))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn peek-smime-signed-content
  "Get the content ignoring the signing stuff"
  [arg]
  (if-some [mp (c/cast? MimeMultipart arg)]
    (some-> (SMIMESignedParser.
              (BcDigestCalculatorProvider.)
              mp
              (t/charset?? (.getContentType mp) "binary"))
            .getContent
            .getContent)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- smime-dec
  "Smime decryption"
  ^CMSTypedStream
  [^PrivateKey pkey ^SMIMEEnveloped env]
  (loop
    [rec (t/with-BC1 JceKeyTransEnvelopedRecipient pkey)
     it (.. env getRecipientInfos getRecipients iterator)
     rc nil]
    (if (or rc (not (.hasNext it)))
      rc
      (recur rec it
             (-> ^RecipientInformation (.next it)
                 (.getContentStream rec))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- smime-loop-dec
  ^bytes [^SMIMEEnveloped ev pkeys]
  (let
    [rc (some #(if-some
                 [cms (smime-dec %1 ev)]
                 (i/x->bytes (.getContentStream cms)) ) pkeys)]
    (if (nil? rc)
      (c/trap! GeneralSecurityException
               "No matching decryption key"))
    rc))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmulti smime-decrypt
  "Decrypt this object" ^bytes (fn [a b] (class a)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmethod smime-decrypt
  MimeMessage
  [^MimeMessage mimemsg pkeys]
  (smime-loop-dec (SMIMEEnveloped. mimemsg) pkeys))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmethod smime-decrypt
  MimeBodyPart
  [^MimeBodyPart part pkeys]
  (-> (SMIMEEnveloped. part) (smime-loop-dec pkeys)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmulti smime-encrypt
  "Encrypt and returns BodyPart"
  ^MimeBodyPart (fn [a b c] (class c)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmethod smime-encrypt
  BodyPart
  [^X509Certificate cert ^ASN1ObjectIdentifier algo ^BodyPart bp]
  (->
    (doto (SMIMEEnvelopedGenerator.)
      (.addRecipientInfoGenerator
        (t/with-BC1 JceKeyTransRecipientInfoGenerator cert)))
    (.generate
      (c/cast? MimeBodyPart bp)
      (.build (t/with-BC1 JceCMSContentEncryptorBuilder algo)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmethod smime-encrypt
  MimeMessage
  [cert ^ASN1ObjectIdentifier algo ^MimeMessage msg]
  (->
    (doto (SMIMEEnvelopedGenerator.)
      (.addRecipientInfoGenerator
        (t/with-BC1 JceKeyTransRecipientInfoGenerator cert)))
    (.generate
      (doto msg .getContent)
      (.build (t/with-BC1 JceCMSContentEncryptorBuilder algo)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmethod smime-encrypt
  Multipart
  [cert ^ASN1ObjectIdentifier algo ^Multipart mp]
  (smime-encrypt cert algo (doto (t/mime-msg<>) (.setContent mp))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmulti smime-inflate
  "Decompress content" (fn [a] (class a)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmethod smime-inflate
  BodyPart
  [^BodyPart bp]
  (if (nil? bp)
    nil
    (with-open [inp (.getInputStream bp)] (smime-inflate inp))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmethod smime-inflate
  InputStream
  [inp]
  (if (nil? inp)
    nil
    (if-some
      [cms (-> (CMSCompressedDataParser. ^InputStream inp)
               (.getContent (ZlibExpanderProvider.)))]
      (i/slurp-bytes (.getContentStream cms))
      (c/trap! GeneralSecurityException
               "Decompress stream: corrupted content"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- si-tester
  [^JcaCertStore cs ^SignerInformation si]
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
         (t/with-BC
           JcaSimpleSignerInfoVerifierBuilder)
         dg
         (if
           (.verify si (.build bdr h))
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
(defn test-pkcs-digsig
  "Verify the signed object with the signature"
  ^bytes [^Certificate cert xs ^bytes sig]
  (let
    [sls (some-> (to-cms xs)
                 (CMSSignedData. sig)
                 .getSignerInfos
                 .getSigners)
     cs (JcaCertStore. [cert])
     rc (some (partial si-tester cs) (seq sls))]
    (if (nil? rc)
      (c/trap! GeneralSecurityException
               "Decode signature: no matching cert"))
    rc))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn test-smime-digsig
  "Verify the signature and return content if ok"
  ([mp certs] (test-smime-digsig mp certs nil))
  ([^MimeMultipart mp certs ^String cte]
   {:pre [(some? mp)]}
   (let
     [sc (if (s/hgl? cte)
           (SMIMESigned. mp cte)
           (SMIMESigned. mp))
      sns (-> (.getSignerInfos sc)
              .getSigners)
      cs (JcaCertStore. certs)
      rc (some (partial si-tester cs) (seq sns))]
     (if (nil? rc)
       (c/trap! GeneralSecurityException
                "Verify signature: no matching cert"))
     {:content
      (some-> sc
              (.getContentAsMimeMessage (t/session<>))
              .getContent)
      :digest rc})))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn pkcs-digsig
  "Sign some data"
  ^bytes
  [^PrivateKey pkey certs algo xs]
  {:pre [(not-empty certs)]}
  (let
    [bdr (-> (t/with-BC JcaDigestCalculatorProviderBuilder)
             .build
             JcaSignerInfoGeneratorBuilder.)
     algo (s/ucase (s/kw->str algo))
     cs (-> (t/with-BC1 JcaContentSignerBuilder algo)
            (.build pkey))
     gen (CMSSignedDataGenerator.)
     cert (c/_1 certs)]
    (.setDirectSignature bdr true)
    (doto gen
      (.addSignerInfoGenerator
        (.build bdr cs ^X509Certificate cert))
      (.addCertificates (JcaCertStore. certs)))
    (-> (.generate gen (to-cms xs) false) .getEncoded)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmulti smime-deflate
  "Compress content" {:tag MimeBodyPart} (fn [a & xs] (class a)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmethod smime-deflate
  MimeMessage
  [^MimeMessage msg]
   ;; make sure it's processed, just in case
   (.getContent msg)
   (-> (SMIMECompressedGenerator.)
       (.generate msg (ZlibCompressor.))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmethod smime-deflate String
  ([cType xs]
   (let [ds (data-source<> cType xs)]
     (-> (SMIMECompressedGenerator.)
         (.generate (doto
                      (MimeBodyPart.)
                      (.setDataHandler (DataHandler. ds)))
                    (ZlibCompressor.)))))
  ([cType xs ^String cloc ^String cid]
   {:pre [(s/hgl? cloc) (s/hgl? cid)]}
   (let [ds (data-source<> cType xs)
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


