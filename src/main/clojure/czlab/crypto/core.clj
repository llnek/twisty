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

(ns ^{:doc "Crypto related functions."
      :author "Kenneth Leung" }

  czlab.crypto.core

  (:require
    [czlab.xlib.dates :refer [plusMonths]]
    [czlab.xlib.files :refer [writeFile]]
    [czlab.xlib.io
     :refer [streamify
             baos<>
             resetStream!]]
    [czlab.xlib.str
     :refer [strbf<>
             stror
             lcase
             ucase
             strim
             hgl?]]
    [czlab.xlib.logging :as log]
    [clojure.string :as cs]
    [czlab.xlib.mime :as mime]
    [czlab.xlib.core
     :refer [throwBadArg
             seqint
             throwIOE
             srandom<>
             bytesify
             try!!
             try!
             trap!
             cast?
             juid
             getClassname]])

  (:import
    [org.bouncycastle.pkcs.jcajce JcaPKCS10CertificationRequestBuilder]
    [org.bouncycastle.operator OperatorCreationException ContentSigner]
    [org.bouncycastle.operator DigestCalculatorProvider ContentSigner]
    [org.bouncycastle.asn1.cms AttributeTable IssuerAndSerialNumber]
    [javax.activation DataHandler CommandMap MailcapCommandMap]
    [javax.mail BodyPart MessagingException Multipart Session]
    [clojure.lang
     APersistentVector]
    [java.io
     PrintStream
     File
     InputStream
     IOException
     FileInputStream
     InputStreamReader
     ByteArrayInputStream
     ByteArrayOutputStream ]
    [java.math BigInteger]
    [java.net URL]
    [java.util Random Date]
    [javax.mail.internet
     ContentType
     MimeBodyPart
     MimeMessage
     MimeMultipart
     MimeUtility]
    [org.bouncycastle.asn1 ASN1ObjectIdentifier]
    [org.bouncycastle.cms CMSAlgorithm]
    [org.bouncycastle.cert X509CertificateHolder]
    [java.security
     Policy
     PermissionCollection
     CodeSource
     Permissions
     KeyPair
     KeyPairGenerator
     KeyStore
     MessageDigest
     PrivateKey
     Provider
     PublicKey
     AllPermission
     SecureRandom
     Security
     KeyStore$PasswordProtection
     GeneralSecurityException
     KeyStore$PrivateKeyEntry
     KeyStore$TrustedCertificateEntry]
    [java.security.cert
     CertificateFactory
     Certificate
     X509Certificate]
    [org.bouncycastle.jce.provider BouncyCastleProvider]
    [org.bouncycastle.asn1.x509 X509Extension]
    [org.bouncycastle.asn1 ASN1EncodableVector]
    [org.bouncycastle.asn1.smime
     SMIMECapabilitiesAttribute
     SMIMECapability
     SMIMECapabilityVector
     SMIMEEncryptionKeyPreferenceAttribute]
    [org.bouncycastle.asn1.x500 X500Name]
    [org.bouncycastle.cms
     CMSCompressedDataParser
     CMSException
     CMSProcessable
     CMSSignedGenerator
     CMSProcessableByteArray
     CMSProcessableFile
     CMSSignedData
     CMSSignedDataGenerator
     CMSTypedData
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
     JceKeyTransRecipientId
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
     JcaDigestCalculatorProviderBuilder ]
    [org.bouncycastle.util Store]
    [org.bouncycastle.operator.bc BcDigestCalculatorProvider]
    [javax.security.auth.x500 X500Principal]
    [org.bouncycastle.mail.smime SMIMEEnvelopedParser]
    [org.apache.commons.mail DefaultAuthenticator]
    [org.bouncycastle.cert.jcajce
     JcaCertStore
     JcaX509CertificateConverter
     JcaX509ExtensionUtils
     JcaX509v1CertificateBuilder
     JcaX509v3CertificateBuilder]
    [org.bouncycastle.cms.jcajce
     ZlibCompressor
     JcaSignerInfoGeneratorBuilder]
    [org.bouncycastle.openssl PEMParser]
    [org.bouncycastle.operator.jcajce
     JcaContentSignerBuilder
     JcaDigestCalculatorProviderBuilder]
    [org.bouncycastle.pkcs
     PKCS10CertificationRequest
     PKCS10CertificationRequestBuilder]
    [javax.crypto
     Cipher
     KeyGenerator
     Mac
     SecretKey]
    [javax.crypto.spec SecretKeySpec]
    [javax.net.ssl X509TrustManager TrustManager]
    [org.apache.commons.codec.binary Hex Base64]
    [org.apache.commons.io IOUtils]
    [czlab.crypto SSLTrustMgrFactory
     PasswordAPI
     CertDesc
     SDataSource]
    [czlab.xlib XData]
    [java.lang Math]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(def ^:private ^String DEF_ALGO "SHA1WithRSAEncryption")
(def ^:private ^String DEF_MAC "HmacSHA512")

(def ^:private EXPLICIT_SIGNING :EXPLICIT)
(def ^:private IMPLICIT_SIGNING :IMPLICIT)
(def ^:private DER_FORM :DER)
(def ^:private PEM_FORM :PEM)

(def ^String SHA512 "SHA512withRSA")
(def ^String SHA256 "SHA256withRSA")
(def ^String SHA1 "SHA1withRSA")
(def ^String SHA_512 "SHA-512")
(def ^String SHA_1 "SHA-1")
(def ^String SHA_256 "SHA-256")
(def ^String MD_5 "MD5")
(def ^String MD5 "MD5withRSA")

(def ^String AES256_CBC  "AES256_CBC")
(def ^String BFISH "BlowFish")
(def ^String PKCS12 "PKCS12")
(def ^String JKS "JKS")
(def ^String SHA1 "SHA1")
(def ^String MD5 "MD5")
(def ^String RAS  "RAS")
(def ^String DES  "DES")
(def ^String RSA  "RSA")
(def ^String DSA  "DSA")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn assertJce

  "This function should fail if the non-restricted (unlimited-strength)
   jce files are not placed in jre-home"
  []

  (let [kgen (doto
               (KeyGenerator/getInstance BFISH)
               (.init 256))]
    (-> (doto
          (Cipher/getInstance BFISH)
          (.init (Cipher/ENCRYPT_MODE)
                 (SecretKeySpec. (.. kgen
                                     generateKey
                                     getEncoded) BFISH)))
        (.doFinal (bytesify "yo")))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(def ^Provider _BCProvider (BouncyCastleProvider.))
(Security/addProvider _BCProvider)
(assertJce)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(doto
  ^MailcapCommandMap
  (CommandMap/getDefaultCommandMap)
  (.addMailcap (str "application/pkcs7-signature;; "
                    "x-java-content-handler="
                    "org.bouncycastle.mail.smime.handlers.pkcs7_signature"))
  (.addMailcap (str "application/pkcs7-mime;; "
                    "x-java-content-handler="
                    "org.bouncycastle.mail.smime.handlers.pkcs7_mime"))
  (.addMailcap (str "application/x-pkcs7-signature;; "
                    "x-java-content-handler="
                    "org.bouncycastle.mail.smime.handlers.x_pkcs7_signature") )
  (.addMailcap (str "application/x-pkcs7-mime;; "
                    "x-java-content-handler="
                    "org.bouncycastle.mail.smime.handlers.x_pkcs7_mime"))
  (.addMailcap (str "multipart/signed;; "
                    "x-java-content-handler="
                    "org.bouncycastle.mail.smime.handlers.multipart_signed") ))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn pkcsFile?

  "true if url points to a PKCS12 key file"
  [^URL keyUrl]

  (not (-> (.getFile keyUrl)
           lcase
           (.endsWith ".jks"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn msgDigest

  "Get a message digest instance:
  MD5
  SHA-1, SHA-256, SHA-384, SHA-512"
  ^MessageDigest
  [^String algo]

  (MessageDigest/getInstance algo _BCProvider))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn nextSerial

  "Get a random Big Integer"
  ^BigInteger
  []

  (BigInteger/valueOf
    (Math/abs (-> (Date.)
                  (.getTime)
                  (Random. )
                  (.nextLong)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn dbgProvider

  "List all BouncyCastle algos"
  {:no-doc true}
  [^PrintStream os]

  (try! (.list _BCProvider os)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- getsrand

  "Get a secure random"
  ^SecureRandom
  []

  (SecureRandom/getInstance "SHA1PRNG" ))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn alias<>

  "Generate a new name based on system timestamp"
  ^String
  []

  (format "%s#%04d"
          (-> (juid)
              (.substring 0 3)) (seqint)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn pkeye

  "Get a private key from the store"
  ^APersistentMap
  [^KeyStore store ^String n ^chars pwd]

  (when-some
    [e
     (->> (KeyStore$PasswordProtection. pwd)
          (.getEntry store n)
          (cast? KeyStore$PrivateKeyEntry ))]
    {:chain (.getCertificateChain e)
     :cert (.getCertificate e)
     :key (.getPrivateKey e)}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn tcerte

  "Get a certificate from store"
  ^KeyStore$TrustedCertificateEntry
  [^KeyStore store ^String n]

  (->> (.getEntry store n nil)
       (cast? KeyStore$TrustedCertificateEntry )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn filterEntries

  "Enumerate entries in the key-store"
  ^APersistentVector
  [^KeyStore store entryType]
  {:pre [(keyword? entryType)]}

  (loop [rc (transient [])
         en (.aliases store)]
    (if-not (.hasMoreElements en)
      (persistent! rc)
      (let
        [n (.nextElement en)]
        (if
          (cond
            (= :certs entryType)
            (.isCertificateEntry store n)
            (= :keys entryType)
            (.isKeyEntry store n)
            :else false)
          (recur (conj! rc n) en)
          (recur rc en))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn pkcsStore<>

  "Create a PKCS12 key-store"
  ^KeyStore
  [& [^InputStream inp ^chars pwd]]

  (let [ks (KeyStore/getInstance "PKCS12" _BCProvider)]
    (when (some? inp)
      (.load ks inp pwd))
    ks))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn jksStore<>

  "Create a JKS key-store"
  ^KeyStore
  [& [^InputStream inp ^chars pwd]]

  (let [ks (->> (Security/getProvider "SUN")
                (KeyStore/getInstance "JKS" ))]
    (when (some? inp)
      (.load inp pwd))
    ks))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn initStore!

  "Initialize the key-store"
  ^KeyStore
  [^KeyStore store arg ^chars pwd]

  (let [z (class arg)
        [b inp]
        (cond
          (= (bytesClass) z)
          [true (streamify arg)]
          (= InputStream z)
          [false arg]
          (= File z)
          [true (FileInputStream. arg)]
          :else (throwBadArg ""))]
    (try
      (.load store inp pwd)
      (finally
        (if b (.close inp))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn convCert

  "Convert to a Certificate"
  ^X509Certificate
  [^bytes bits]

  (-> (CertificateFactory/getInstance "X.509")
      (.generateCertificate (streamify bits))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn convPKey

  "Convert to a PrivateKey"
  ^APersistentMap
  [InputStream inp ^chars pwd & [^chars pwd2]]

  (let [ks (doto (pkcsStore<>)
             (.load inp pwd2))
        n (first (filterEntries ks :keys))]
    (when (hgl? n)
      (pkeye ks n pwd))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn easyPolicy<>

  "Make a Policy that enables all permissions"
  ^Policy
  []

  (proxy [Policy] []
    (getPermissions [cs]
      (doto (Permissions.)
        (.add (AllPermission.))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn genMac

  "Generate a Message Auth Code"
  ^String
  [^bytes skey ^bytes data & [algo] ]
  {:pre [(some? data)]}

  (let [^String algo (stror algo DEF_MAC)
        mac (Mac/getInstance algo _BCProvider)]
    (->> (SecretKeySpec. skey algo)
         (.init mac ))
    (.update mac data)
    (Hex/encodeHexString (.doFinal mac))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn genHash

  "Generate a Message Digest"
  ^String
  [^bytes data & [algo] ]
  {:pre [(some? data)]}

  (-> (-> ^String
          (stror algo SHA_512)
          (MessageDigest/getInstance ))
      (.digest data)
      (Base64/encodeBase64String )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn asymKeyPair

  "Make a Asymmetric key-pair"
  ^KeyPair
  [^String algo keylen]

  (log/debug "generating keypair for algo %s, length %s" algo keylen)
  (-> (doto (KeyPairGenerator/getInstance algo _BCProvider)
            (.initialize (int keylen) (srandom<>)))
      (.generateKeyPair )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- fmtPEM

  "Output as PEM"
  ^bytes
  [^String top ^String end ^bytes bits]

  (let [bs (-> (Base64/getMimeEncoder)
               (.encode bits))
        nl (bytesify "\n")
        bb (byte-array 1)
        baos (baos<>)
        len (alength bs)]
    (.write baos (bytesify top))
    (loop [pos 0]
      (if (== pos len)
        (do
          (.write baos (bytesify end))
          (.toByteArray baos))
        (do
          (when (and (> pos 0)
                     (== (mod pos 64) 0))
            (.write baos nl))
          (aset bb 0 (aget bs pos))
          (.write baos bb)
          (recur (inc pos)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn exportPrivateKey

  "Export Private Key"
  ^bytes
  [^PrivateKey pkey fmt]
  {:pre [(keyword? fmt)]}

  (let [bits (.getEncoded pkey)]
    (if (= fmt PEM_FORM)
      (fmtPEM "-----BEGIN RSA PRIVATE KEY-----\n"
              "\n-----END RSA PRIVATE KEY-----\n"
              bits)
      bits)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn exportPublicKey

  "Export Public Key"
  ^bytes
  [^PublicKey pkey fmt]
  {:pre [(keyword? fmt)]}

  (let [bits (.getEncoded pkey)]
    (if (= fmt PEM_FORM)
      (fmtPEM "-----BEGIN RSA PUBLIC KEY-----\n"
              "\n-----END RSA PUBLIC KEY-----\n"
              bits)
      bits)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn exportCert

  "Export Certificate"
  ^bytes
  [^X509Certificate cert fmt]
  {:pre [(keyword? fmt)]}

  (let [bits (.getEncoded cert)]
    (if (= fmt PEM_FORM)
      (fmtPEM "-----BEGIN CERTIFICATE-----\n"
              "-----END CERTIFICATE-----\n"
              bits)
      bits)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn csrReQ

  "Make a PKCS10 - csr-request"
  [^String dnStr keylen fmt]
  {:pre [(keyword? fmt)]}

  (log/debug "csrreq: dnStr= %s, key-len= %s" dnStr keylen)
  (let [csb (JcaContentSignerBuilder. DEF_ALGO)
        kp (asymKeyPair RSA keylen)
        rbr (new JcaPKCS10CertificationRequestBuilder
                 (X500Principal. dnStr)
                 (.getPublic kp))
        k (.getPrivate kp)
        cs (-> (.setProvider csb _BCProvider)
               (.build k))
        bits (-> (.build rbr cs)
                 (.getEncoded))]
    [(if (= fmt PEM_FORM)
       (fmtPEM "-----BEGIN CERTIFICATE REQUEST-----\n"
               "\n-----END CERTIFICATE REQUEST-----\n"
               bits)
       bits)
     (exportPrivateKey k fmt)]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; generate self-signed cert
;; self signed-> issuer is self
(defn- mkSSV1Cert

  ""
  [^Provider pv
   ^KeyPair kp
   {:keys [dnStr algo start end] :as options}]

  (let [prv (.getPrivate kp)
        pub (.getPublic kp)
        bdr (new JcaX509v1CertificateBuilder
                 (X500Principal. ^String dnStr)
                 (nextSerial)
                 ^Date start
                 ^Date end
                 (X500Principal. ^String dnStr)
                 pub)
        cs (-> (JcaContentSignerBuilder. ^String algo)
               (.setProvider pv)
               (.build prv))
        cert (-> (JcaX509CertificateConverter.)
                 (.setProvider  pv)
                 (.getCertificate (.build bdr cs)))]
    (.checkValidity cert (Date.))
    (.verify cert pub)
    (log/debug "mkSSV1Cert: dn= %s%s%s%s%s%s%s"
               dnStr
               ", algo= " algo
               ", start=" start ", end=" end )
    [cert prv]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- mkSSV1

  "Make a SSV1 self-signed server key"
  ^bytes
  [^KeyStore ks
   ^KeyPair kp
   ^chars pwd options]

  (let [[^Certificate cert ^PrivateKey pkey]
        (mkSSV1Cert (.getProvider ks) kp options)
        baos (byteOS)]
    (.setKeyEntry ks
                  (juid)
                  pkey
                  pwd
                  (into-array Certificate [cert] ))
    (.store ks baos pwd)
    (.toByteArray baos)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn pkcs12

  "Make a PKCS12 object from key and cert"
  [^bytes keyPEM
   ^bytes certPEM
   ^chars pwd ^File out]

  (let [ct (.getTrustedCertificate (convCert certPEM))
        rdr (InputStreamReader. (streamify keyPEM))
        baos (byteOS)
        ss (pkcsStore<>)
        ^KeyPair kp (.readObject (PEMParser. rdr))]
    (.setKeyEntry ss
                  (juid)
                  (.getPrivate kp)
                  pwd
                  (into-array Certificate [ct]))
    (.store ss baos pwd)
    (writeFile out (.toByteArray baos))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmacro ssv1XXX

  ""
  {:private true
   :no-doc true}
  [store algo style dnStr pwd out options]

  `(let [dft# {:keylen 1024 :start (Date.)
               :end (plusMonths 12)
               :algo ~algo}
         opts# (-> (merge dft# ~options)
                   (assoc :dnStr ~dnStr))
         keylen# (:keylen opts#)
         v1# (mkSSV1 ~store
                      (asymKeyPair ~style keylen#)
                      ~pwd opts#) ]
     (writeFile ~out v1#)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ssv1PKCS12

  "Make a SSV1 (root level) type PKCS12 object"
  [^String dnStr ^chars pwd
   ^File out options]

  (ssv1XXX (pkcsStore<>) DEF_ALGO RSA dnStr pwd out options))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ssv1JKS

  "Make a SSV1 (root level) type JKS object"
  [^String dnStr ^chars pwd
   ^File out options]

  (ssv1XXX (jksStore<>) "SHA1withDSA" DSA dnStr pwd out options))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- mkSSV3Cert

  "Make a SSV3 server key"
  [^Provider pv
   ^KeyPair kp
   issuerObjs
   {:keys [dnStr algo start end] :as options}]

  (let [subject (X500Principal. ^String dnStr)
        exu (JcaX509ExtensionUtils.)
        [^X509Certificate
         issuer
         ^PrivateKey
         issuerKey] issuerObjs
        bdr (new JcaX509v3CertificateBuilder
                 issuer
                 (nextSerial)
                 ^Date start
                 ^Date end
                 subject
                 (.getPublic kp))
        cs (-> (JcaContentSignerBuilder. ^String algo)
               (.setProvider pv)
               (.build issuerKey))]
    (-> bdr
        (.addExtension X509Extension/authorityKeyIdentifier
                       false
                       (-> exu
                           (.createAuthorityKeyIdentifier issuer))))
    (-> bdr
        (.addExtension X509Extension/subjectKeyIdentifier
                       false
                       (-> exu
                           (.createSubjectKeyIdentifier (.getPublic kp)))))
    (let [ct (-> (JcaX509CertificateConverter.)
                 (.setProvider pv)
                 (.getCertificate (.build bdr cs))) ]
      (.checkValidity ct (Date.))
      (.verify ct (.getPublicKey issuer))
      [ ct (.getPrivate kp) ] )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- mkSSV3

  "Make a SSV3 server key"
  [^KeyStore ks ^chars pwd
   issuerObjs options ]

  (let [^PrivateKey issuerKey (last issuerObjs)
        issuerCerts (vec (first issuerObjs))
        [^Certificate cert
         ^PrivateKey pkey]
        (mkSSV3Cert (.getProvider ks)
                    (asymKeyPair (.getAlgorithm issuerKey)
                                 (:keylen options))
                    [ (first issuerCerts) issuerKey ]
                    options)
        baos (byteOS)
        cs (cons cert issuerCerts) ]
    (.setKeyEntry ks (juid) pkey pwd (into-array Certificate cs))
    (.store ks baos pwd)
    (.toByteArray baos)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- make-ssv3XXX

  ""
  [^String dnStr ^chars pwd
   ^File out
   {:keys [hack issuerKey issuerCerts] :as options}]

  (let [issuerObjs [issuerCerts issuerKey]
        opts (-> (merge {:keylen 1024
                         :start (Date.)
                         :end (plusMonths 12) }
                        {:algo (:algo hack) }
                        options)
                 (assoc :dnStr dnStr))
        ks (:ks hack)]
    (->> (-> opts
             (dissoc :issuerCerts)
             (dissoc :hack)
             (dissoc :issuerKey))
         (mkSSV3 ks pwd issuerObjs)
         (writeFile out ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ssv3PKCS12

  "Make a SSV3 type PKCS12 object"
  [^String dnStr ^chars pwd
   ^File out options]

  (make-ssv3XXX dnStr
                pwd
                out
                (-> options
                    (assoc :hack
                           {:algo DEF_ALGO
                            :ks (pkcsStore<>) } ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; JKS uses SUN and hence needs to use DSA
;;
(defn ssv3JKS

  "Make a SSV3 JKS object"
  [^String dnStr ^chars pwd
   ^File out options]

  (make-ssv3XXX dnStr
                pwd
                out
                (-> options
                    (assoc :hack
                           {:algo "SHA1withDSA"
                            :ks (jksStore<>) } ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn exportPkcs7

  "Extract and export PKCS7 info from a PKCS12 object"
  [^File fileOut ^URL p12File ^chars pwd & [^chars pwd2]]

  (with-open [inp (.openStream p12File)]
    (let
      [xxx (CMSProcessableByteArray. (bytesify "???"))
       gen (CMSSignedDataGenerator.)
       pkey (convPKey inp pwd pwd2)
       cl (:chain pkey)
       bdr (new JcaSignerInfoGeneratorBuilder
                (-> (JcaDigestCalculatorProviderBuilder.)
                    (.setProvider _BCProvider)
                    (.build)))
       ;;    "SHA1withRSA"
       cs (-> (JcaContentSignerBuilder. SHA512)
              (.setProvider _BCProvider)
              (.build (.getPrivateKey pkey)))
       ^X509Certificate x509 (first cl)]
      (->> (.build bdr cs x509)
           (.addSignerInfoGenerator gen ))
      (->> (JcaCertStore. cl)
           (.addCertificates gen ))
      (writeFile fileOut (-> (.generate gen xxx)
                             (.getEncoded))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn session<>

  "Creates a new java-mail session"
  ^Session
  [ & [^String user ^chars pwd] ]

  (Session/getInstance
    (System/getProperties)
    (when (hgl? user)
      (->> (if (some? pwd) (String. pwd))
           (DefaultAuthenticator. user)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn mimeMsg<>

  "Create a new MIME Message"

  (^MimeMessage
    [^String user ^chars pwd]
    (mimeMsg<> user pwd nil))

  (^MimeMessage
    [^InputStream inp]
    (mimeMsg<> "" nil inp))

  (^MimeMessage
    []
    (mimeMsg<> "" nil nil))

  (^MimeMessage
    [^String user
     ^chars pwd
     ^InputStream inp]
    (let [s (session<> user pwd)]
      (if (nil? inp)
        (MimeMessage. s)
        (MimeMessage. s inp)))) )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn isSigned?

  "Check if this stream-like object/message-part is signed"
  [^Object obj]

  (if-some [inp (mime/maybeStream obj)]
    (try
      (->> (mimeMsg<> "" nil inp)
           (.getContentType)
           (mime/isSigned? ))
      (finally
        (resetStream! inp)))
    (if (instance? Multipart obj)
      (->> ^Multipart obj
           (.getContentType )
           (mime/isSigned? ))
      (throwIOE "Invalid content: %s" (getClassname obj)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn isCompressed?

  "Check if this stream-like object/message-part is compressed"
  [^Object obj]

  (if-some [inp (mime/maybeStream obj)]
    (try
      (->> (mimeMsg<> "" nil inp)
           (.getContentType )
           (mime/isCompressed? ))
      (finally
        (resetStream! inp)))
    (condp instance? obj
      Multipart (->> ^Multipart obj
                     (.getContentType )
                     (mime/isCompressed? ))
      BodyPart (->> ^BodyPart obj
                    (.getContentType )
                    (mime/isCompressed? ))
      (throwIOE "Invalid content: %s" (getClassname obj)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn isEncrypted?

  "Check if this stream-like object/message-part is encrypted"
  [^Object obj]

  (if-some [inp (mime/maybeStream obj)]
    (try
      (->> (mimeMsg<> "" nil inp)
           (.getContentType )
           (mime/isEncrypted? ))
      (finally
        (resetStream! inp)))
    (condp instance? obj
      Multipart (->> ^Multipart obj
                     (.getContentType )
                     (mime/isEncrypted? ))
      BodyPart (->> ^BodyPart obj
                    (.getContentType )
                    (mime/isEncrypted? ))
      (throwIOE "Invalid content: %s" (getClassname obj)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn getCharset

  "Deduce the char-set from content-type"
  ^String
  [^String cType & [^String dft] ]

  (str
    (stror
      (when (hgl? cType)
        (try! (-> (ContentType. cType)
                  (.getParameter "charset")
                  (MimeUtility/javaCharset ))))
      (when (hgl? dft)
        (MimeUtility/javaCharset dft)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- finger-print

  ""
  ^String
  [^bytes data ^String algo]

  (let [hv (-> (MessageDigest/getInstance (str algo))
               (.digest data))
        hlen (alength hv)
        tail (dec hlen)]
    (loop [ret (strbf<>)
           i 0 ]
      (if (>= i hlen)
        (str ret)
        (let [n (-> (bit-and (aget ^bytes hv i) 0xff)
                    (Integer/toString  16)
                    (cs/upper-case )) ]
          (-> ret
              (.append (if (= (.length n) 1) (str "0" n) n))
              (.append (if (= i tail) "" ":")))
          (recur ret (inc i)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmacro fingerprintSHA1

  "Generate a fingerprint/digest using SHA-1"
  ^String
  [^bytes data]

  `(finger-print ~data SHA_1))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmacro fingerprintMD5

  "Generate a fingerprint/digest using MD5"
  ^String
  [^bytes data]

  `(finger-print ~data MD_5))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- mkCertGist

  "Key data describing a Certificate"
  ^CertGist
  [^X500Principal _issuer
   ^X500Principal _subj
   ^Date _notbefore
   ^Date _notafter ]

  (reify

    CertGist

    (notBefore [_] _notbefore)
    (notAfter [_] _notafter)
    (issuer [_] _issuer)
    (subj [_] _subj)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn certGist

  "Get some basic info from Certificate"
  ^CertGist
  [^X509Certificate x509]

  (if (nil? x509)
    (mkCertGist nil nil nil nil)
    (mkCertGist
      (.getIssuerX500Principal x509)
      (.getSubjectX500Principal x509)
      (.getNotBefore x509)
      (.getNotAfter x509))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn validCert?

  "Validate this Certificate"
  [^X509Certificate x509]

  (try!! false (.checkValidity x509 (Date.))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn simpleTrustMgr<>

  "Make a pass through trust manager"
  ^X509TrustManager
  []

  (nth (SSLTrustMgrFactory/getTrustManagers) 0))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


