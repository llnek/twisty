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
    [czlab.xlib.io :refer [streamify byteOS resetStream!]]
    [czlab.xlib.str :refer [lcase ucase strim hgl?]]
    [czlab.xlib.files :refer [writeOneFile]]
    [czlab.xlib.dates :refer [plusMonths]]
    [czlab.xlib.logging :as log]
    [clojure.string :as cs]
    [czlab.xlib.mime :as mime]
    [czlab.xlib.core
     :refer [nextInt
             throwIOE
             throwBadArg
             newRandom
             bytesify
             trycr
             tryc
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
;;(defonce DES_EDE3_CBC CMSAlgorithm/DES_EDE3_CBC)
;;(defonce RC2_CBC CMSAlgorithm/RC2_CBC)
;;(defonce IDEA_CBC CMSAlgorithm/IDEA_CBC)
;;(defonce CAST5_CBC CMSAlgorithm/CAST5_CBC)
;;(defonce AES128_CBC CMSAlgorithm/AES128_CBC)
;;(defonce AES192_CBC CMSAlgorithm/AES192_CBC)
;;(defonce AES256_CBC CMSAlgorithm/AES256_CBC)
;;(defonce CAMELLIA128_CBC CMSAlgorithm/CAMELLIA128_CBC)
;;(defonce CAMELLIA192_CBC CMSAlgorithm/CAMELLIA192_CBC)
;;(defonce CAMELLIA256_CBC CMSAlgorithm/CAMELLIA256_CBC)
;;(defonce SEED_CBC CMSAlgorithm/SEED_CBC)
;;(defonce DES_EDE3_WRAP CMSAlgorithm/DES_EDE3_WRAP;;)
;;(defonce AES128_WRAP CMSAlgorithm/AES128_WRAP)
;;(defonce AES256_WRAP CMSAlgorithm/AES256_WRAP)
;;(defonce CAMELLIA128_WRAP CMSAlgorithm/CAMELLIA128_WRAP)
;;(defonce CAMELLIA192_WRAP CMSAlgorithm/CAMELLIA192_WRAP)
;;(defonce CAMELLIA256_WRAP CMSAlgorithm/CAMELLIA256_WRAP)
;;(defonce SEED_WRAP CMSAlgorithm/SEED_WRAP)
;;(defonce ECDH_SHA1KDF CMSAlgorithm/ECDH_SHA1KDF)

(def ^:private ^String DEF_ALGO "SHA1WithRSAEncryption")
(def ^:private ^String DEF_MAC "HmacSHA512")

(defonce ^:private EXPLICIT_SIGNING :EXPLICIT)
(defonce ^:private IMPLICIT_SIGNING :IMPLICIT)
(defonce ^:private DER_FORM :DER)
(defonce ^:private PEM_FORM :PEM)

(defonce ^String SHA512 "SHA512withRSA")
(defonce ^String SHA256 "SHA256withRSA")
(defonce ^String SHA1 "SHA1withRSA")
(defonce ^String SHA_512 "SHA-512")
(defonce ^String SHA_1 "SHA-1")
(defonce ^String SHA_256 "SHA-256")
(defonce ^String MD_5 "MD5")
(defonce ^String MD5 "MD5withRSA")

(defonce ^String AES256_CBC  "AES256_CBC")
(defonce ^String BFISH "BlowFish")
(defonce ^String PKCS12 "PKCS12")
(defonce ^String JKS "JKS")
(defonce ^String SHA1 "SHA1")
(defonce ^String MD5 "MD5")
(defonce ^String RAS  "RAS")
(defonce ^String DES  "DES")
(defonce ^String RSA  "RSA")
(defonce ^String DSA  "DSA")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn assertJce

  "This function should fail if the non-restricted (unlimited-strength)
   jce files are not placed in jre-home"

  []

  (let [kgen (doto
               (KeyGenerator/getInstance BFISH)
               (.init 256)) ]
    (-> (doto
          (Cipher/getInstance BFISH)
          (.init (Cipher/ENCRYPT_MODE)
                 (SecretKeySpec. (.. kgen
                                     generateKey
                                     getEncoded) BFISH)))
        (.doFinal (bytesify "yo")))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defonce ^Provider _BCProvider (BouncyCastleProvider.))
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
           (lcase)
           (.endsWith ".jks"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn msgDigest

  "Get a message digest instance:
  MD5
  SHA-1, SHA-256, SHA-384, SHA-512"

  ^MessageDigest
  [algo]

  (MessageDigest/getInstance (name algo) _BCProvider))

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
(defn newAlias

  "Generate a new name based on system timestamp"

  ^String
  []

  (str (-> (juid)
           (.substring 0 3)) "#" (nextInt)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- findAliases

  "Acts like a filter to get a set of aliases"

  [^KeyStore ks predicate]

  (loop [rc (transient [])
         en (.aliases ks) ]
    (if-not (.hasMoreElements en)
      (persistent! rc)
      (let
        [n (.nextElement en)]
        (if (predicate ks n)
          (recur (conj! rc n) en)
          (recur rc en))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn getPKey

  "Get a private key from the store"

  ^KeyStore$PrivateKeyEntry
  [^KeyStore store ^String n ^chars pwd]

  (->> (KeyStore$PasswordProtection. pwd)
       (.getEntry store n)
       (cast? KeyStore$PrivateKeyEntry )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn getCert

  "Get a certificate from store"

  ^KeyStore$TrustedCertificateEntry
  [^KeyStore store ^String n ^chars pwd]

  (->> (.getEntry store n nil)
       (cast? KeyStore$TrustedCertificateEntry )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn certAliases

  "Enumerate all cert aliases in the key-store"

  ^APersistentVector
  [^KeyStore store]

  (findAliases store
               #(.isCertificateEntry ^KeyStore %1 (str %2))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn pkeyAliases

  "Enumerate all key aliases in the key-store"

  ^APersistentVector
  [^KeyStore store]

  (findAliases store
               #(.isKeyEntry ^KeyStore %1 (str %2))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- regoCerts

  "Go through all private keys and from their cert chains,
   register each individual cert"

  [^KeyStore ks ^PasswordAPI pwdObj]

  (let [ca (some-> pwdObj (.toCharArray)) ]
    (doseq [a (pkeyAliases ks)
            :let [cs (-> ^KeyStore$PrivateKeyEntry
                         (getPKey ks a ca)
                         (.getCertificateChain )) ]]
      (doseq [^Certificate c (seq cs)]
        (.setCertificateEntry ks (newAlias) c)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn getPkcsStore

  "Create a PKCS12 key-store"

  ^KeyStore
  [& [^InputStream inp ^PasswordAPI pwdObj]]

  (let [^chars
        ca (some-> pwdObj (.toCharArray ))
        ks (doto
             (KeyStore/getInstance "PKCS12" _BCProvider)
             (.load inp ca)) ]
    (when (some? inp)
      (regoCerts ks pwdObj))
    ks))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn getJksStore

  "Create a JKS key-store"

  ^KeyStore
  [& [^InputStream inp ^PasswordAPI pwdObj]]

  (let [pv (Security/getProvider "SUN")
        ^chars
        ca (some-> pwdObj (.toCharArray ))
        ks (doto
             (KeyStore/getInstance "JKS" pv)
             (.load inp ca)) ]
    (when (some? inp)
      (regoCerts ks pwdObj))
    ks))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmulti initStore! "Initialize the key-store" (fn [_ b & xs] (class b)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod initStore!

  InputStream

  ^KeyStore
  [^KeyStore store ^InputStream inp ^PasswordAPI pwdObj]

  (doto store
    (.load inp (some-> pwdObj (.toCharArray )))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod initStore!

  :default

  ^KeyStore
  [^KeyStore ks ^bytes bits ^PasswordAPI pwdObj]

  (initStore! ks (streamify bits) pwdObj))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod initStore!

  File

  ^KeyStore
  [^KeyStore ks ^File f ^PasswordAPI pwdObj]

  (with-open
    [inp (FileInputStream. f) ]
    (initStore! ks inp pwdObj)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn convCert

  "Convert to a Certificate"

  ^KeyStore$TrustedCertificateEntry
  [^bytes bits]

  (let [ks (getPkcsStore)
        nm (newAlias)]
    (->> (-> (CertificateFactory/getInstance "X.509")
             (.generateCertificate (streamify bits)))
         (.setCertificateEntry ks nm ))
    (.getEntry ks nm nil)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn convPKey

  "Convert to a PrivateKey"

  ^KeyStore$PrivateKeyEntry
  [^bytes bits ^PasswordAPI pwdObj]

  (let [^chars
        ca (some-> pwdObj
                   (.toCharArray ))
        ks (getPkcsStore) ]
    (.load ks (streamify bits) ca)
    (.getEntry ks
               (str (first (pkeyAliases ks)))
               (KeyStore$PasswordProtection. ca))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn easyPolicy

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

  (let [^String algo (or algo DEF_MAC)
        mac (Mac/getInstance algo _BCProvider) ]
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

  (-> (->> (str (or algo SHA_512))
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
            (.initialize (int keylen) (newRandom)))
      (.generateKeyPair )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- loadPKCS12Key

  "Load a PKCS12 key file"

  ^KeyStore$PrivateKeyEntry
  [^URL p12File
   ^PasswordAPI pwdObj]

  (with-open
    [inp (.openStream p12File) ]
    (let
      [ca (some-> pwdObj
                  (.toCharArray ))
       ks (doto (getPkcsStore)
                (.load inp ca)) ]
      (getPKey ks (.nextElement (.aliases ks)) ca))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- fmtPEM

  "Output as PEM"

  ^bytes
  [^String top ^String end ^bytes bits]

  (let [bs (Base64/encodeBase64 bits)
        nl (bytesify "\n")
        bb (byte-array 1)
        baos (byteOS)
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

  (let [bits (.getEncoded pkey) ]
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

  (let [bits (.getEncoded pkey) ]
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

  (let [bits (.getEncoded cert) ]
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
                 (.getEncoded)) ]
    [(if (= fmt PEM_FORM)
       (fmtPEM "-----BEGIN CERTIFICATE REQUEST-----\n"
               "\n-----END CERTIFICATE REQUEST-----\n"
               bits)
       bits)
     (exportPrivateKey k fmt) ]))

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
                 (.getCertificate (.build bdr cs))) ]
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
   ^PasswordAPI pwdObj options]

  (let [[^Certificate cert ^PrivateKey pkey]
        (mkSSV1Cert (.getProvider ks) kp options)
        ^chars ca (some-> pwdObj
                          (.toCharArray ))
        baos (byteOS) ]
    (.setKeyEntry ks
                  (juid)
                  pkey
                  ca
                  (into-array Certificate [cert] ))
    (.store ks baos ca)
    (.toByteArray baos)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn pkcs12

  "Make a PKCS12 object from key and cert"

  [^bytes keyPEM
   ^bytes certPEM
   ^PasswordAPI pwdObj ^File out]

  (let [ct (.getTrustedCertificate (convCert certPEM))
        rdr (InputStreamReader. (streamify keyPEM))
        ^chars ca (some-> pwdObj
                          (.toCharArray ))
        baos (byteOS)
        ss (getPkcsStore)
        ^KeyPair kp (.readObject (PEMParser. rdr)) ]
    (.setKeyEntry ss
                  (juid)
                  (.getPrivate kp)
                  ca
                  (into-array Certificate [ct]))
    (.store ss baos ca)
    (writeOneFile out (.toByteArray baos))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmacro ssv1XXX

  ""

  {:private true
   :no-doc true}
  [store algo style dnStr pwdObj out options]

  `(let [dft# {:keylen 1024 :start (Date.)
               :end (plusMonths 12)
               :algo ~algo}
         opts# (-> (merge dft# ~options)
                   (assoc :dnStr ~dnStr))
         keylen# (:keylen opts#)
         v1# (mkSSV1 ~store
                      (asymKeyPair ~style keylen#)
                      ~pwdObj opts#) ]
     (writeOneFile ~out v1#)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ssv1PKCS12

  "Make a SSV1 (root level) type PKCS12 object"

  [^String dnStr ^PasswordAPI pwdObj
   ^File out options]

  (ssv1XXX (getPkcsStore) DEF_ALGO RSA dnStr pwdObj out options))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ssv1JKS

  "Make a SSV1 (root level) type JKS object"

  [^String dnStr ^PasswordAPI pwdObj
   ^File out options]

  (ssv1XXX (getJksStore) "SHA1withDSA"  DSA dnStr pwdObj out options))

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
               (.build issuerKey)) ]
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

  [^KeyStore ks ^PasswordAPI pwdObj
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
        ^chars ca (some-> pwdObj (.toCharArray ))
        baos (byteOS)
        cs (cons cert issuerCerts) ]
    (.setKeyEntry ks (juid) pkey ca (into-array Certificate cs))
    (.store ks baos ca)
    (.toByteArray baos)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- make-ssv3XXX

  ""

  [^String dnStr ^PasswordAPI pwdObj
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
         (mkSSV3 ks pwdObj issuerObjs )
         (writeOneFile out ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ssv3PKCS12

  "Make a SSV3 type PKCS12 object"

  [^String dnStr ^PasswordAPI pwdObj
   ^File out options]

  (make-ssv3XXX dnStr
                pwdObj
                out
                (-> options
                    (assoc :hack
                           {:algo DEF_ALGO
                            :ks (getPkcsStore) } ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; JKS uses SUN and hence needs to use DSA
;;
(defn ssv3JKS

  "Make a SSV3 JKS object"

  [^String dnStr ^PasswordAPI pwdObj
   ^File out options]

  (make-ssv3XXX dnStr
                pwdObj
                out
                (-> options
                    (assoc :hack
                           {:algo "SHA1withDSA"
                            :ks (getJksStore) } ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn exportPkcs7

  "Extract and export PKCS7 info from a PKCS12 object"

  [^URL p12File ^PasswordAPI pwdObj
   ^File fileOut]

  (let [dummy (CMSProcessableByteArray. (bytesify "???"))
        pkey (loadPKCS12Key p12File pwdObj)
        cl (vec (.getCertificateChain pkey))
        gen (CMSSignedDataGenerator.)
        bdr (new JcaSignerInfoGeneratorBuilder
                 (-> (JcaDigestCalculatorProviderBuilder.)
                     (.setProvider _BCProvider)
                     (.build)))
;;    "SHA1withRSA"
        cs (-> (JcaContentSignerBuilder. (str SHA512))
               (.setProvider _BCProvider)
               (.build (.getPrivateKey pkey)))
        ^X509Certificate x509 (first cl) ]
    (.addSignerInfoGenerator gen (.build bdr cs x509))
    (.addCertificates gen (JcaCertStore. cl))
    (writeOneFile fileOut (-> (.generate gen dummy)
                              (.getEncoded)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn newSession

  "Creates a new java-mail session"

  ^Session
  [ & [^String user ^PasswordAPI pwdObj] ]

  (Session/getInstance
    (System/getProperties)
    (when (hgl? user)
      (DefaultAuthenticator. user (str pwdObj)) )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn newMimeMsg

  "Create a new MIME Message"

  (^MimeMessage
    [^String user
     ^PasswordAPI pwdObj]
    (newMimeMsg user pwdObj nil))

  (^MimeMessage
    [^InputStream inp]
    (newMimeMsg "" nil inp))

  (^MimeMessage
    []
    (newMimeMsg "" nil nil))

  (^MimeMessage
    [^String user
     ^PasswordAPI pwdObj
     ^InputStream inp]
    (let [s (newSession user pwdObj) ]
      (if (nil? inp)
        (MimeMessage. s)
        (MimeMessage. s inp)))) )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn isSigned?

  "Check if this stream-like object/message-part is signed"

  [^Object obj]

  (if-some [inp (mime/maybeStream obj) ]
    (try
      (->> (newMimeMsg "" "" inp)
           (.getContentType )
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

  (if-some [inp (mime/maybeStream obj) ]
    (try
      (->> (newMimeMsg "" "" inp)
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

  (if-some [inp (mime/maybeStream obj) ]
    (try
      (->> (newMimeMsg "" "" inp)
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

  (if (empty? dft)
    (if (hgl? cType)
      (str (tryc
             (-> (ContentType. cType)
                 (.getParameter "charset")
                 (MimeUtility/javaCharset ))))
      "")
    (let [cs (getCharset cType) ]
      (str (if (hgl? cs) cs (MimeUtility/javaCharset dft))))) )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- finger-print

  ""

  ^String
  [^bytes data ^String algo]

  (let [hv (-> (MessageDigest/getInstance (str algo))
               (.digest data))
        hlen (alength hv)
        tail (dec hlen) ]
    (loop [ret (StringBuilder.)
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
(defn fingerprintSHA1

  "Generate a fingerprint/digest using SHA-1"

  ^String
  [^bytes data]

  (finger-print data SHA_1))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn fingerprintMD5

  "Generate a fingerprint/digest using MD5"

  ^String
  [^bytes data]

  (finger-print data MD_5))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn certDesc

  "Key data describing a Certificate"

  ^CertDesc
  [^X500Principal _subj
   ^X500Principal _issuer
   ^Date _notbefore
   ^Date _notafter ]

  (reify

    CertDesc

    (notBefore [_] _notbefore)
    (notAfter [_] _notafter)
    (issuer [_] _issuer)
    (subj [_] _subj)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn descCertificate

  "Get some basic info from Certificate"

  ^CertDesc
  [^X509Certificate x509]

  (if (nil? x509)
    (certDesc nil nil nil nil)
    (certDesc (.getSubjectX500Principal x509)
              (.getIssuerX500Principal x509)
              (.getNotBefore x509)
              (.getNotAfter x509))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn descCert

  "Get description of a Certificate"

  (^CertDesc
    [^bytes privateKeyBits ^PasswordAPI pwdObj]
    (if-some [pkey (convPKey privateKeyBits pwdObj) ]
      (descCertificate (.getCertificate pkey))
      (certDesc nil nil nil nil)))

  (^CertDesc
    [^bytes certBits]
    (if-some [cert (convCert certBits)]
      (descCertificate (.getTrustedCertificate cert))
      (certDesc nil nil nil nil))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn validCertificate?

  "Validate this Certificate"

  [^X509Certificate x509]

  (trycr false (.checkValidity x509 (Date.))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn validPKey?

  "Validate this Private Key"

  [^bytes keyBits ^PasswordAPI pwdObj]

  (if-some [pkey (convPKey keyBits pwdObj)]
    (validCertificate? (.getCertificate pkey))
    false))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn validCert?

  "Validate this Certificate"

  [^bytes certBits]

  (if-some [cert (convCert certBits)]
    (validCertificate? (.getTrustedCertificate cert))
    false))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- intoArrayCerts

  "From a list of TrustedCertificateEntry(s)"

  [certs]

  (if (empty? certs)
    []
    (map #(.getTrustedCertificate ^KeyStore$TrustedCertificateEntry %1)
         (seq certs))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- intoArrayPKeys

  "From a list of PrivateKeyEntry(s)"

  [pkeys]

  (if (empty? pkeys)
    []
    (map #(.getPrivateKey ^KeyStore$PrivateKeyEntry %1)
         (seq pkeys))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn simpleTrustMgr

  "Make a pass through trust manager"

  ^X509TrustManager
  []

  (nth (SSLTrustMgrFactory/getTrustManagers) 0))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF

