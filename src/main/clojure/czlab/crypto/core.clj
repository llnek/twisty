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


(ns ^{:doc ""
      :author "kenl" }

  czlab.xlib.crypto.core

  (:require
    [czlab.xlib.util.io :refer [Streamify ByteOS ResetStream!]]
    [czlab.xlib.util.str :refer [lcase ucase strim hgl?]]
    [czlab.xlib.util.files :refer [WriteOneFile]]
    [czlab.xlib.util.dates :refer [PlusMonths]]
    [czlab.xlib.util.logging :as log]
    [clojure.string :as cs]
    [czlab.xlib.util.mime :as mime]
    [czlab.xlib.util.core
    :refer [NextInt ThrowIOE ThrowBadArg
    NewRandom Bytesify tryc try!
    trap! Cast? juid GetClassname]])

  (:import
    [org.bouncycastle.pkcs.jcajce JcaPKCS10CertificationRequestBuilder]
    [org.bouncycastle.operator OperatorCreationException ContentSigner]
    [org.bouncycastle.asn1.cms AttributeTable IssuerAndSerialNumber]
    [java.io PrintStream File InputStream IOException
    ByteArrayOutputStream ByteArrayInputStream
    FileInputStream InputStreamReader]
    [java.math BigInteger]
    [java.net URL]
    [java.util Random Date]
    [javax.activation DataHandler CommandMap MailcapCommandMap]
    [javax.mail BodyPart MessagingException Multipart Session]
    [javax.mail.internet ContentType
    MimeBodyPart MimeMessage MimeMultipart MimeUtility]
    [org.bouncycastle.asn1 ASN1ObjectIdentifier]
    ;;[org.bouncycastle.asn1.kisa KISAObjectIdentifiers]
    ;;[org.bouncycastle.asn1.nist NISTObjectIdentifiers]
    ;;[org.bouncycastle.asn1.ntt NTTObjectIdentifiers]
    ;;[org.bouncycastle.asn1.oiw OIWObjectIdentifiers]
    ;;[org.bouncycastle.asn1.pkcs PKCSObjectIdentifiers]
    ;;[org.bouncycastle.asn1.sec SECObjectIdentifiers]
    ;;[org.bouncycastle.asn1.teletrust TeleTrusTObjectIdentifiers]
    ;;[org.bouncycastle.asn1.x9 X9ObjectIdentifiers]
    [org.bouncycastle.cms CMSAlgorithm]
    [org.bouncycastle.cert X509CertificateHolder]
    [java.security KeyStore$PasswordProtection
    GeneralSecurityException
    KeyStore$PrivateKeyEntry KeyStore$TrustedCertificateEntry
    Policy PermissionCollection CodeSource
    Permissions KeyPair KeyPairGenerator KeyStore
    MessageDigest PrivateKey Provider PublicKey
    AllPermission SecureRandom Security]
    [java.security.cert CertificateFactory
    Certificate X509Certificate]
    [org.bouncycastle.jce.provider BouncyCastleProvider]
    [org.bouncycastle.asn1.x509 X509Extension]
    [org.bouncycastle.asn1 ASN1EncodableVector]
    [org.bouncycastle.asn1.smime SMIMECapabilitiesAttribute
    SMIMECapability
    SMIMECapabilityVector
    SMIMEEncryptionKeyPreferenceAttribute]
    [org.bouncycastle.asn1.x500 X500Name]
    [org.bouncycastle.cms CMSCompressedDataParser CMSException
    CMSProcessable CMSSignedGenerator
    CMSProcessableByteArray CMSProcessableFile
    CMSSignedData CMSSignedDataGenerator
    CMSTypedData CMSTypedStream
    DefaultSignedAttributeTableGenerator
    Recipient RecipientInfoGenerator
    RecipientInformation SignerInformation]
    [org.bouncycastle.cms.jcajce JcaSignerInfoGeneratorBuilder
    JcaSimpleSignerInfoVerifierBuilder
    JceCMSContentEncryptorBuilder
    JceKeyTransEnvelopedRecipient
    JceKeyTransRecipientId
    JceKeyTransRecipientInfoGenerator
    ZlibExpanderProvider]
    [org.bouncycastle.mail.smime SMIMECompressedGenerator
    SMIMEEnveloped
    SMIMEEnvelopedGenerator SMIMEException
    SMIMESigned SMIMESignedGenerator
    SMIMESignedParser]
    [org.bouncycastle.operator.jcajce
    JcaDigestCalculatorProviderBuilder JcaContentSignerBuilder]
    [org.bouncycastle.util Store]
    [org.bouncycastle.operator.bc BcDigestCalculatorProvider]
    [javax.security.auth.x500 X500Principal]
    [org.bouncycastle.mail.smime SMIMEEnvelopedParser]
    [org.apache.commons.mail DefaultAuthenticator]
    [org.bouncycastle.cert.jcajce JcaCertStore
    JcaX509CertificateConverter
    JcaX509ExtensionUtils
    JcaX509v1CertificateBuilder
    JcaX509v3CertificateBuilder]
    [org.bouncycastle.cms.jcajce ZlibCompressor
    JcaSignerInfoGeneratorBuilder]
    [org.bouncycastle.openssl PEMParser]
    [org.bouncycastle.operator DigestCalculatorProvider
    ContentSigner]
    [org.bouncycastle.operator.jcajce
    JcaDigestCalculatorProviderBuilder
    JcaContentSignerBuilder]
    [org.bouncycastle.pkcs
    PKCS10CertificationRequestBuilder
    PKCS10CertificationRequest]
    [javax.crypto Cipher KeyGenerator Mac SecretKey]
    [javax.crypto.spec SecretKeySpec]
    [javax.net.ssl X509TrustManager TrustManager]
    [org.apache.commons.codec.binary Hex Base64]
    [org.apache.commons.io IOUtils]
    [com.zotohlab.frwk.crypto PasswordAPI
    CertDesc SDataSource]
    [com.zotohlab.frwk.io XData]
    [com.zotohlab.frwk.net SSLTrustMgrFactory]
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

(defonce EXPLICIT_SIGNING :EXPLICIT)
(defonce IMPLICIT_SIGNING :IMPLICIT)
(defonce DER_CERT :DER)
(defonce PEM_CERT :PEM)

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

(def ^:private ^String DEF_ALGO "SHA1WithRSAEncryption")
(def ^:private ^String DEF_MAC "HmacSHA512")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn AssertJce

  "This function should fail if the non-restricted (unlimited-strength)
   jce files are not placed in jre-home"

  []

  (let
    [kgen (doto
            (KeyGenerator/getInstance BFISH)
            (.init 256)) ]
    (-> (doto
              (Cipher/getInstance BFISH)
              (.init (Cipher/ENCRYPT_MODE)
                     (SecretKeySpec. (.. kgen
                                         generateKey getEncoded) BFISH)))
        (.doFinal (Bytesify "This is just an example")))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(def ^:private ^Provider _BCProvider (BouncyCastleProvider.))
(Security/addProvider _BCProvider)
(AssertJce)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(doto ^MailcapCommandMap (CommandMap/getDefaultCommandMap)
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
(defn PkcsFile?

  "True if url points to a PKCS12 key file"

  [^URL keyUrl]

  (not (-> (.getFile keyUrl)
           (lcase)
           (.endsWith ".jks"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn MsgDigest*

  "Get a message digest instance"

  ^MessageDigest
  [algo]

  (MessageDigest/getInstance (str algo) _BCProvider))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn NextSerial

  "Get a random Big Integer"

  ^BigInteger
  []

  (let [r (Random. (.getTime (Date.))) ]
    (BigInteger/valueOf (Math/abs (.nextLong r)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn DbgProvider

  "List all BouncyCastle algos"

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
(defn NewAlias

  "Generate a new name based on system timestamp"

  ^String
  []

  (str "" (System/currentTimeMillis) "#" (NextInt)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- findAliases

  "Acts like a filter to get a set of aliases"

  [^KeyStore ks predicate]

  (loop [rc (transient [])
         en (.aliases ks) ]
    (if-some
      [n (when (.hasMoreElements en)
               (.nextElement en)) ]
      (if (predicate ks n)
          (recur (conj! rc n) en)
          (recur rc en))
      ;else
      (persistent! rc))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn GetPKey ""

  ^KeyStore$PrivateKeyEntry
  [^KeyStore ks ^String n ^chars pwd]

  (->> (KeyStore$PasswordProtection. pwd)
       (.getEntry ks n)
       (Cast? KeyStore$PrivateKeyEntry )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn GetCert ""

  ^KeyStore$TrustedCertificateEntry
  [^KeyStore ks ^String n ^chars pwd]

  (->> (.getEntry ks n nil)
       (Cast? KeyStore$TrustedCertificateEntry )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn CertAliases

  "Enumerate all cert aliases in the key-store"

  [^KeyStore keystore]

  (findAliases keystore
               #(.isCertificateEntry ^KeyStore %1 (str %2))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn PKeyAliases

  "Enumerate all key aliases in the key-store"

  [^KeyStore keystore]

  (findAliases keystore
               #(.isKeyEntry ^KeyStore %1 (str %2))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- regoCerts

  "Go through all private keys and from their cert chains,
   register each individual cert"

  [^KeyStore ks ^PasswordAPI pwdObj]

  (let [ca (some-> pwdObj (.toCharArray)) ]
    (doseq [^String a (PKeyAliases ks)
           :let [cs (-> ^KeyStore$PrivateKeyEntry
                        (GetPKey ks a ca)
                        (.getCertificateChain )) ]]
      (doseq [^Certificate c (seq cs)]
        (.setCertificateEntry ks (NewAlias) c)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn GetPkcsStore

  "Create a PKCS12 key-store"

  ^KeyStore
  [ & [^InputStream inp ^PasswordAPI pwdObj]]

  (let [^chars
        ca (some-> pwdObj
                   (.toCharArray ))
        ks (doto (KeyStore/getInstance "PKCS12" _BCProvider)
                 (.load inp ca)) ]
    (when (some? inp) (regoCerts ks pwdObj))
    ks))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn GetJksStore

  "Create a JKS key-store"

  ^KeyStore
  [ & [^InputStream inp ^PasswordAPI pwdObj] ]

  (let [pv (Security/getProvider "SUN")
        ^chars
        ca (some-> pwdObj
                   (.toCharArray ))
        ks (doto (KeyStore/getInstance "JKS" pv)
                 (.load inp ca)) ]
    (when (some? inp) (regoCerts ks pwdObj))
    ks))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmulti InitStore!

  "Initialize the key-store"

  (fn [_ b & more]
    (condp instance? b
      InputStream :stream
      File :file
      :bytes)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod InitStore! :stream

  ^KeyStore
  [^KeyStore store
   ^InputStream inp
   ^PasswordAPI pwdObj]

  (doto store
    (.load inp (some-> pwdObj
                       (.toCharArray )))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod InitStore! :bytes

  ^KeyStore
  [^KeyStore store
   ^bytes bits
   ^PasswordAPI pwdObj]

  (InitStore! store (Streamify bits) pwdObj))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod InitStore! :file

  ^KeyStore
  [^KeyStore store
   ^File f
   ^PasswordAPI pwdObj]

  (with-open
    [inp (FileInputStream. f) ]
    (InitStore! store inp pwdObj)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ConvCert

  "a KeyStore$TrustedCertificateEntry"

  ^KeyStore$TrustedCertificateEntry
  [^bytes bits]

  (let [ks (GetPkcsStore)
        nm (NewAlias)]
    (->> (-> (CertificateFactory/getInstance "X.509")
             (.generateCertificate (Streamify bits)))
         (.setCertificateEntry ks nm ))
    (.getEntry ks nm nil)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ConvPKey

  "a KeyStore$PrivateKeyEntry"

  ^KeyStore$PrivateKeyEntry
  [^bytes bits
   ^PasswordAPI pwdObj]

  (let [^chars
        ca (some-> pwdObj
                   (.toCharArray ))
        ks (GetPkcsStore) ]
    (.load ks (Streamify bits) ca)
    (.getEntry ks
               (str (first (PKeyAliases ks)))
               (KeyStore$PasswordProtection. ca))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn EasyPolicy*

  "Make a Policy that enables all permissions"

  ^Policy
  []

  (proxy [Policy] []
    (getPermissions [cs]
      (doto (Permissions.)
        (.add (AllPermission.))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn GenMac

  "Generate a Message Auth Code"

  ^String
  [^bytes skey ^String data & [algo] ]

  (let [^String algo (or algo DEF_MAC)
        mac (Mac/getInstance algo _BCProvider) ]
    (->> (SecretKeySpec. skey algo)
         (.init mac ))
    (->> (Bytesify data)
         (.update mac ))
    (Hex/encodeHexString (.doFinal mac))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn GenHash

  "Generate a Message Digest"

  ^String
  [^String data & [algo] ]

  (-> (->> (str (or algo SHA_512))
           (MessageDigest/getInstance ))
      (.digest (Bytesify data))
      (Base64/encodeBase64String )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn AsymKeyPair*

  "Make a Asymmetric key-pair"

  ^KeyPair
  [^String algo keylen]

  (log/debug "generating keypair for algo %s, length %s" algo keylen)
  (-> (doto (KeyPairGenerator/getInstance algo _BCProvider)
            (.initialize (int keylen) (NewRandom)))
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
       ks (doto (GetPkcsStore)
                (.load inp ca)) ]
      (GetPKey ks (.nextElement (.aliases ks)) ca))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- fmtPEM

  "Output as PEM"

  ^bytes
  [^String top ^String end ^bytes bits]

  (let [bs (Base64/encodeBase64 bits)
        nl (Bytesify "\n")
        baos (ByteOS)
        len (alength bs)
        bb (byte-array 1) ]
    (.write baos (Bytesify top))
    (loop [pos 0]
      (if (== pos len)
        (do
          (.write baos (Bytesify end))
          (.toByteArray baos))
        (do
          (when (and (> pos 0)
                     (== (mod pos 64) 0)) (.write baos nl))
          (aset bb 0 (aget bs pos))
          (.write baos bb)
          (recur (inc pos)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ExportPrivateKey

  "Export Private Key"

  ^bytes
  [^PrivateKey pkey fmt]

  {:pre [(keyword? fmt)]}

  (let [bits (.getEncoded pkey) ]
    (if (= fmt PEM_CERT)
      (fmtPEM "-----BEGIN RSA PRIVATE KEY-----\n"
              "\n-----END RSA PRIVATE KEY-----\n"
              bits)
      bits)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ExportPublicKey

  "Export Public Key"

  ^bytes
  [^PublicKey pkey fmt]

  {:pre [(keyword? fmt)]}

  (let [bits (.getEncoded pkey) ]
    (if (= fmt PEM_CERT)
      (fmtPEM "-----BEGIN RSA PUBLIC KEY-----\n"
              "\n-----END RSA PUBLIC KEY-----\n"
              bits)
      bits)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ExportCert

  "Export Certificate"

  ^bytes
  [^X509Certificate cert fmt]

  {:pre [(keyword? fmt)]}

  (let [bits (.getEncoded cert) ]
    (if (= fmt PEM_CERT)
      (fmtPEM "-----BEGIN CERTIFICATE-----\n"
              "-----END CERTIFICATE-----\n"
              bits)
      bits)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn CsrReQ*

  "Make a PKCS10 - csr-request"

  [keylen ^String dnStr fmt]

  {:pre [(keyword? fmt)]}

  (log/debug "csrreq: dnStr= %s, key-len= %s" dnStr keylen)
  (let [csb (JcaContentSignerBuilder. DEF_ALGO)
        kp (AsymKeyPair* RSA keylen)
        rbr (new JcaPKCS10CertificationRequestBuilder
                 (X500Principal. dnStr)
                 (.getPublic kp))
        k (.getPrivate kp)
        cs (-> (.setProvider csb _BCProvider)
               (.build k))
        bits (-> (.build rbr cs)
                 (.getEncoded)) ]
    [(if (= fmt PEM_CERT)
      (fmtPEM "-----BEGIN CERTIFICATE REQUEST-----\n"
              "\n-----END CERTIFICATE REQUEST-----\n"
              bits)
      bits)
     (ExportPrivateKey k fmt) ]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; generate self-signed cert
;; self signed-> issuer is self
(defn- mkSSV1Cert ""

  [^Provider pv ^KeyPair kp options]

  (let [^String dnStr (:dnStr options)
        ^String algo (:algo options)
        ^Date start (:start options)
        ^Date end (:end options)
        prv (.getPrivate kp)
        pub (.getPublic kp)
        bdr (new JcaX509v1CertificateBuilder
                 (X500Principal. dnStr)
                 (NextSerial)
                 start end (X500Principal. dnStr) pub)
        cs (-> (JcaContentSignerBuilder. algo)
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
        baos (ByteOS) ]
    (.setKeyEntry ks (juid) pkey ca (into-array Certificate [cert] ))
    (.store ks baos ca)
    (.toByteArray baos)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn Pkcs12*

  "Make a PKCS12 object from key and cert"

  [^bytes keyPEM
   ^bytes certPEM
   ^PasswordAPI pwdObj ^File out]

  (let [ct (.getTrustedCertificate (ConvCert certPEM))
        rdr (InputStreamReader. (Streamify keyPEM))
        ^chars ca (some-> pwdObj
                          (.toCharArray ))
        baos (ByteOS)
        ss (GetPkcsStore)
        ^KeyPair kp (.readObject (PEMParser. rdr)) ]
    (.setKeyEntry ss
                  (juid)
                  (.getPrivate kp)
                  ca (into-array Certificate [ct]))
    (.store ss baos ca)
    (WriteOneFile out (.toByteArray baos))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn SSv1PKCS12*

  "Make a SSV1 (root level) type PKCS12 object"

  [^String dnStr ^PasswordAPI pwdObj
   ^File out options]

  (let [dft {:keylen 1024 :start (Date.)
             :end (PlusMonths 12)
             :algo DEF_ALGO }
        opts (-> (merge dft options)
                 (assoc :dnStr dnStr))
        keylen (:keylen opts)
        ssv1 (mkSSV1 (GetPkcsStore)
                     (AsymKeyPair* RSA keylen)
                     pwdObj opts) ]
    (WriteOneFile out ssv1)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn SSv1JKS*

  "Make a SSV1 (root level) type JKS object"

  [^String dnStr ^PasswordAPI pwdObj
   ^File out options]

  (let [dft {:keylen 1024 :start (Date.)
             :end (PlusMonths 12)
             :algo "SHA1withDSA" }
        opts (-> (merge dft options)
                 (assoc :dnStr dnStr))
        keylen (:keylen opts)
        jks (mkSSV1 (GetJksStore)
                    (AsymKeyPair* DSA keylen)
                    pwdObj opts) ]
    (WriteOneFile out jks)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- mkSSV3Cert

  "Make a SSV3 server key"

  [^Provider pv ^KeyPair kp  issuerObjs options ]

  (let [subject (X500Principal. (str (:dnStr options)))
        ^X509Certificate issuer (first issuerObjs)
        ^PrivateKey issuerKey (last issuerObjs)
        exu (JcaX509ExtensionUtils.)
        bdr (new JcaX509v3CertificateBuilder
                 issuer
                 (NextSerial)
                 ^Date (:start options)
                 ^Date (:end options)
                 subject
                 (.getPublic kp))
        cs (-> (JcaContentSignerBuilder. (str (:algo options)))
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
        [^Certificate cert ^PrivateKey pkey]
        (mkSSV3Cert (.getProvider ks)
                    (AsymKeyPair* (.getAlgorithm issuerKey)
                                 (:keylen options))
                    [ (first issuerCerts) issuerKey ]
                    options)
        ^chars ca (some-> pwdObj
                    (.toCharArray ))
        baos (ByteOS)
        cs (cons cert issuerCerts) ]
    (.setKeyEntry ks (juid) pkey ca (into-array Certificate cs))
    (.store ks baos ca)
    (.toByteArray baos)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- make-ssv3XXX ""

  [^String dnStr ^PasswordAPI pwdObj
   ^File out options]

  (let [dft {:keylen 1024 :start (Date.)
             :end (PlusMonths 12) }
        hack (:hack options)
        issuerObjs [(:issuerCerts options)
                    (:issuerKey options) ]
        opts (-> (merge dft
                        {:algo (:algo hack) }
                        options)
                 (assoc :dnStr dnStr))
        ks (:ks hack)
        opts2 (-> opts
                  (dissoc hack)
                  (dissoc :issuerCerts)
                  (dissoc :issuerKey)) ]
    (WriteOneFile out (mkSSV3 ks pwdObj issuerObjs opts2))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn SSv3PKCS12*

  "Make a SSV3 type PKCS12 object"

  [^String dnStr ^PasswordAPI pwdObj
   ^File out options]

  (make-ssv3XXX dnStr
                pwdObj
                out
                (-> options (assoc :hack
                                   {:algo DEF_ALGO
                                    :ks (GetPkcsStore) } ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; JKS uses SUN and hence needs to use DSA
;;
(defn SSv3JKS*

  "Make a SSV3 JKS object"

  [^String dnStr ^PasswordAPI pwdObj
   ^File out options]

  (make-ssv3XXX dnStr
                pwdObj
                out
                (-> options
                    (assoc :hack
                           {:algo "SHA1withDSA"
                            :ks (GetJksStore) } ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ExportPkcs7

  "Extract and export PKCS7 info from a PKCS12 object"

  [^URL p12File ^PasswordAPI pwdObj
   ^File fileOut]

  (let [dummy (CMSProcessableByteArray. (Bytesify "?"))
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
    (WriteOneFile fileOut (-> (.generate gen dummy)
                              (.getEncoded)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn NewSession

  "Creates a new java-mail session"

  ^Session
  [ & [^String user ^PasswordAPI pwdObj] ]

  (Session/getInstance
    (System/getProperties)
    (when-not (empty? user)
      (DefaultAuthenticator. user (str pwdObj)) )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn NewMimeMsg

  "Create a new MIME Message"

  (^MimeMessage
    [^String user
     ^PasswordAPI pwdObj]
    (NewMimeMsg user pwdObj nil))

  (^MimeMessage
    [^InputStream inp]
    (NewMimeMsg "" nil inp))

  (^MimeMessage
    []
    (NewMimeMsg "" nil nil))

  (^MimeMessage
    [^String user
     ^PasswordAPI pwdObj
     ^InputStream inp]
    (let [s (NewSession user pwdObj) ]
      (if (nil? inp)
        (MimeMessage. s)
        (MimeMessage. s inp)))) )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn IsSigned?

  "Check if this stream-like object/message-part is signed"

  [^Object obj]

  (let [inp (mime/MaybeStream obj) ]
    (if (nil? inp)
      (if (instance? Multipart obj)
        (->> ^Multipart obj
             (.getContentType )
             (mime/IsSigned? ))
        (ThrowIOE (str "Invalid content: " (GetClassname obj))))
      (try
        (->> (NewMimeMsg "" "" inp)
             (.getContentType )
             (mime/IsSigned? ))
        (finally
          (ResetStream! inp))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn IsCompressed?

  "Check if this stream-like object/message-part is compressed"

  [^Object obj]

  (let [inp (mime/MaybeStream obj) ]
    (if (nil? inp)
      (condp instance? obj
        Multipart (->> ^Multipart obj
                       (.getContentType )
                       (mime/IsCompressed? ))

        BodyPart (->> ^BodyPart obj
                      (.getContentType )
                      (mime/IsCompressed? ))

        (ThrowIOE (str "Invalid content: " (GetClassname obj))))
      (try
        (->> (NewMimeMsg "" "" inp)
             (.getContentType )
             (mime/IsCompressed? ))
        (finally
          (ResetStream! inp))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn IsEncrypted?

  "Check if this stream-like object/message-part is encrypted"

  [^Object obj]

  (let [inp (mime/MaybeStream obj) ]
    (if (nil? inp)
      (condp instance? obj
        Multipart (->> ^Multipart obj
                       (.getContentType )
                       (mime/IsEncrypted? ))

        BodyPart (->> ^BodyPart obj
                      (.getContentType )
                      (mime/IsEncrypted? ))

        (ThrowIOE (str "Invalid content: " (GetClassname obj))))
      (try
        (->> (NewMimeMsg "" "" inp)
             (.getContentType )
             (mime/IsEncrypted? ))
        (finally
          (ResetStream! inp))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn GetCharset

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
    (let [cs (GetCharset cType) ]
      (str (if (hgl? cs) cs (MimeUtility/javaCharset dft))))) )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- makeSignerGentor

  "Create a SignedGenerator"

  ^SMIMESignedGenerator
  [^PrivateKey pkey
   certs  ;; list of certs
   ^String algo]

  (let [gen (SMIMESignedGenerator. "base64")
        lst (vec certs)
        caps (doto (SMIMECapabilityVector.)
                   (.addCapability SMIMECapability/dES_EDE3_CBC)
                   (.addCapability SMIMECapability/rC2_CBC, 128)
                   (.addCapability SMIMECapability/dES_CBC) )
        signedAttrs (doto (ASN1EncodableVector.)
                      (.add (SMIMECapabilitiesAttribute. caps)))
        ^X509Certificate subj (first lst)
        ^X509Certificate issuer (if (> (count lst) 1)
                                  (nth lst 1)
                                  subj)
        issuerDN (.getSubjectX500Principal issuer)
         ;;
         ;; add an encryption key preference for encrypted responses -
         ;; normally this would be different from the signing certificate...
         ;;
        issAndSer (new IssuerAndSerialNumber
                       (X500Name/getInstance (.getEncoded issuerDN))
                       (.getSerialNumber subj))
        dm1 (.add signedAttrs (SMIMEEncryptionKeyPreferenceAttribute. issAndSer))
        bdr (doto (new JcaSignerInfoGeneratorBuilder
                       (-> (JcaDigestCalculatorProviderBuilder.)
                           (.setProvider _BCProvider)
                           (.build)))
                  (.setDirectSignature true))
        cs (-> (JcaContentSignerBuilder. (str algo))
               (.setProvider _BCProvider)
               (.build pkey)) ]
    (-> bdr
        (.setSignedAttributeGenerator
          (new DefaultSignedAttributeTableGenerator
               (AttributeTable. signedAttrs))))
    (.addSignerInfoGenerator gen (.build bdr cs subj))
    (.addCertificates gen (JcaCertStore. lst))
    gen))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmulti SmimeDigSig

  "Generates a MimeMultipart"

  (fn [a b c d]
    (condp instance? d
      MimeMessage :mimemessage
      Multipart :multipart
      BodyPart :bodypart
      (ThrowBadArg "wrong type"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod SmimeDigSig :mimemessage

  [^PrivateKey pkey
   certs ;; list of certs
   ^String algo
   ^MimeMessage mmsg]

  (let [g (makeSignerGentor pkey certs algo) ]
    ;; force internal processing, just in case
    (.getContent mmsg)
    (.generate g mmsg)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod SmimeDigSig :multipart

  [^PrivateKey pkey
   certs  ;; list of certs
   ^String algo
   ^Multipart mp]

  (let [g (makeSignerGentor pkey certs algo)
        mm (NewMimeMsg) ]
    (.setContent mm mp)
    (.generate g mm)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod SmimeDigSig :bodypart

  [^PrivateKey pkey
   certs  ;; list of certs
   ^String algo
   ^BodyPart bp]

  (-> (makeSignerGentor pkey certs algo)
      (.generate ^MimeBodyPart bp )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- smimeDec

  "SMIME decryption"

  ^CMSTypedStream
  [^PrivateKey pkey ^SMIMEEnveloped env]

  (loop [rec (-> (JceKeyTransEnvelopedRecipient. pkey)
                 (.setProvider _BCProvider))
         it (-> (.getRecipientInfos env)
                (.getRecipients)
                (.iterator))
         rc nil ]
    (if (or (some? rc)
            (not (.hasNext it)))
      rc
      (recur rec it
             (-> ^RecipientInformation (.next it)
                 (.getContentStream rec))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmulti SmimeDecrypt

  "SMIME decrypt this object"

  (fn [a b]
    (condp instance? b
      MimeMessage :mimemsg
      BodyPart :bodypart
      (ThrowBadArg "wrong type"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- smimeLoopDec ""

  ^bytes
  [pkeys ^SMIMEEnveloped ev]

  (let [rc (some #(if-some [cms (smimeDec ^PrivateKey %1 ev) ]
                     (IOUtils/toByteArray (.getContentStream cms))
                     nil)
                 pkeys) ]
    (when (nil? rc)
      (trap! GeneralSecurityException "No matching decryption key"))
    rc))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod SmimeDecrypt :mimemsg

  ^bytes
  [pkeys ^MimeMessage mimemsg]

  (smimeLoopDec pkeys (SMIMEEnveloped. mimemsg)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod SmimeDecrypt :bodypart

  ^bytes
  [pkeys ^BodyPart part]

  (->> ^MimeBodyPart part
       (SMIMEEnveloped. )
       (smimeLoopDec pkeys )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn PeekSmimeSignedContent

  "Get the content ignoring the signing stuff"

  ^Object
  [^Multipart mp]

  (some-> (new SMIMESignedParser
               (BcDigestCalculatorProvider.)
               ^MimeMultipart mp
               (GetCharset (.getContentType mp) "binary"))
          (.getContent)
          (.getContent)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn TestSmimeDigSig

  "Verify the signature and return content if ok"

  [^Multipart mp certs & [^String cte] ]

  (let
    [sc (if (hgl? cte)
          (SMIMESigned. ^MimeMultipart mp cte)
          (SMIMESigned. ^MimeMultipart mp))
     sns (-> (.getSignerInfos sc)
             (.getSigners) )
     s (JcaCertStore. (vec certs))
     rc (some
          (fn [^SignerInformation si]
            (loop
              [c (.getMatches s (.getSID si))
               it (.iterator c)
               ret nil
               stop false]
              (if (or stop (not (.hasNext it)))
                ret
                (let
                  [ci (-> (JcaSimpleSignerInfoVerifierBuilder.)
                          (.setProvider _BCProvider)
                          (.build ^X509CertificateHolder (.next it))) ]
                  (if (.verify si ci)
                    (if-some [digest (.getContentDigest si) ]
                      (recur c it [sc digest] true)
                      (recur c it nil false))
                    (recur c it nil false))))))
          (seq sns)) ]
    (when (nil? rc)
      (trap! GeneralSecurityException "Verify signature: no matching cert"))

    [(some-> sc
             (.getContentAsMimeMessage (NewSession))
             (.getContent))
     (nth rc 1) ] ))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmulti SmimeDecompress

  "Inflate the compressed content"

  (fn [a]
    (condp instance? a
      InputStream :stream
      BodyPart :bodypart
      (ThrowBadArg "wrong type"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod SmimeDecompress :bodypart

  ^XData
  [^BodyPart bp]

  (if (nil? bp)
    (XData.)
    (SmimeDecompress (.getInputStream bp))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod SmimeDecompress :stream

  ^XData
  [^InputStream inp]

  (if (nil? inp)
    (XData.)
    (let [cms (-> (CMSCompressedDataParser. inp)
                  (.getContent (ZlibExpanderProvider.))) ]
      (when (nil? cms)
        (trap! GeneralSecurityException
               "Decompress stream: corrupted content"))
      (->> (.getContentStream cms)
           (IOUtils/toByteArray )
           (XData. )))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmulti SmimeEncrypt

  "Generates a MimeBodyPart"

  (fn [a b c]
    (condp instance? c
      MimeMessage :mimemsg
      Multipart :multipart
      BodyPart :bodypart
      (ThrowBadArg "wrong type"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod SmimeEncrypt :bodypart

  ^MimeBodyPart
  [^Certificate cert ^String algo ^BodyPart bp]

  (let [gen (SMIMEEnvelopedGenerator.) ]
    (.addRecipientInfoGenerator
      gen
      (-> ^X509Certificate cert
          (JceKeyTransRecipientInfoGenerator. )
          (.setProvider _BCProvider)))
    (.generate
      gen
      ^MimeBodyPart
      bp (-> (JceCMSContentEncryptorBuilder. algo)
             (.setProvider _BCProvider)
             (.build)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod SmimeEncrypt :mimemsg

  ^MimeBodyPart
  [^Certificate cert ^String algo ^MimeMessage msg]

  (let [gen (SMIMEEnvelopedGenerator.) ]
    ;; force message to be processed, just in case.
    (.getContent msg)
    (.addRecipientInfoGenerator
      gen
      (-> ^X509Certificate cert
          (JceKeyTransRecipientInfoGenerator. )
          (.setProvider _BCProvider)))
    (.generate
      gen
      msg
      (-> (JceCMSContentEncryptorBuilder. algo)
          (.setProvider _BCProvider)
          (.build)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod SmimeEncrypt :multipart

  ^MimeBodyPart
  [^Certificate cert ^String algo ^Multipart mp]

  (let [gen (SMIMEEnvelopedGenerator.) ]
    (.addRecipientInfoGenerator
      gen
      (-> ^X509Certificate cert
          (JceKeyTransRecipientInfoGenerator. )
          (.setProvider _BCProvider)))
    (.generate
      gen
      (doto (NewMimeMsg)(.setContent mp))
      (-> (JceCMSContentEncryptorBuilder. algo)
          (.setProvider _BCProvider)
          (.build)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn SmimeCompress

  "Generates a MimeBodyPart"

  (^MimeBodyPart
    [^String cType ^XData xs]
    (let [ds (if (.isDiskFile xs)
               (SDataSource. (.fileRef xs) cType)
               (SDataSource. (.javaBytes xs) cType))
          bp (MimeBodyPart.) ]
      (.setDataHandler bp (DataHandler. ds))
      (.generate (SMIMECompressedGenerator.) bp (ZlibCompressor.))))

  (^MimeBodyPart
    [^MimeMessage msg]
    (.getContent msg) ;; make sure it's processed, just in case
    (-> (SMIMECompressedGenerator.)
        (.generate msg (ZlibCompressor.))))

  (^MimeBodyPart
    [^String cType ^String contentLoc
     ^String cid ^XData xs]
    (let [ds (if (.isDiskFile xs)
               (SDataSource. (.fileRef xs) cType)
               (SDataSource. (.javaBytes xs) cType))
          bp (MimeBodyPart.) ]
      (when (hgl? contentLoc)
        (.setHeader bp "content-location" contentLoc))
      (when (hgl? cid)
        (.setHeader bp "content-id" cid))
      (.setDataHandler bp (DataHandler. ds))
      (let [zbp (.generate (SMIMECompressedGenerator.) bp (ZlibCompressor.))
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
;;
(defn PkcsDigSig

  "SMIME sign some data"

  ^bytes
  [^PrivateKey pkey certs ^String algo ^XData xs]

  (let [bdr (new JcaSignerInfoGeneratorBuilder
                 (-> (JcaDigestCalculatorProviderBuilder.)
                     (.setProvider _BCProvider)
                     (.build)))
        cs (-> (JcaContentSignerBuilder. (str algo))
               (.setProvider _BCProvider)
               (.build pkey))
        gen (CMSSignedDataGenerator.)
        cl (vec certs)
        cert (first cl) ]
    (.setDirectSignature bdr true)
    (.addSignerInfoGenerator gen (.build bdr cs ^X509Certificate cert))
    (.addCertificates gen (JcaCertStore. cl))
    (-> (.generate gen
                   (if (.isDiskFile xs)
                     (CMSProcessableFile. (.fileRef xs))
                     (CMSProcessableByteArray. (.javaBytes xs)))
                   false)
        (.getEncoded))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn TestPkcsDigSig

  "Verify the signed object with the signature"

  ^bytes
  [^Certificate cert ^XData xdata ^bytes signature]

  (let [cproc (if (.isDiskFile xdata)
                (CMSProcessableFile. (.fileRef xdata))
                (CMSProcessableByteArray. (.javaBytes xdata)))
        cms (CMSSignedData. ^CMSProcessable cproc signature)
        s (JcaCertStore. [cert])
        sls (-> cms (.getSignerInfos) (.getSigners))
        rc (some
             (fn [^SignerInformation si]
               (loop
                 [c (.getMatches s (.getSID si))
                  it (.iterator c)
                  digest nil
                  stop false ]
                 (if (or stop (not (.hasNext it)))
                   digest
                   (let
                     [bdr (-> (JcaSimpleSignerInfoVerifierBuilder.)
                              (.setProvider _BCProvider))
                      ok (->> ^X509CertificateHolder (.next it)
                              (.build bdr )
                              (.verify si ))
                      dg (when ok (.getContentDigest si)) ]
                     (if (nil? dg)
                       (recur c it nil false)
                       (recur c it dg true))))))
             (seq sls)) ]
    (when (nil? rc)
      (trap! GeneralSecurityException
             "Decode signature: no matching cert"))
    rc))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- str-signingAlgo ""

  [algo]

  (condp = algo
    "SHA-512" SMIMESignedGenerator/DIGEST_SHA512
    "SHA-1" SMIMESignedGenerator/DIGEST_SHA1
    "MD5" SMIMESignedGenerator/DIGEST_MD5
    (ThrowBadArg (str "Unsupported signing algo: " algo))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- finger-print ""

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
(defn FingerprintSHA1

  "Generate a fingerprint using SHA-1"

  ^String
  [^bytes data]

  (finger-print data SHA_1))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn FingerprintMD5

  "Generate a fingerprint using MD5"

  ^String
  [^bytes data]

  (finger-print data MD_5))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn CertDesc* ""

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
(defn DescCertificate

  "Get some basic info from Certificate"

  ^CertDesc
  [^X509Certificate x509]

  (if (nil? x509)
    (CertDesc* nil nil nil nil)
    (CertDesc* (.getSubjectX500Principal x509)
               (.getIssuerX500Principal x509)
               (.getNotBefore x509)
               (.getNotAfter x509))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn DescCert

  "a object"

  (^CertDesc
    [^bytes privateKeyBits ^PasswordAPI pwdObj]
    (if-some [pkey (ConvPKey privateKeyBits pwdObj) ]
      (DescCertificate (.getCertificate pkey))
      (CertDesc* nil nil nil nil)))

  (^CertDesc
    [^bytes certBits]
    (if-some [cert (ConvCert certBits) ]
      (DescCertificate (.getTrustedCertificate cert))
      (CertDesc* nil nil nil nil))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ValidCertificate?

  "Validate this Certificate"

  [^X509Certificate x509]

  (try
    (.checkValidity x509 (Date.))
    (catch Throwable e# false)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ValidPKey?

  "Validate this Private Key"

  [^bytes keyBits ^PasswordAPI pwdObj]

  (if-some [pkey (ConvPKey keyBits pwdObj) ]
    (ValidCertificate? (.getCertificate pkey))
    false))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ValidCert?

  "Validate this Certificate"

  [^bytes certBits]

  (if-some [cert (ConvCert certBits) ]
    (ValidCertificate? (.getTrustedCertificate cert))
    false))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn IntoArrayCerts

  "From a list of TrustedCertificateEntry(s)"

  [certs]

  (if (empty? certs)
    []
    (map #(.getTrustedCertificate ^KeyStore$TrustedCertificateEntry %1)
         (seq certs))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn IntoArrayPKeys

  "From a list of PrivateKeyEntry(s)"

  [pkeys]

  (if (empty? pkeys)
    []
    (map #(.getPrivateKey ^KeyStore$PrivateKeyEntry %1)
         (seq pkeys))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn SimpleTrustMgr* ""

  ^X509TrustManager
  []

  (nth (SSLTrustMgrFactory/getTrustManagers) 0))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF

