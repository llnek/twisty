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
     :refer [nextInt throwIOE throwBadArg
             newRandom bytesify tryc try!
             trap! cast? juid getClassname]])

  (:import
    [org.bouncycastle.pkcs.jcajce JcaPKCS10CertificationRequestBuilder]
    [org.bouncycastle.operator OperatorCreationException ContentSigner]
    [org.bouncycastle.operator DigestCalculatorProvider ContentSigner]
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
(defn assertJce

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
        (.doFinal (bytesify "This is just an example")))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(def ^:private ^Provider _BCProvider (BouncyCastleProvider.))
(Security/addProvider _BCProvider)
(assertJce)

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
(defn pkcsFile?

  "true if url points to a PKCS12 key file"

  [^URL keyUrl]

  (not (-> (.getFile keyUrl)
           (lcase)
           (.endsWith ".jks"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn msgDigest

  "Get a message digest instance"

  ^MessageDigest
  [algo]

  (MessageDigest/getInstance (name algo) _BCProvider))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn nextSerial

  "Get a random Big Integer"

  ^BigInteger
  []

  (BigInteger/valueOf (Math/abs (->> (Date.)
                                     (.getTime)
                                     (Random. )
                                     (.nextLong)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn dbgProvider

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
(defn newAlias

  "Generate a new name based on system timestamp"

  ^String
  []

  (str "" (System/currentTimeMillis) "#" (nextInt)))

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
(defn getPKey ""

  ^KeyStore$PrivateKeyEntry
  [^KeyStore ks ^String n ^chars pwd]

  (->> (KeyStore$PasswordProtection. pwd)
       (.getEntry ks n)
       (cast? KeyStore$PrivateKeyEntry )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn getCert ""

  ^KeyStore$TrustedCertificateEntry
  [^KeyStore ks ^String n ^chars pwd]

  (->> (.getEntry ks n nil)
       (cast? KeyStore$TrustedCertificateEntry )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn certAliases

  "Enumerate all cert aliases in the key-store"

  [^KeyStore keystore]

  (findAliases keystore
               #(.isCertificateEntry ^KeyStore %1 (str %2))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn pkeyAliases

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
(defn getJksStore

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
(defmulti initStore!

  "Initialize the key-store"

  (fn [_ b & more]
    (condp instance? b
      InputStream :stream
      File :file
      :bytes)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod initStore! :stream

  ^KeyStore
  [^KeyStore ks ^InputStream inp ^PasswordAPI pwdObj]

  (doto ks
    (.load inp (some-> pwdObj
                       (.toCharArray )))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod initStore! :bytes

  ^KeyStore
  [^KeyStore ks ^bytes bits ^PasswordAPI pwdObj]

  (initStore! ks (streamify bits) pwdObj))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod initStore! :file

  ^KeyStore
  [^KeyStore ks ^File f ^PasswordAPI pwdObj]

  (with-open
    [inp (FileInputStream. f) ]
    (initStore! ks inp pwdObj)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn convCert

  "a KeyStore$TrustedCertificateEntry"

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

  "a KeyStore$PrivateKeyEntry"

  ^KeyStore$PrivateKeyEntry
  [^bytes bits
   ^PasswordAPI pwdObj]

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
  [^bytes skey ^String data & [algo] ]

  (let [^String algo (or algo DEF_MAC)
        mac (Mac/getInstance algo _BCProvider) ]
    (->> (SecretKeySpec. skey algo)
         (.init mac ))
    (->> (bytesify data)
         (.update mac ))
    (Hex/encodeHexString (.doFinal mac))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn genHash

  "Generate a Message Digest"

  ^String
  [^String data & [algo] ]

  (-> (->> (str (or algo SHA_512))
           (MessageDigest/getInstance ))
      (.digest (bytesify data))
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
    (if (= fmt PEM_CERT)
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
    (if (= fmt PEM_CERT)
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
    (if (= fmt PEM_CERT)
      (fmtPEM "-----BEGIN CERTIFICATE-----\n"
              "-----END CERTIFICATE-----\n"
              bits)
      bits)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn csrReQ

  "Make a PKCS10 - csr-request"

  [keylen ^String dnStr fmt]

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
    [(if (= fmt PEM_CERT)
      (fmtPEM "-----BEGIN CERTIFICATE REQUEST-----\n"
              "\n-----END CERTIFICATE REQUEST-----\n"
              bits)
      bits)
     (exportPrivateKey k fmt) ]))

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
                 (nextSerial)
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
        baos (byteOS) ]
    (.setKeyEntry ks (juid) pkey ca (into-array Certificate [cert] ))
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
                  ca (into-array Certificate [ct]))
    (.store ss baos ca)
    (writeOneFile out (.toByteArray baos))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ssv1PKCS12

  "Make a SSV1 (root level) type PKCS12 object"

  [^String dnStr ^PasswordAPI pwdObj
   ^File out options]

  (let [dft {:keylen 1024 :start (Date.)
             :end (plusMonths 12)
             :algo DEF_ALGO }
        opts (-> (merge dft options)
                 (assoc :dnStr dnStr))
        keylen (:keylen opts)
        ssv1 (mkSSV1 (getPkcsStore)
                     (asymKeyPair RSA keylen)
                     pwdObj opts)]
    (writeOneFile out ssv1)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ssv1JKS

  "Make a SSV1 (root level) type JKS object"

  [^String dnStr ^PasswordAPI pwdObj
   ^File out options]

  (let [dft {:keylen 1024 :start (Date.)
             :end (plusMonths 12)
             :algo "SHA1withDSA" }
        opts (-> (merge dft options)
                 (assoc :dnStr dnStr))
        keylen (:keylen opts)
        jks (mkSSV1 (getJksStore)
                    (asymKeyPair DSA keylen)
                    pwdObj opts) ]
    (writeOneFile out jks)))

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
                 (nextSerial)
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
                    (asymKeyPair (.getAlgorithm issuerKey)
                                 (:keylen options))
                    [ (first issuerCerts) issuerKey ]
                    options)
        ^chars ca (some-> pwdObj
                    (.toCharArray ))
        baos (byteOS)
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
             :end (plusMonths 12) }
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
    (writeOneFile out (mkSSV3 ks pwdObj issuerObjs opts2))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ssv3PKCS12

  "Make a SSV3 type PKCS12 object"

  [^String dnStr ^PasswordAPI pwdObj
   ^File out options]

  (make-ssv3XXX dnStr
                pwdObj
                out
                (-> options (assoc :hack
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

  (let [dummy (CMSProcessableByteArray. (bytesify "?"))
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
    (when-not (empty? user)
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

  (let [inp (mime/maybeStream obj) ]
    (if (nil? inp)
      (if (instance? Multipart obj)
        (->> ^Multipart obj
             (.getContentType )
             (mime/isSigned? ))
        (throwIOE (str "Invalid content: " (getClassname obj))))
      (try
        (->> (newMimeMsg "" "" inp)
             (.getContentType )
             (mime/isSigned? ))
        (finally
          (resetStream! inp))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn isCompressed?

  "Check if this stream-like object/message-part is compressed"

  [^Object obj]

  (let [inp (mime/maybeStream obj) ]
    (if (nil? inp)
      (condp instance? obj
        Multipart (->> ^Multipart obj
                       (.getContentType )
                       (mime/isCompressed? ))

        BodyPart (->> ^BodyPart obj
                      (.getContentType )
                      (mime/isCompressed? ))

        (throwIOE (str "Invalid content: " (getClassname obj))))
      (try
        (->> (newMimeMsg "" "" inp)
             (.getContentType )
             (mime/isCompressed? ))
        (finally
          (resetStream! inp))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn isEncrypted?

  "Check if this stream-like object/message-part is encrypted"

  [^Object obj]

  (let [inp (mime/maybeStream obj) ]
    (if (nil? inp)
      (condp instance? obj
        Multipart (->> ^Multipart obj
                       (.getContentType )
                       (mime/isEncrypted? ))

        BodyPart (->> ^BodyPart obj
                      (.getContentType )
                      (mime/isEncrypted? ))

        (throwIOE (str "Invalid content: " (getClassname obj))))
      (try
        (->> (newMimeMsg "" "" inp)
             (.getContentType )
             (mime/isEncrypted? ))
        (finally
          (resetStream! inp))))))

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
(defmulti smimeDigSig

  "Generates a MimeMultipart"

  (fn [a b c d]
    (condp instance? d
      MimeMessage :mimemessage
      Multipart :multipart
      BodyPart :bodypart
      (throwBadArg "wrong type"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeDigSig :mimemessage

  [^PrivateKey pkey
   certs
   ^String algo
   ^MimeMessage mmsg]

  (let [g (makeSignerGentor pkey certs algo) ]
    ;; force internal processing, just in case
    (.getContent mmsg)
    (.generate g mmsg)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeDigSig :multipart

  [^PrivateKey pkey
   certs
   ^String algo
   ^Multipart mp]

  (let [g (makeSignerGentor pkey certs algo)
        mm (newMimeMsg) ]
    (.setContent mm mp)
    (.generate g mm)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeDigSig :bodypart

  [^PrivateKey pkey
   certs
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
         rc nil]
    (if (or (some? rc)
            (not (.hasNext it)))
      rc
      (recur rec it
             (-> ^RecipientInformation (.next it)
                 (.getContentStream rec))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmulti smimeDecrypt

  "SMIME decrypt this object"

  (fn [a b]
    (condp instance? b
      MimeMessage :mimemsg
      BodyPart :bodypart
      (throwBadArg "wrong type"))))

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
(defmethod smimeDecrypt :mimemsg

  ^bytes
  [pkeys ^MimeMessage mimemsg]

  (smimeLoopDec pkeys (SMIMEEnveloped. mimemsg)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeDecrypt :bodypart

  ^bytes
  [pkeys ^BodyPart part]

  (->> ^MimeBodyPart part
       (SMIMEEnveloped. )
       (smimeLoopDec pkeys )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn peekSmimeSignedContent

  "Get the content ignoring the signing stuff"

  ^Object
  [^Multipart mp]

  (some-> (new SMIMESignedParser
               (BcDigestCalculatorProvider.)
               ^MimeMultipart mp
               (getCharset (.getContentType mp) "binary"))
          (.getContent)
          (.getContent)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn testSmimeDigSig

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
             (.getContentAsMimeMessage (newSession))
             (.getContent))
     (nth rc 1) ] ))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmulti smimeDecompress

  "Inflate the compressed content"

  (fn [a]
    (condp instance? a
      InputStream :stream
      BodyPart :bodypart
      (throwBadArg "wrong type"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeDecompress :bodypart

  ^XData
  [^BodyPart bp]

  (if (nil? bp)
    (XData.)
    (smimeDecompress (.getInputStream bp))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeDecompress :stream

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
(defmulti smimeEncrypt

  "Generates a MimeBodyPart"

  (fn [a b c]
    (condp instance? c
      MimeMessage :mimemsg
      Multipart :multipart
      BodyPart :bodypart
      (throwBadArg "wrong type"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod smimeEncrypt :bodypart

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
(defmethod smimeEncrypt :mimemsg

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
(defmethod smimeEncrypt :multipart

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
      (doto (newMimeMsg)(.setContent mp))
      (-> (JceCMSContentEncryptorBuilder. algo)
          (.setProvider _BCProvider)
          (.build)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn smimeCompress

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
(defn pkcsDigSig

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
(defn testPkcsDigSig

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
    (throwBadArg (str "Unsupported signing algo: " algo))))

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
(defn fingerprintSHA1

  "Generate a fingerprint using SHA-1"

  ^String
  [^bytes data]

  (finger-print data SHA_1))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn fingerprintMD5

  "Generate a fingerprint using MD5"

  ^String
  [^bytes data]

  (finger-print data MD_5))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn certDesc ""

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

  "a object"

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

  (try
    (.checkValidity x509 (Date.))
    (catch Throwable e# false)))

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
(defn intoArrayCerts

  "From a list of TrustedCertificateEntry(s)"

  [certs]

  (if (empty? certs)
    []
    (map #(.getTrustedCertificate ^KeyStore$TrustedCertificateEntry %1)
         (seq certs))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn intoArrayPKeys

  "From a list of PrivateKeyEntry(s)"

  [pkeys]

  (if (empty? pkeys)
    []
    (map #(.getPrivateKey ^KeyStore$PrivateKeyEntry %1)
         (seq pkeys))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn simpleTrustMgr ""

  ^X509TrustManager
  []

  (nth (SSLTrustMgrFactory/getTrustManagers) 0))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF

