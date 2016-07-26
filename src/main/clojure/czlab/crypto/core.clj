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

(ns ^{:doc "Crypto functions."
      :author "Kenneth Leung" }

  czlab.crypto.core

  (:require
    [czlab.xlib.files :refer [writeFile]]
    [czlab.xlib.dates :refer [+months]]
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
    [org.bouncycastle.pkcs.bc
     BcPKCS12PBEInputDecryptorProviderBuilder]
    [org.bouncycastle.operator OperatorCreationException ContentSigner]
    [org.bouncycastle.operator DigestCalculatorProvider ContentSigner]
    [org.bouncycastle.asn1.cms AttributeTable IssuerAndSerialNumber]
    [javax.activation DataHandler CommandMap MailcapCommandMap]
    [javax.mail BodyPart MessagingException Multipart Session]
    [org.bouncycastle.pkcs PKCS8EncryptedPrivateKeyInfo]
    [org.bouncycastle.util.encoders Hex Base64]
    [org.bouncycastle.openssl
     X509TrustedCertificateBlock
     PEMKeyPair
     PEMEncryptedKeyPair]
    [clojure.lang
     APersistentVector]
    [java.io
     StringWriter
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
    [org.bouncycastle.asn1.cms ContentInfo]
    [org.bouncycastle.asn1.pkcs PrivateKeyInfo]
    [org.bouncycastle.asn1.x509
     X509Extension
     SubjectPublicKeyInfo]
    [org.bouncycastle.cert
     X509CRLHolder
     X509CertificateHolder
     X509AttributeCertificateHolder]
    [org.bouncycastle.cms CMSAlgorithm]
    [org.bouncycastle.openssl.jcajce
     JcePEMDecryptorProviderBuilder
     JcePEMEncryptorBuilder
     JcaMiscPEMGenerator
     JcaPEMKeyConverter]
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
    [org.bouncycastle.openssl
     PEMWriter
     PEMParser
     PEMEncryptor]
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
    [czlab.crypto
     PasswordAPI
     PKeyGist
     CertGist
     SSLTrustMgrFactory]
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

(def ^:private ENC_ALGOS
  #{"AES-128-CBC" "AES-128-CFB" "AES-128-ECB" "AES-128-OFB"
    "AES-192-CBC" "AES-192-CFB" "AES-192-ECB" "AES-192-OFB"
    "AES-256-CBC" "AES-256-CFB" "AES-256-ECB" "AES-256-OFB"
    "BF-CBC" "BF-CFB" "BF-ECB" "BF-OFB"
    "DES-CBC" "DES-CFB" "DES-ECB" "DES-OFB"
    "DES-EDE" "DES-EDE-CBC" "DES-EDE-CFB" "DES-EDE-ECB"
    "DES-EDE-OFB" "DES-EDE3" "DES-EDE3-CBC" "DES-EDE3-CFB"
    "DES-EDE3-ECB" "DES-EDE3-OFB"
    "RC2-CBC" "RC2-CFB" "RC2-ECB" "RC2-OFB"
    "RC2-40-CBC" "RC2-64-CBC" })

(def ^String SHA512 "SHA512withRSA")
(def ^String SHA256 "SHA256withRSA")
(def ^String MD5 "MD5withRSA")
(def ^String BFISH "BlowFish")

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
(def ^Provider _BC_ (BouncyCastleProvider.))
(Security/addProvider _BC_)
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
(defn- toXCert

  ""
  ^X509Certificate
  [^X509CertificateHolder h]

  (-> (JcaX509CertificateConverter.)
      (.setProvider _BC_)
      (.getCertificate h)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- pemencr<>

  ""
  ^PEMEncryptor
  [^chars pwd]

  (when (some? pwd)
    (-> (rand-nth ENC_ALGOS)
        (JcePEMEncryptorBuilder. )
        (.setProvider _BC_)
        (.setSecureRandom (srandom<>))
        (.build pwd))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn jksFile?

  "true if url points to a JKS key file"
  [^URL keyUrl]

  (-> (.getFile keyUrl)
      lcase
      (.endsWith ".jks")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn msgDigest

  "Get a message digest instance:
  MD5
  SHA-1, SHA-256, SHA-384, SHA-512"
  ^MessageDigest
  [^String algo]

  (MessageDigest/getInstance algo _BC_))

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

  (try! (.list _BC_ os)))

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
(defn pkeyGist<>

  "Get a private key from the store"
  ^PKeyGist
  [^KeyStore store ^String n ^chars pwd]

  (when-some
    [e
     (->> (KeyStore$PasswordProtection. pwd)
          (.getEntry store n)
          (cast? KeyStore$PrivateKeyEntry ))]
    (reify PKeyGist
      (chain [_] (.getCertificateChain e))
      (cert [_] (.getCertificate e))
      (pkey [_] (.getPrivateKey e)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn tcert

  "Get a certificate from store"
  ^Certificate
  [^KeyStore store ^String n]

  (when-some
    [^KeyStore$TrustedCertificateEntry
     e (->> (.getEntry store n nil)
            (cast? KeyStore$TrustedCertificateEntry ))]
    (.getTrustedCertificate e)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn filterEntries

  "Enumerate entries in the key-store"
  ^APersistentVector
  [^KeyStore store entryType]
  {:pre [(keyword? entryType)]}

  (loop [en (.aliases store)
         rc (transient [])]
    (if-not (.hasMoreElements en)
      (persistent! rc)
      (let [n (.nextElement en)]
        (if
          (cond
            (= :certs entryType)
            (.isCertificateEntry store n)
            (= :keys entryType)
            (.isKeyEntry store n)
            :else false)
          (recur en (conj! rc n))
          (recur en rc))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn pkcsStore<>

  "Create a PKCS12 key-store"
  ^KeyStore
  [& [^InputStream inp ^chars pwd2]]

  (let [ks (KeyStore/getInstance "PKCS12" _BC_)]
    (when (some? inp)
      (.load ks inp pwd2))
    ks))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn jksStore<>

  "Create a JKS key-store"
  ^KeyStore
  [& [^InputStream inp ^chars pwd2]]

  (let [ks (->> (Security/getProvider "SUN")
                (KeyStore/getInstance "JKS" ))]
    (when (some? inp)
      (.load inp pwd2))
    ks))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn initStore!

  "Initialize the key-store"
  ^KeyStore
  [^KeyStore store arg ^chars pwd2]

  (let
    [[b ^InputStream inp]
     (condp = (class arg)
       (bytesClass) [true (streamify arg)]
       InputStream [false arg]
       File [true (FileInputStream. arg)]
       (throwBadArg "Bad type"))]
    (try
      (.load store inp pwd2)
      (finally
        (if b (.close inp))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn convCert

  "Convert to a Certificate"
  ^Certificate
  [arg]

  (let
    [^InputStream
     inp (condp (class arg)
           (bytesClass) (streamify arg)
           InputStream arg
           (throwBadArg "Bad type"))]
    (-> (CertificateFactory/getInstance "X.509")
        (.generateCertificate inp))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn convPKey

  "Convert to a Private Key"
  ^PKeyGist
  [arg ^chars pwd & [^chars pwd2]]

  (let
    [^InputStream
     inp (condp = (class arg)
           (bytesClass) (streamify arg)
           InputStream arg
           (throwBadArg "Bad type"))
     ks (doto (pkcsStore<>)
          (.load inp pwd2))
     n (first (filterEntries ks :keys))]
    (when (hgl? n)
      (pkeyGist ks n pwd))))

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
  [^bytes skey data & [algo] ]
  {:pre [(some? skey)
         (some? data)]}

  (let
    [^String algo (stror algo DEF_MAC)
     mac (Mac/getInstance algo _BC_)
     ^bytes
     bits (condp = (class data)
            InputStream (toBytes data)
            (bytesClass) data
            (throwBadArg "Bad type"))]
    (->> (SecretKeySpec. skey algo)
         (.init mac ))
    (.update mac bits)
    (Hex/toHexString (.doFinal mac))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn genHash

  "Generate a Message Digest"
  ^String
  [data & [algo] ]
  {:pre [(some? data)]}

  (let
    [^bytes
     bits (condp = (class data)
            InputStream (toBytes data)
            (bytesClass) data
            (throwBadArg "Bad type"))]
    (->> (-> ^String
             (stror algo SHA_512)
             (MessageDigest/getInstance )
             (.digest data))
         (Base64/toBase64String ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn asymKeyPair<>

  "Make a Asymmetric key-pair"
  ^KeyPair
  [^String algo & [keylen]]

  (let [len (or keylen 1024)]
    (log/debug "gen keypair for algo %s, len %d" algo len)
    (-> (doto (KeyPairGenerator/getInstance algo _BC_)
              (.initialize (int len) (srandom<> true)))
        (.generateKeyPair ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn fmtPEM

  "Serialize object in PEM format"
  ^bytes
  [obj & [^chars pwd]]
  {:pre [(some? obj)]}

  (let [sw (StringWriter.)
        ec (pemencr<> pwd)
        pw (PEMWriter. sw)]
    (->>
      (if (some? ec)
        (JcaMiscPEMGenerator. obj ec)
        (JcaMiscPEMGenerator. obj))
      (.writeObject pw ))
    (.flush pw)
    (bytesify (.toString sw))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn exportPrivateKey

  "Export Private Key"
  ^bytes
  [^PrivateKey pkey & [fmt pwd]]
  {:pre [(some? pkey)]}

  ;;"-----BEGIN RSA PRIVATE KEY-----\n" "\n-----END RSA PRIVATE KEY-----\n"
  (if (= (or fmt PEM_FORM)
         PEM_FORM)
    (fmtPEM pkey pwd)
    (.getEncoded pkey)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn exportPublicKey

  "Export Public Key"
  ^bytes
  [^PublicKey pkey & [fmt]]
  {:pre [(some? pkey)]}

  ;;"-----BEGIN RSA PUBLIC KEY-----\n" "\n-----END RSA PUBLIC KEY-----\n"
  (if (= (or fmt PEM_FORM)
         PEM_FORM)
    (fmtPEM pkey)
    (.getEncoded pkey)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn exportCert

  "Export Certificate"
  ^bytes
  [^X509Certificate cert & [fmt]]
  {:pre [(some? cert)]}

  ;;"-----BEGIN CERTIFICATE-----\n" "-----END CERTIFICATE-----\n"
  (if (= (or fmt PEM_FORM)
         PEM_FORM)
    (fmtPEM cert)
    (.getEncoded cert)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn csreq<>

  "Make a PKCS10 - csr-request"
  [^String dnStr & [keylen fmt pwd]]
  {:pre [(hgl? dnStr)]}

  (let [csb (JcaContentSignerBuilder. DEF_ALGO)
        len (or keylen 1024)
        kp (asymKeyPair<> RSA len)
        rbr (JcaPKCS10CertificationRequestBuilder.
              (X500Principal. dnStr)
              (.getPublic kp))
        k (.getPrivate kp)
        cs (-> (.setProvider csb _BC_)
               (.build k))
        rc (.build rbr cs)]
    (log/debug "csr: dnStr= %s, key-len= %d" dnStr len)
    [(if (= (or fmt PEM_FORM)
            PEM_FORM)
       (fmtPEM rc)
       (.getEncoded rc))
       ;;"-----BEGIN CERTIFICATE REQUEST-----\n" "\n-----END CERTIFICATE REQUEST-----\n"
     (exportPrivateKey k fmt pwd)]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- pemparse2

  ""
  [^JcaPEMKeyConverter pc obj]

  (let
    [z (class obj)]
    (cond
      (= PEMKeyPair z)
      (.getKeyPair pc ^PEMKeyPair obj)

      (= KeyPair z)
      obj

      (= PrivateKeyInfo z)
      (.getPrivateKey pc ^PrivateKeyInfo obj)

      (= ContentInfo z);;cms.ContentInfo
      obj

      (= X509AttributeCertificateHolder z)
      (toXCert obj)

      (= X509TrustedCertificateBlock z)
      (-> ^X509TrustedCertificateBlock obj
          (.getCertificateHolder )
          (toXCert))

      (= SubjectPublicKeyInfo z)
      (.getPublicKey pc ^SubjectPublicKeyInfo obj)

      (= X509CertificateHolder z)
      (toXCert obj)

      (= X509CRLHolder z)
      obj

      (= PKCS10CertificationRequest z)
      obj

      :else obj)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- pemparse

  "PEM encoded streams may contain
  X509 certificates,
  PKCS8 encoded keys and PKCS7 objs.

  PKCS7 objs => a CMS ContentInfo object.
  PubKeys => well formed SubjectPublicKeyInfo objs
  PrvKeys => well formed PrivateKeyInfo obj.
  => PEMKeyPair if contains both private and public key.
  CRLs, Certificates,
  PKCS#10 requests,
  and Attribute Certificates => appropriate holder class"

  [^InputStream inp]

  (with-open [rdr (InputStreamReader. inp)]
    (let
      [dc (-> (JcePEMDecryptorProviderBuilder.)
              (.build pwd))
       dp (-> (BcPKCS12PBEInputDecryptorProviderBuilder.)
              (.build pwd))
       pc (doto
            (JcaPEMKeyConverter.)
            (.setProvider _BC_))
       obj (-> (PEMParser. rdr)
               (.readObject ))
       z (class obj)]
      (->>
        (cond
          (= PKCS8EncryptedPrivateKeyInfo z)
          (-> ^PKCS8EncryptedPrivateKeyInfo obj
              (.decryptPrivateKeyInfo dp))
          (= PEMEncryptedKeyPair z)
          (-> pc
              (.getKeyPair ^PEMEncryptedKeyPair obj)
              (.decryptKeyPair dc))
          :else obj)
        (pemparse2 )))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; generate self-signed cert
;; self signed-> issuer is self
(defn- ssv1Cert

  ""
  [^KeyStore store {:keys [^String dnStr
                           ^String algo
                           ^Date start
                           ^Date end] :as args}]
  (let [kp (->> (or (:keylen args) 1024)
                (asymKeyPair<> (:style args)))
        end (->> (or (:validFor args) 12)
                 (+months )
                 (or end ))
        start (or start (Date.))
        pv (.getProvider store)
        prv (.getPrivate kp)
        pub (.getPublic kp)
        bdr (JcaX509v1CertificateBuilder.
              (X500Principal. dnStr)
              (nextSerial)
              start end
              (X500Principal. dnStr) pub)
        cs (-> (JcaContentSignerBuilder. algo)
               (.setProvider pv)
               (.build prv))
        cert (toXCert (.build bdr cs))]
    (.checkValidity cert (Date.))
    (.verify cert pub)
    (log/debug (str "mkSSV1Cert: dn= %s "
                    ",algo= %s,start= %s"
                    ",end=%s")
               dnStr algo start end)
    [cert prv]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn pkcs12<>

  "Make a PKCS12 object from key and cert"
  [^File fout keyPEM certPEM
   ^chars pwd & [^chars pwd2]]

  (let [ct (.getTrustedCertificate (convCert certPEM))
        rdr (InputStreamReader. (streamify keyPEM))
        ss (pkcsStore<>)
        out (baos<>)
        ^KeyPair kp (.readObject (PEMParser. rdr))]
    (.setKeyEntry ss
                  (alias<>)
                  (.getPrivate kp)
                  pwd
                  (into-array Certificate [ct]))
    (.store ss out pwd)
    (writeFile fout (.toByteArray out))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- ssv1XXX

  ""
  {:no-doc true}
  [store dnStr pwd fout pwd2 args]

  (let [[cert pkey]
        (->> (assoc args :dnStr dnStr)
             (ssv1Cert store args))
        out (baos<>)]
    (.setKeyEntry
      ks
      (alias<>)
      ^PrivateKey pkey
      pwd
      (into-array Certificate [cert]))
    (.store ks out pwd2)
    (->> (.toByteArray out)
         (writeFile (io/file fout)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ssv1PKCS12

  "Make a SSV1 (root level) type PKCS12 object"
  [^String dnStr ^chars pwd args ^File fout & [^chars pwd2]]

  (->> (merge {:algo DEF_ALGO
               :style RSA} args)
       (ssv1XXX (pkcsStore<>) dnStr pwd fout pwd2)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ssv1JKS

  "Make a SSV1 (root level) type JKS object"
  [^String dnStr ^chars pwd args ^File out & [^chars pwd2]]

  (->> (merge {:algo "SHA1withDSA"
               :style DSA} args)
       (ssv1XXX (jksStore<>) dnStr pwd fout pwd2)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- mkSSV3Cert

  "Make a SSV3 server key"
  [^PKeyGist issuer
   ^Provider pv
   {:keys [^String dnStr
           ^String algo
           ^Date start
           ^Date end] :as args}]

  (let [^X509Certificate rootc (.cert issuer)
        subject (X500Principal. dnStr)
        klen (or (:keylen args) 1024)
        exu (JcaX509ExtensionUtils.)
        kp (-> (.pkey issuer)
               (.getAlgorithm )
               (asymKeyPair klen))
        bdr (JcaX509v3CertificateBuilder.
              rootc
              (nextSerial)
              start
              end
              subject
              (.getPublic kp))
        cs (-> (JcaContentSignerBuilder. algo)
               (.setProvider pv)
               (.build (.pkey issuer)))]
    (.addExtension
      bdr
      X509Extension/authorityKeyIdentifier
      false
      (.createAuthorityKeyIdentifier exu rootc))
    (.addExtension
      bdr
      X509Extension/subjectKeyIdentifier
      false
      (.createSubjectKeyIdentifier exu (.getPublic kp)))
    (let [ct (toXCert (.build bdr cs))]
      (.checkValidity ct (Date.))
      (.verify ct (.getPublicKey rootc))
      [ct (.getPrivate kp)])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- makeSSV3

  ""
  [^PKeyGist issuer ^String dnStr ^chars pwd ^File fout pwd2 args]

  (let [chain (into [] (.chain issuer))
        ^KeyStore ks (:ks args)
        [cert pkey]
        (-> (assoc args :dnStr dnStr)
            (mkSSV3Cert issuer (.getProvider ks) ))
        out (baos<>)
        cs (cons cert chain)]
    (.setKeyEntry
      ks
      (alias<>)
      pkey
      pwd
      (into-array Certificate cs))
    (.store ks fout pwd2)
    (->> (.toByteArray out)
         (writeFile (io/file fout)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ssv3PKCS12

  "Make a SSV3 type PKCS12 object"
  [^PKeyGist issuer ^String dnStr ^chars pwd
   ^File fout args & [^chars pwd2]]

  (makeSSV3
    issuer
    dnStr
    pwd
    fout
    pwd2
    (merge args {:algo DEF_ALGO :ks (pkcsStore<>) } )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; JKS uses SUN and hence needs to use DSA
;;
(defn ssv3JKS

  "Make a SSV3 JKS object"
  [^PKeyGist issuer ^String dnStr ^chars pwd
   ^File fout args & [^chars pwd2]]

  (makeSSV3
    issuer
    dnStr
    pwd
    fout
    pwd2
    (merge args {:algo "SHA1withDSA" :ks (jksStore<>) } )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn exportPkcs7

  "Extract and export PKCS7 info from a PKCS12 object"
  [^File fileOut ^URL p12File ^chars pwd & [^chars pwd2]]

  (with-open [inp (.openStream p12File)]
    (let
      [xxx (CMSProcessableByteArray. (bytesify "?"))
       gen (CMSSignedDataGenerator.)
       pkey (convPKey inp pwd pwd2)
       cl (.chain pkey)
       bdr (JcaSignerInfoGeneratorBuilder.
                (-> (JcaDigestCalculatorProviderBuilder.)
                    (.setProvider _BC_)
                    (.build)))
       ;;    "SHA1withRSA"
       cs (-> (JcaContentSignerBuilder. SHA512)
              (.setProvider _BC_)
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
(defn certGist

  "Get some basic info from Certificate"
  ^CertGist
  [^X509Certificate x509]

  (when (some? x509)
    (reify CertGist
      (issuer [_] (.getIssuerX500Principal x509))
      (subj [_] (.getSubjectX500Principal x509))
      (notBefore [_] (.getNotBefore x509))
      (notAfter [_] (.getNotAfter x509)))))

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


