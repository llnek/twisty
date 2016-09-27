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
    [czlab.xlib.meta :refer [bytesClass]]
    [czlab.xlib.logging :as log]
    [clojure.java.io :as io]
    [clojure.string :as cs])

  (:use [czlab.xlib.core]
        [czlab.xlib.io]
        [czlab.xlib.str])

  (:import
    [javax.activation DataHandler CommandMap MailcapCommandMap]
    [javax.mail BodyPart MessagingException Multipart Session]
    [org.bouncycastle.jce.provider BouncyCastleProvider]
    [org.apache.commons.mail DefaultAuthenticator]
    [javax.net.ssl X509TrustManager TrustManager]
    [clojure.lang APersistentVector]
    [org.bouncycastle.util.encoders Hex Base64]
    [org.bouncycastle.pkcs.jcajce
     JcaPKCS10CertificationRequestBuilder]
    [org.bouncycastle.pkcs.bc
     BcPKCS12PBEInputDecryptorProviderBuilder]
    [org.bouncycastle.operator
     DigestCalculatorProvider
     ContentSigner
     OperatorCreationException]
    [org.bouncycastle.asn1.pkcs PrivateKeyInfo]
    [org.bouncycastle.asn1 ASN1EncodableVector]
    [org.bouncycastle.asn1.x500 X500Name]
    [org.bouncycastle.asn1.x509
     X509Extension
     SubjectPublicKeyInfo]
    [org.bouncycastle.asn1.cms
     AttributeTable
     ContentInfo
     IssuerAndSerialNumber]
    [org.bouncycastle.pkcs
     PKCS8EncryptedPrivateKeyInfo]
    [org.bouncycastle.openssl
     X509TrustedCertificateBlock
     PEMKeyPair
     PEMEncryptedKeyPair]
    [org.bouncycastle.cert
     X509CRLHolder
     X509CertificateHolder
     X509AttributeCertificateHolder]
    [org.bouncycastle.openssl.jcajce
     JcePEMDecryptorProviderBuilder
     JcePEMEncryptorBuilder
     JcaMiscPEMGenerator
     JcaPEMKeyConverter]
    [java.security
     Policy
     PermissionCollection
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
    [org.bouncycastle.cms
     CMSSignedDataGenerator
     CMSProcessableFile
     CMSProcessable
     CMSSignedGenerator
     CMSProcessableByteArray]
    [org.bouncycastle.cms.jcajce
     JcaSignerInfoGeneratorBuilder]
    [org.bouncycastle.operator.jcajce
     JcaContentSignerBuilder
     JcaDigestCalculatorProviderBuilder ]
    ;;[org.bouncycastle.util Store]
    [javax.security.auth.x500 X500Principal]
    [org.bouncycastle.cert.jcajce
     JcaCertStore
     JcaX509CertificateConverter
     JcaX509ExtensionUtils
     JcaX509v1CertificateBuilder
     JcaX509v3CertificateBuilder]
    [org.bouncycastle.openssl
     PEMWriter
     PEMParser
     PEMEncryptor]
    [org.bouncycastle.pkcs
     PKCS10CertificationRequest
     PKCS10CertificationRequestBuilder]
    [javax.crypto
     Mac
     SecretKey
     Cipher
     KeyGenerator]
    [javax.crypto.spec SecretKeySpec]
    [java.io
     StringWriter
     PrintStream
     File
     InputStream
     IOException
     FileInputStream
     InputStreamReader
     ByteArrayInputStream
     ByteArrayOutputStream]
    [java.math BigInteger]
    [java.net URL]
    [java.util Random Date]
    [javax.mail.internet
     ContentType
     MimeBodyPart
     MimeMessage
     MimeMultipart
     MimeUtility]
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
;;(def ^:private EXPLICIT_SIGNING :EXPLICIT)
;;(def ^:private IMPLICIT_SIGNING :IMPLICIT)
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

(def ^String SHA512RSA "SHA512withRSA")
(def ^String SHA256RSA "SHA256withRSA")
(def ^String SHA1RSA "SHA1withRSA")
(def ^String MD5RSA "MD5withRSA")
(def ^String BFISH "BlowFish")

(def DER_FORM :DER)
(def PEM_FORM :PEM)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- maybeStream

  "Convert object into some form of stream, if possible"
  ^InputStream
  [obj]

  (condp instance? obj
    String (streamify (bytesify obj))
    (bytesClass) (streamify obj)
    InputStream obj
    nil))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn isSigned?

  "true if this content-type indicates signed"
  [^String cType]

  (let [ct (lcase cType)]
    (or (embeds? ct "multipart/signed")
        (and (embeds? ct "application/x-pkcs7-mime")
             (embeds? ct "signed-data")))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn isEncrypted?

  "true if this content-type indicates encrypted"
  [^String cType]

  (let [ct (lcase cType)]
    (and (embeds? ct "application/x-pkcs7-mime")
         (embeds? ct "enveloped-data"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn isCompressed?

  "true if this content-type indicates compressed"
  [^String cType]

  (let [ct (lcase cType)]
    (and (embeds? ct "application/pkcs7-mime")
         (embeds? ct "compressed-data"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn assertJce

  "This function should fail if the non-restricted (unlimited-strength)
   jce files are not placed in jre-home"
  []

  (let
    [kgen (doto
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
(def ^:dynamic ^Provider *_BC_* (BouncyCastleProvider.))
(Security/addProvider *_BC_*)
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
                    "org.bouncycastle.mail.smime.handlers.multipart_signed")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmacro withBC1
  "Set BC as provider as part of construction(arg)"
  [clazz p1 & [pv]]
  `(-> (new ~clazz ~p1)
       (.setProvider (or ~pv *_BC_*))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmacro withBC
  "Set BC as provider as part of construction"
  [clazz & [pv]]
  `(-> (new ~clazz)
       (.setProvider (or ~pv *_BC_*))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- toXCert

  ""
  ^X509Certificate
  [^X509CertificateHolder h]

  (-> JcaX509CertificateConverter
      (withBC )
      (.getCertificate h)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- pemencr<>

  ""
  ^PEMEncryptor
  [^chars pwd]

  (if-not (empty? pwd)
    (-> (->> (rand-nth (vec ENC_ALGOS))
             (withBC1 JcePEMEncryptorBuilder ))
        (.setSecureRandom (rand<>))
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

  (MessageDigest/getInstance algo *_BC_*))

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

  (trye! nil (.list *_BC_* os)))

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

  (if-some
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
(defn tcert<>

  "Get a certificate from store"
  ^Certificate
  [^KeyStore store ^String n]

  (if-some
    [e (->> (.getEntry store n nil)
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
  {:tag KeyStore}

  ([^InputStream inp] (pkcsStore<> inp nil))
  ([] (pkcsStore<> nil nil))
  ([^InputStream inp ^chars pwd2]
   (doto
     (KeyStore/getInstance "PKCS12" *_BC_*)
     (.load inp pwd2))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn jksStore<>

  "Create a JKS key-store"
  {:tag KeyStore}

  ([^InputStream inp] (jksStore<> inp nil))
  ([] (jksStore<> nil nil))
  ([^InputStream inp ^chars pwd2]
   (doto (->> (Security/getProvider "SUN")
              (KeyStore/getInstance "JKS"))
     (.load inp pwd2))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn initStore!

  "Initialize the key-store"
  ^KeyStore
  [^KeyStore store arg ^chars pwd2]

  (let
    [[b ^InputStream inp]
     (condp = (class arg)
       File [true (FileInputStream. ^File arg)]
       (bytesClass) [true (streamify arg)]
       InputStream [false arg]
       nil [false nil]
       (throwBadArg "Bad type"))]
    (try
      (.load store inp pwd2)
      store
      (finally
        (if b (closeQ inp))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn convCert

  "Convert to a Certificate"
  ^Certificate
  [arg]

  (let
    [^InputStream
     inp (condp = (class arg)
           (bytesClass) (streamify arg)
           InputStream arg
           (throwBadArg "Bad type"))]
    (-> (CertificateFactory/getInstance "X.509")
        (.generateCertificate inp))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- convPKey

  "Convert to a Private Key"
  {:tag PKeyGist}

  ([arg ^chars pwd] (convPKey arg pwd nil))
  ([arg ^chars pwd ^chars pwd2]
   (let
     [^InputStream
      inp (condp = (class arg)
            (bytesClass) (streamify arg)
            InputStream arg
            (throwBadArg "Bad type"))
      ks (pkcsStore<> inp pwd2)
      n (first (filterEntries ks :keys))]
     (if (hgl? n)
       (pkeyGist<> ks n pwd)))))

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
  {:tag String}

  ([^bytes skey data] (genMac skey data nil))
  ([^bytes skey data algo]
   {:pre [(some? skey) (some? data)]}
   (let
     [algo (stror algo DEF_MAC)
      mac (Mac/getInstance algo *_BC_*)]
     (when-some [bits (convBytes data)]
       (->> (SecretKeySpec. skey algo)
            (.init mac ))
       (.update mac bits)
       (Hex/toHexString (.doFinal mac))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn genHash

  "Generate a Message Digest"
  {:tag String}

  ([data] (genHash data nil))
  ([data algo]
   (if-some
     [bits (convBytes data)]
     (->> (-> (stror algo "SHA-512")
              (MessageDigest/getInstance )
              (.digest bits))
          (Base64/toBase64String )))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn asymKeyPair<>

  "Make a Asymmetric key-pair"
  {:tag KeyPair}

  ([^String algo] (asymKeyPair<> algo nil))
  ([^String algo keylen]
   (let [len (or keylen 1024)]
     (log/debug "gen keypair for algo %s, len %d" algo len)
     (-> (doto (KeyPairGenerator/getInstance algo *_BC_*)
               (.initialize (int len) (rand<> true)))
         (.generateKeyPair )))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn exportPEM

  "Serialize object in PEM format"
  ^bytes

  ([obj] (exportPEM obj nil))
  ([obj ^chars pwd]
   (if (some? obj)
     (let [sw (StringWriter.)
           ec (pemencr<> pwd)
           pw (PEMWriter. sw)]
       (->>
         (if (some? ec)
           (JcaMiscPEMGenerator. obj ec)
           (JcaMiscPEMGenerator. obj))
         (.writeObject pw ))
       (.flush pw)
       (bytesify (.toString sw))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn exportPrivateKey

  "Export Private Key"
  ^bytes

  ([^PrivateKey pkey pwd] (exportPrivateKey pkey pwd nil))
  ([^PrivateKey pkey] (exportPrivateKey pkey nil nil))
  ([^PrivateKey pkey pwd fmt]
   {:pre [(some? pkey)]}
   (if (= (or fmt PEM_FORM) PEM_FORM)
     (exportPEM pkey pwd)
     (.getEncoded pkey))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn exportPublicKey

  "Export Public Key"
  ^bytes

  ([^PublicKey pkey] (exportPublicKey pkey nil))
  ([^PublicKey pkey fmt]
   {:pre [(some? pkey)]}
   (if (= (or fmt PEM_FORM) PEM_FORM)
     (exportPEM pkey)
     (.getEncoded pkey))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn exportCert

  "Export Certificate"
  ^bytes

  ([^X509Certificate cert] (exportCert cert nil))
  ([^X509Certificate cert fmt]
   {:pre [(some? cert)]}
   (if (= (or fmt PEM_FORM) PEM_FORM)
     (exportPEM cert)
     (.getEncoded cert))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn csreq<>

  "Make a PKCS10 - csr-request"

  ([^String dnStr keylen] (csreq<> dnStr keylen nil))
  ([^String dnStr] (csreq<> dnStr nil nil))
  ([^String dnStr keylen pwd]
   {:pre [(hgl? dnStr)]}
   (let
     [csb (withBC1 JcaContentSignerBuilder DEF_ALGO)
      len (or keylen 1024)
      kp (asymKeyPair<> "RSA" len)
      rbr (JcaPKCS10CertificationRequestBuilder.
            (X500Principal. dnStr)
            (.getPublic kp))
      k (.getPrivate kp)
      rc (->> (.build csb k) (.build rbr))]
     (log/debug "csr: dnStr= %s, key-len= %d" dnStr len)
     [(exportPEM rc)
      (exportPrivateKey k pwd)])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- pemparse2

  ""
  [^JcaPEMKeyConverter pc obj]

  (let []
    (condp = (class obj)

      PEMKeyPair
      (.getKeyPair pc ^PEMKeyPair obj)

      KeyPair
      obj

      PrivateKeyInfo
      (.getPrivateKey pc ^PrivateKeyInfo obj)

      ContentInfo
      obj

      X509AttributeCertificateHolder
      (toXCert obj)

      X509TrustedCertificateBlock
      (-> ^X509TrustedCertificateBlock obj
          (.getCertificateHolder )
          (toXCert))

      SubjectPublicKeyInfo
      (.getPublicKey pc ^SubjectPublicKeyInfo obj)

      X509CertificateHolder
      (toXCert obj)

      X509CRLHolder
      obj

      PKCS10CertificationRequest
      obj

      obj)))

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

  [^InputStream inp ^chars pwd]

  (with-open
    [rdr (InputStreamReader. inp)]
    (let
      [dp (-> (BcPKCS12PBEInputDecryptorProviderBuilder.)
              (.build pwd))
       dc (-> (JcePEMDecryptorProviderBuilder.)
              (.build pwd))
       pc (withBC JcaPEMKeyConverter)
       obj (-> (PEMParser. rdr)
               (.readObject ))]
      (->>
        (condp = (class obj)
          PKCS8EncryptedPrivateKeyInfo
          (-> ^PKCS8EncryptedPrivateKeyInfo
              obj (.decryptPrivateKeyInfo dp))
          PEMEncryptedKeyPair
          (->>
            (-> ^PEMEncryptedKeyPair
                obj (.decryptKeyPair dc))
            (.getKeyPair pc))
          obj)
        (pemparse2 )))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn pkcs12<>

  "Make a PKCS12 object from key and cert"

  ([cert pk fout pwd] (pkcs12<> cert pk fout pwd nil))
  ([^X509Certificate cert
    ^PrivateKey pk
    ^File fout ^chars pwd ^chars pwd2]
   (let [ss (pkcsStore<>)
         out (baos<>)]
     (.setKeyEntry ss
                   (alias<>)
                   pk
                   pwd
                   (into-array Certificate [cert]))
     (.store ss out pwd2)
     (writeFile (io/file fout) (.toByteArray out)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; generate self-signed cert
;; self signed-> issuer is self
(defn- ssv1Cert

  ""
  [^KeyStore store {:keys [^String dnStr
                           ^String algo
                           ^Date start
                           ^Date end] :as args}]
  (let
    [kp (->> (or (:keylen args) 1024)
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
     cs (-> (withBC1 JcaContentSignerBuilder algo pv)
            (.build prv))
     cert (toXCert (.build bdr cs))]
    (.checkValidity cert (Date.))
    (.verify cert pub)
    (log/debug (str "mkSSV1Cert: dn= %s "
                    ",algo= %s,start= %s"
                    ",end=%s")
               dnStr algo start end)
    [prv cert]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- ssv1XXX

  ""
  {:no-doc true}
  [^KeyStore store dnStr pwd fout pwd2 args]

  (let
    [[^PrivateKey pkey cert]
     (->> (assoc args :dnStr dnStr)
          (ssv1Cert store ))
     out (baos<>)]
    (.setKeyEntry
      store
      (alias<>)
      pkey
      pwd
      (into-array Certificate [cert]))
    (.store store out pwd2)
    (writeFile (io/file fout) (.toByteArray out))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ssv1PKCS12

  "Make a SSV1 (root level) type PKCS12 object"

  ([dnStr pwd args fout]
   (ssv1PKCS12 dnStr pwd args fout nil))

  ([^String dnStr ^chars pwd args fout ^chars pwd2]
   (->> (merge {:algo DEF_ALGO
                :style "RSA"} args)
        (ssv1XXX (pkcsStore<>) dnStr pwd fout pwd2))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ssv1JKS

  "Make a SSV1 (root level) type JKS object"

  ([dnStr pwd args fout]
   (ssv1JKS dnStr pwd args fout nil))

  ([^String dnStr ^chars pwd args ^File fout ^chars pwd2]
   (->> (merge {:algo "SHA1withDSA"
                :style "DSA"} args)
        (ssv1XXX (jksStore<>) dnStr pwd fout pwd2))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- mkSSV3Cert

  "Make a SSV3 server key"
  [^KeyStore store ^PKeyGist issuer
   {:keys [^String dnStr ^String algo
           ^Date start ^Date end] :as args}]

  (let
    [^X509Certificate rootc (.cert issuer)
     end (->> (or (:validFor args) 12)
              (+months )
              (or end ))
     start (or start (Date.))
     subject (X500Principal. dnStr)
     len (or (:keylen args) 1024)
     pv (.getProvider store)
     exu (JcaX509ExtensionUtils.)
     kp (-> (.pkey issuer)
            (.getAlgorithm )
            (asymKeyPair<> len))
     bdr (JcaX509v3CertificateBuilder.
           rootc
           (nextSerial)
           start
           end
           subject
           (.getPublic kp))
     cs (-> (withBC1 JcaContentSignerBuilder algo pv)
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
      [(.getPrivate kp) ct])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- makeSSV3

  ""
  [^KeyStore store ^PKeyGist issuer
   ^String dnStr ^chars pwd ^File fout pwd2 args]

  (let
    [chain (into [] (.chain issuer))
     [^PrivateKey pkey cert]
     (->> (assoc args :dnStr dnStr)
          (mkSSV3Cert store issuer ))
     out (baos<>)
     cs (cons cert chain)]
    (.setKeyEntry
      store
      (alias<>)
      pkey
      pwd
      (into-array Certificate cs))
    (.store store out pwd2)
    (writeFile (io/file fout) (.toByteArray out))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ssv3PKCS12

  "Make a SSV3 type PKCS12 object"

  ([issuer dnStr pwd fout args]
   (ssv3PKCS12 issuer dnStr pwd fout args nil))

  ([^PKeyGist issuer ^String dnStr ^chars pwd
    ^File fout args ^chars pwd2]
   (makeSSV3
     (pkcsStore<>)
     issuer
     dnStr
     pwd
     fout
     pwd2
     (merge args {:algo DEF_ALGO } ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; JKS uses SUN and hence needs to use DSA
;;
(defn ssv3JKS

  "Make a SSV3 JKS object"

  ([issuer dnStr pwd fout args]
   (ssv3JKS issuer dnStr pwd fout args nil))

  ([^PKeyGist issuer ^String dnStr ^chars pwd
    ^File fout args ^chars pwd2]
   (makeSSV3
     (jksStore<>)
     issuer
     dnStr
     pwd
     fout
     pwd2
     (merge args {:algo "SHA1withDSA" } ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn exportPkcs7

  "Extract and export PKCS7 info from a PKCS12 object"
  [^PKeyGist pkey fout]

  (let
    [xxx (CMSProcessableByteArray. (bytesify "?"))
     gen (CMSSignedDataGenerator.)
     cl (into [] (.chain pkey))
     bdr (->> (-> (withBC JcaDigestCalculatorProviderBuilder)
                  (.build))
              (JcaSignerInfoGeneratorBuilder.))
     ;;    "SHA1withRSA"
     cs (-> (withBC1 JcaContentSignerBuilder SHA512RSA)
            (.build (.pkey pkey)))
     ^X509Certificate x509 (.cert pkey)]
    (->> (.build bdr cs x509)
         (.addSignerInfoGenerator gen ))
    (->> (JcaCertStore. cl)
         (.addCertificates gen ))
    (->> (-> (.generate gen xxx)
             (.getEncoded))
         (writeFile (io/file fout)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn session<>

  "Creates a new java-mail session"
  {:tag Session}

  ([^String user] (session<> user nil))
  ([] (session<> nil nil))
  ([^String user ^chars pwd]
   (Session/getInstance
     (System/getProperties)
     (if (hgl? user)
       (->> (if (some? pwd) (String. pwd))
            (DefaultAuthenticator. user))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn mimeMsg<>

  "Create a new MIME Message"
  {:tag MimeMessage}

  ([^String user ^chars pwd] (mimeMsg<> user pwd nil))
  ([^InputStream inp] (mimeMsg<> "" nil inp))
  ([] (mimeMsg<> "" nil nil))
  ([^String user ^chars pwd ^InputStream inp]
   (let [s (session<> user pwd)]
     (if (nil? inp)
       (MimeMessage. s)
       (MimeMessage. s inp)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn isDataSigned?

  "Check if this stream-like object/message-part is signed"
  [^Object obj]

  (if-some [inp (maybeStream obj)]
    (try
      (->> (mimeMsg<> "" nil inp)
           (.getContentType)
           (isSigned? ))
      (finally
        (resetStream! inp)))
    (if (instance? Multipart obj)
      (->> ^Multipart obj
           (.getContentType )
           (isSigned? ))
      (throwIOE "Invalid content: %s" (getClassname obj)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn isDataCompressed?

  "Check if this stream-like object/message-part is compressed"
  [^Object obj]

  (if-some [inp (maybeStream obj)]
    (try
      (->> (mimeMsg<> "" nil inp)
           (.getContentType )
           (isCompressed? ))
      (finally
        (resetStream! inp)))
    (condp instance? obj
      Multipart (->> ^Multipart obj
                     (.getContentType )
                     (isCompressed? ))
      BodyPart (->> ^BodyPart obj
                    (.getContentType )
                    (isCompressed? ))
      (throwIOE "Invalid content: %s" (getClassname obj)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn isDataEncrypted?

  "Check if this stream-like object/message-part is encrypted"
  [^Object obj]

  (if-some [inp (maybeStream obj)]
    (try
      (->> (mimeMsg<> "" nil inp)
           (.getContentType )
           (isEncrypted? ))
      (finally
        (resetStream! inp)))
    (condp instance? obj
      Multipart (->> ^Multipart obj
                     (.getContentType )
                     (isEncrypted? ))
      BodyPart (->> ^BodyPart obj
                    (.getContentType )
                    (isEncrypted? ))
      (throwIOE "Invalid content: %s" (getClassname obj)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn getCharset

  "Deduce the char-set from content-type"
  {:tag String}

  ([^String cType] (getCharset cType nil))
  ([^String cType ^String dft]
   (stror
     (if (hgl? cType)
       (trye! nil
              (-> (ContentType. cType)
                  (.getParameter "charset")
                  (MimeUtility/javaCharset ))))
     (if (hgl? dft)
       (MimeUtility/javaCharset dft)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- fingerprint<>

  ""
  ^String
  [^bytes data ^String algo]

  (let
    [hv (-> (str algo)
            (MessageDigest/getInstance)
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
(defn digest<sha1>

  "Generate a fingerprint/digest using SHA-1"
  ^String
  [^bytes data]

  (fingerprint<> data "SHA-1"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn digest<md5>

  "Generate a fingerprint/digest using MD5"
  ^String
  [^bytes data]

  (fingerprint<> data "MD5"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn certGist

  "Get some basic info from Certificate"
  ^CertGist
  [^X509Certificate x509]

  (if (some? x509)
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


