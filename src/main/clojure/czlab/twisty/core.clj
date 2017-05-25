;; Copyright (c) 2013-2017, Kenneth Leung. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file epl-v10.html at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

(ns ^{:doc "Crypto functions."
      :author "Kenneth Leung"}

  czlab.twisty.core

  (:require [czlab.basal.meta :as m :refer [bytesClass]]
            [czlab.basal.dates :as d :refer [addMonths]]
            [czlab.basal.log :as log]
            [clojure.java.io :as io]
            [clojure.string :as cs]
            [czlab.basal.core :as c]
            [czlab.basal.io :as i]
            [czlab.basal.str :as s])

  (:import [javax.activation DataHandler CommandMap MailcapCommandMap]
           [javax.mail BodyPart MessagingException Multipart Session]
           [org.bouncycastle.jce.provider BouncyCastleProvider]
           [org.apache.commons.mail DefaultAuthenticator]
           [javax.net.ssl X509TrustManager TrustManager]
           [org.bouncycastle.util.encoders Hex Base64]
           [org.bouncycastle.asn1.pkcs PrivateKeyInfo]
           [org.bouncycastle.asn1 ASN1EncodableVector]
           [org.bouncycastle.asn1.x500 X500Name]
           [clojure.lang APersistentVector]
           [org.bouncycastle.pkcs.jcajce
            JcaPKCS10CertificationRequestBuilder]
           [org.bouncycastle.pkcs.bc
            BcPKCS12PBEInputDecryptorProviderBuilder]
           [org.bouncycastle.operator
            DigestCalculatorProvider
            ContentSigner
            OperatorCreationException]
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
            JcaDigestCalculatorProviderBuilder]
           [javax.security.auth.x500 X500Principal]
           [javax.crypto.spec SecretKeySpec]
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
           [czlab.basal Stateful]
           [czlab.jasal XData]
           [java.lang Math]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(def ^:private ^String def-algo "SHA1WithRSAEncryption")
(def ^:private ^String def-mac "HmacSHA512")
;;(def ^:private EXPLICIT_SIGNING :EXPLICIT)
;;(def ^:private IMPLICIT_SIGNING :IMPLICIT)
(def ^:private enc-algos
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
(def ^String sha-512-rsa "SHA512withRSA")
(def ^String sha-256-rsa "SHA256withRSA")
(def ^String sha1-rsa "SHA1withRSA")
(def ^String md5-rsa "MD5withRSA")
(def ^String blow-fish "BlowFish")
(def der-form ::der)
(def pem-form ::pem)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn isSigned?
  "Does content-type indicate signed?" [cType]

  (let [ct (s/lcase cType)]
    (or (s/embeds? ct "multipart/signed")
        (and (s/embeds? ct "application/x-pkcs7-mime")
             (s/embeds? ct "signed-data")))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn isEncrypted?
  "Does content-type indicate encrypted?" [cType]

  (let [ct (s/lcase cType)]
    (and (s/embeds? ct "application/x-pkcs7-mime")
         (s/embeds? ct "enveloped-data"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn isCompressed?
  "Does content-type indicate compressed?" [cType]

  (let [ct (s/lcase cType)]
    (and (s/embeds? ct "application/pkcs7-mime")
         (s/embeds? ct "compressed-data"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn assertJce
  "This function should fail if the non-restricted (unlimited-strength)
   jce files are **not** placed in jre-home" []

  (let
    [kgen (doto
            (KeyGenerator/getInstance blow-fish)
            (.init 256))]
    (-> (doto
          (Cipher/getInstance blow-fish)
          (.init Cipher/ENCRYPT_MODE
                 (SecretKeySpec. (.. kgen
                                     generateKey
                                     getEncoded) blow-fish)))
        (.doFinal (c/bytesit "yo")))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(def ^:dynamic ^Provider *-bc-* (BouncyCastleProvider.))
(Security/addProvider *-bc-*)
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
                    "org.bouncycastle.mail.smime.handlers.x_pkcs7_signature"))
  (.addMailcap (str "application/x-pkcs7-mime;; "
                    "x-java-content-handler="
                    "org.bouncycastle.mail.smime.handlers.x_pkcs7_mime"))
  (.addMailcap (str "multipart/signed;; "
                    "x-java-content-handler="
                    "org.bouncycastle.mail.smime.handlers.multipart_signed")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmacro withBC1
  "BC as provider - part of ctor(arg)"

  ([cz p1] `(withBC1 ~cz ~p1 nil))
  ([cz p1 pv]
   `(-> (new ~cz ~p1)
        (.setProvider (or ~pv *-bc-*)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmacro withBC
  "BC as provider - part of ctor"

  ([cz] `(withBC ~cz nil))
  ([cz pv]
   `(-> (new ~cz)
        (.setProvider (or ~pv *-bc-*)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- toXCert
  "" ^X509Certificate [^X509CertificateHolder h]
  (-> JcaX509CertificateConverter withBC (.getCertificate h)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- pemencr<>
  "" ^PEMEncryptor [^chars pwd]

  (if-not (empty? pwd)
    (-> (->> (rand-nth (vec enc-algos))
             (withBC1 JcePEMEncryptorBuilder ))
        (.setSecureRandom (c/rand<>)) (.build pwd))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn jksFile?
  "Is url pointing to a JKS key file?" [keyUrl]
  (some-> keyUrl io/as-url .getFile s/lcase (.endsWith ".jks")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn msgDigest
  "Get a message digest instance:
  MD5
  SHA-1, SHA-256, SHA-384, SHA-512"
  ^MessageDigest
  [algo]
  (-> (s/ucase (s/strKW algo))
      (s/stror "SHA-512")
      (MessageDigest/getInstance  *-bc-*)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn nextSerial
  "A random Big Integer" ^BigInteger []
  (BigInteger/valueOf (Math/abs (-> (Random. (c/now<>)) .nextLong))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn dbgProvider
  "List all BC algos"
  {:no-doc true} [^PrintStream os] (c/trye!! nil (.list *-bc-* os)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn alias<>
  "A new random name" ^String []
  (format "%s#%04d" (-> (c/jid<>) (.substring 0 4)) (c/seqint)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(c/decl-object PKeyGist)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmulti pkeyGist<> "" {:tag Stateful} (fn [a _ _] (class a)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod pkeyGist<> PrivateKey
  [^PrivateKey pkey
   ^Certificate cert listOfCerts]
  (c/object<> PKeyGist
              {:chain (into [] listOfCerts)
               :cert cert
               :pkey pkey}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmethod pkeyGist<> KeyStore
  [^KeyStore store ^String alias pwd]
  {:pre [(s/hgl? alias)]}

  (if-some [e (->> (KeyStore$PasswordProtection. (c/charsit pwd))
                   (.getEntry store alias)
                   (c/cast? KeyStore$PrivateKeyEntry))]
    (pkeyGist<> (.getPrivateKey e)
                (.getCertificate e)
                (.getCertificateChain e))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn tcert<>
  "Get cert from store"
  ^Certificate [^KeyStore store ^String alias] {:pre [(some? store)]}

  (if-some [e (->> (.getEntry store alias nil)
                   (c/cast? KeyStore$TrustedCertificateEntry))]
    (.getTrustedCertificate e)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn filterEntries
  "Enumerate entries in the key-store"
  ^APersistentVector
  [^KeyStore store entryType]
  {:pre [(some? store)(keyword? entryType)]}

  (loop [en (.aliases store)
         rc (transient [])]
    (if-not (.hasMoreElements en)
      (c/pcoll! rc)
      (let [n (.nextElement en)]
        (if
          (cond
            (= :certs entryType)
            (.isCertificateEntry store n)
            (= :keys entryType)
            (.isKeyEntry store n))
          (recur en (conj! rc n))
          (recur en rc))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn initStore!
  "Initialize the key-store"
  ^KeyStore [store arg pwd2] {:pre [(some? store)]}

  (let [[del? inp] (i/inputStream?? arg)]
    (try
      (doto ^KeyStore
        store
        (.load ^InputStream inp (c/charsit pwd2)))
      (finally (if del? (i/closeQ inp))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn pkcs12<>
  "Create a PKCS12 key-store" {:tag KeyStore}

  ([arg] (pkcs12<> arg nil))
  ([] (pkcs12<> nil nil))
  ([arg pwd2]
   (-> (KeyStore/getInstance "PKCS12" *-bc-*)
       (initStore! arg pwd2))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn jks<>
  "Create a JKS key-store" {:tag KeyStore}

  ([arg] (jks<> arg nil))
  ([] (jks<> nil nil))
  ([arg pwd2]
   (-> (->> (Security/getProvider "SUN")
            (KeyStore/getInstance "JKS"))
       (initStore! arg pwd2))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn convCerts
  "To a set of Certs (p7b)" ^APersistentVector [arg]

  (let [[del? inp] (i/inputStream?? arg)]
    (try (-> (CertificateFactory/getInstance "X.509")
             (.generateCertificates ^InputStream inp))
         (finally (if del? (i/closeQ inp))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn convCert "To a Certificate" ^Certificate [arg]

  (let [[del? inp] (i/inputStream?? arg)]
    (try (-> (CertificateFactory/getInstance "X.509")
             (.generateCertificate ^InputStream inp))
     (finally (if del? (i/closeQ inp))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn convPKey "To a Private Key"

  ([arg pwd] (convPKey arg pwd nil))
  ([arg ^chars pwd ^chars pwdStore]
   (let
     [ks (initStore! (pkcs12<>) arg pwdStore)
      n (first (filterEntries ks :keys))]
     (if (s/hgl? n)
       (pkeyGist<> ks n pwd)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn easyPolicy<>
  "Enables all permissions" ^Policy []
  (proxy [Policy] []
    (getPermissions [cs]
      (doto (Permissions.) (.add (AllPermission.))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn genMac<>
  "Create Message Auth Code" {:tag String}

  ([skey data] (genMac<> skey data nil))
  ([skey data algo]
   {:pre [(some? skey) (some? data)]}
   (let
     [algo (-> (s/strKW algo) s/ucase (s/stror def-mac))
      mac (Mac/getInstance algo *-bc-*)
      flag (c/decl-long-var 0)
      _ (->> (SecretKeySpec.
               (i/bytes?? skey) algo) (.init mac))]
     (i/chunkReadStream data
                        (fn [buf offset len end?]
                          (if (> len 0)
                            (do
                              (c/long-var flag + len)
                              (.update mac buf offset len)))))
     (str (some->
            (if (c/spos? (c/long-var flag)) (.doFinal mac))
            Hex/toHexString)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- gen-digest "" [data algo]
   (let [d (msgDigest algo)
         flag (c/decl-long-var 0)]
     (i/chunkReadStream data
                        (fn [buf offset len end?]
                          (if (> len 0)
                            (do
                              (c/long-var flag + len)
                              (.update d buf offset len)))))
     (if (c/spos? (c/long-var flag)) (.digest d))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn genDigest<>
  "Create Message Digest" {:tag String}

  ([data] (genDigest<> data nil))
  ([data algo]
   (str (some-> (gen-digest data algo) Base64/toBase64String))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn asymKeyPair<>
  "Create a Asymmetric key-pair" {:tag KeyPair}

  ([algo] (asymKeyPair<> algo nil))
  ([^String algo keylen]
   (let [len (or keylen 1024)]
     (log/debug "gen keypair for algo %s, len %d" algo len)
     (-> (doto (KeyPairGenerator/getInstance algo *-bc-*)
               (.initialize (int len) (c/rand<> true)))
         .generateKeyPair ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn exportPEM
  "" ^bytes [obj & [pwd]] {:pre [(some? obj)]}

  (if obj
    (let [ec (pemencr<> ^chars pwd)
          sw (StringWriter.)
          pw (PEMWriter. sw)]
      (->> (if ec
             (JcaMiscPEMGenerator. obj ec)
             (JcaMiscPEMGenerator. obj))
           (.writeObject pw ))
      (.flush pw)
      (c/bytesit (str sw)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn exportPrivateKey
  "" ^bytes [pkey & [pwd fmt]] {:pre [(some? pkey)]}

  (if (= (or fmt pem-form) pem-form)
    (exportPEM pkey pwd)
    (.getEncoded ^PrivateKey pkey)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn exportPublicKey
  "" ^bytes [pkey & [fmt]] {:pre [(some? pkey)]}

  (if (= (or fmt pem-form) pem-form)
    (exportPEM pkey)
    (.getEncoded ^PublicKey pkey)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn exportCert
  "" ^bytes [^X509Certificate cert & [fmt]] {:pre [(some? cert)]}

  (if (= (or fmt pem-form) pem-form) (exportPEM cert) (.getEncoded cert)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn csreq<>
  "A PKCS10 (csr-request)" {:tag APersistentVector}

  ([dnStr keylen] (csreq<> dnStr keylen nil))
  ([dnStr] (csreq<> dnStr 1024 nil))
  ([^String dnStr keylen pwd]
   {:pre [(s/hgl? dnStr)]}
   (let
     [csb (withBC1 JcaContentSignerBuilder def-algo)
      len (or keylen 1024)
      kp (asymKeyPair<> "RSA" len)
      rbr (JcaPKCS10CertificationRequestBuilder.
            (X500Principal. dnStr) (.getPublic kp))
      k (.getPrivate kp)
      rc (->> (.build csb k) (.build rbr))]
     (log/debug "csr: dnStr= %s, key-len= %d" dnStr len)
     [(exportPEM rc)
      (exportPrivateKey k pwd)])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- pemparse2
  "" [^JcaPEMKeyConverter pc obj]
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
          .getCertificateHolder
          toXCert)

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
       obj (-> (PEMParser. rdr) .readObject)]
      (->>
        (condp = (class obj)
          PKCS8EncryptedPrivateKeyInfo
          (-> ^PKCS8EncryptedPrivateKeyInfo
              obj
              (.decryptPrivateKeyInfo dp))
          PEMEncryptedKeyPair
          (->>
            (-> ^PEMEncryptedKeyPair
                obj
                (.decryptKeyPair dc))
            (.getKeyPair pc))
          obj)
        pemparse2))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn spitKeyStore
  "Write store to file"
  ^File [store fout pwd2] {:pre [(some? store)
                                 (some? fout)]}
  (let [f (io/file fout)
        out (i/baos<>)]
    (. ^KeyStore store store out (c/charsit pwd2))
    (doto f (i/writeFile (.toByteArray out)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- setKeyEntry "" ^KeyStore [store pk pwd certs]
  (doto ^KeyStore store
    (.setKeyEntry (alias<>)
                  ^PrivateKey pk (c/charsit pwd) (c/vargs Certificate certs))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- setCertEntry "" ^KeyStore [store cert]
  (doto ^KeyStore store
    (.setCertificateEntry (alias<>) ^Certificate cert)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn intoJks<>
  "Create jks store"
  ^KeyStore
  [^X509Certificate cert ^PrivateKey pk pwd certs]
  {:pre [(some? cert)(some? pk)]}

  (doto (jks<>)
     (setKeyEntry pk
                  pwd
                  (cons cert (or certs [])))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn intoPkcs12<>
  "Create pkcs12 store"
  ^KeyStore
  [^X509Certificate cert ^PrivateKey pk pwd certs]
  {:pre [(some? cert)(some? pk)]}

  (doto (pkcs12<>)
     (setKeyEntry pk
                  pwd
                  (cons cert (or certs [])))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ssv1Cert
  "Create self-signed cert, issuer is self"
  ^APersistentVector
  [{:keys [^String dnStr
           ^String algo
           ^Date start
           ^Date end
           validFor
           keylen
           style] :as args}]
  (let
    [kp (asymKeyPair<> style (or keylen 1024))
     start (or start (c/date<>))
     end (->> (or validFor 12)
              addMonths
              .getTime
              (or end ))
     prv (.getPrivate kp)
     pub (.getPublic kp)
     bdr (JcaX509v1CertificateBuilder.
           (X500Principal. dnStr)
           (nextSerial)
           start end
           (X500Principal. dnStr) pub)
     cs (-> JcaContentSignerBuilder
            (withBC1 algo *-bc-*) (.build prv))
     cert (toXCert (.build bdr cs))]
    (.checkValidity cert (c/date<>))
    (.verify cert pub)
    (log/debug (str "mkssv1cert: dn= %s "
                    ",algo= %s,start= %s"
                    ",end=%s") dnStr algo start end)
    [prv cert]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ssv1PKCS12<>
  "(root level) store" ^KeyStore [dnStr pwd args]

  (let [[pkey cert] (ssv1Cert (merge {:algo def-algo
                                      :dnStr dnStr
                                      :style "RSA"} args))]
    (intoPkcs12<> cert pkey pwd [])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ssv1JKS<>
  "(root level) store" ^KeyStore [dnStr pwd args]

  (let [[pkey cert] (ssv1Cert (merge {:algo "SHA1withDSA"
                                      :dnStr dnStr
                                      :style "DSA"} args))]
    (intoJks<> cert pkey pwd [])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ssv3Cert "SSV3 server key"
  ^APersistentVector
  [^czlab.twisty.core.PKeyGist
   issuer
   {:keys [^String dnStr
           ^String algo
           ^Date start
           ^Date end
           keylen validFor] :as args}]
  (let
    [^X509Certificate rootc (:cert issuer)
     subject (X500Principal. dnStr)
     exu (JcaX509ExtensionUtils.)
     end (->> (or validFor 12)
              addMonths
              .getTime
              (or end ))
     start (or start (c/date<>))
     len (or keylen 1024)
     kp (-> ^PrivateKey
            (:pkey issuer)
            .getAlgorithm
            (asymKeyPair<> len))
     bdr (JcaX509v3CertificateBuilder.
           rootc
           (nextSerial)
           start
           end
           subject
           (.getPublic kp))
     cs (-> (withBC1 JcaContentSignerBuilder algo *-bc-*)
            (.build (:pkey issuer)))]
    (doto bdr
      (.addExtension
        X509Extension/authorityKeyIdentifier
        false
        (.createAuthorityKeyIdentifier exu rootc))
      (.addExtension
        X509Extension/subjectKeyIdentifier
        false
        (.createSubjectKeyIdentifier exu (.getPublic kp))))
    (let [ct (toXCert (.build bdr cs))]
      (.checkValidity ct (c/date<>))
      (.verify ct (.getPublicKey rootc))
      [(.getPrivate kp) ct])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- makeSSV3
  "" [issuer ^String dnStr pwd args]

  (let [[pkey cert] (ssv3Cert issuer
                              (assoc args :dnStr dnStr))]
    [pkey cert (into [] (:chain issuer))]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn ssv3PKCS12<>
  "SSV3 type pkcs12" ^KeyStore [issuer dnStr pwd args]

  (let [[pkey cert certs] (makeSSV3 issuer
                                    dnStr
                                    pwd
                                    (merge args {:algo def-algo}))]
    (intoPkcs12<> cert pkey pwd certs)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; JKS uses SUN and hence needs to use DSA
(defn ssv3JKS<>
  "SSV3 type jks" ^KeyStore [issuer dnStr pwd args]

  (let [[pkey cert certs] (makeSSV3 issuer
                                    dnStr
                                    pwd
                                    (merge args {:algo "SHA1withDSA"}))]
    (intoJks<> cert pkey pwd certs)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn exportPkcs7 "" ^bytes [pkey]
  (let
    [xxx (CMSProcessableByteArray. (c/bytesit "?"))
     gen (CMSSignedDataGenerator.)
     cl (:chain pkey)
     bdr (->> (-> (withBC JcaDigestCalculatorProviderBuilder)
                  .build)
              JcaSignerInfoGeneratorBuilder.)
     ;;    "SHA1withRSA"
     cs (-> (withBC1 JcaContentSignerBuilder sha-512-rsa)
            (.build (:pkey pkey)))
     ^X509Certificate x509 (:cert pkey)]
    (->> (.build bdr cs x509)
         (.addSignerInfoGenerator gen ))
    (->> (JcaCertStore. cl)
         (.addCertificates gen ))
    (-> (.generate gen xxx) .getEncoded)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn exportPkcs7File
  "" ^File [pkey fout] (doto (io/file fout) (i/writeFile (exportPkcs7 pkey))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn session<>
  "Create a new java-mail session" {:tag Session}

  ([user] (session<> user nil))
  ([] (session<> nil nil))
  ([^String user pwd]
   (Session/getInstance
     (System/getProperties)
     (if (s/hgl? user)
       (->> (if pwd (c/strit pwd))
            (DefaultAuthenticator. user))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn mimeMsg<>
  "Create a new MIME Message" {:tag MimeMessage}

  ([^String user pwd ^InputStream inp]
   (let [s (session<> user pwd)]
     (if (nil? inp)
       (MimeMessage. s)
       (MimeMessage. s inp))))
  ([user pwd] (mimeMsg<> user pwd nil))
  ([inp] (mimeMsg<> "" nil inp))
  ([] (mimeMsg<> "" nil nil)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn isDataSigned?
  "Is object/message-part signed?" [obj]

  (if-some [x (i/inputStream?? obj)]
    (c/let-try [[del? inp] x]
      (->> (mimeMsg<> "" nil inp)
           .getContentType
           isSigned? )
      (finally
        (if del? (i/closeQ inp)
          (i/resetStream! inp))))
    (if-some [mp (c/cast? Multipart obj)]
      (->> (.getContentType mp) isSigned? )
      (c/throwIOE "Invalid content: %s" (c/getClassname obj)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn isDataCompressed?
  "Is object/message-part compressed?" [obj]

  (if-some [x (i/inputStream?? obj)]
    (c/let-try [[del? inp] x]
      (->> (mimeMsg<> "" nil inp)
           .getContentType
           isCompressed? )
      (finally
        (if del? (i/closeQ inp)
          (i/resetStream! inp))))
    (condp instance? obj
      Multipart (->> (c/cast? Multipart obj)
                     .getContentType
                     isCompressed? )
      BodyPart (->> (c/cast? BodyPart obj)
                    .getContentType
                    isCompressed? )
      (c/throwIOE "Invalid content: %s" (c/getClassname obj)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn isDataEncrypted?
  "Is object/message-part encrypted?" [obj]

  (if-some [x (i/inputStream?? obj)]
    (c/let-try [[del? inp] x]
      (->> (mimeMsg<> "" nil inp)
           .getContentType
           isEncrypted? )
      (finally
        (if del? (i/closeQ inp)
          (i/resetStream! inp))))
    (condp instance? obj
      Multipart (->> (c/cast? Multipart obj)
                     .getContentType
                     isEncrypted? )
      BodyPart (->> (c/cast? BodyPart obj)
                    .getContentType
                    isEncrypted? )
      (c/throwIOE "Invalid content: %s" (c/getClassname obj)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn getCharset
  "Charset from content-type" {:tag String}

  ([cType] (getCharset cType nil))
  ([^String cType ^String dft]
   (s/stror
     (if (s/hgl? cType)
       (c/try! (-> (ContentType. cType)
                 (.getParameter "charset")
                 MimeUtility/javaCharset )))
     (if (s/hgl? dft)
       (MimeUtility/javaCharset dft)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn fingerprint<>
  "Data's fingerprint" {:tag String}

  ([data] (fingerprint<> data nil))
  ([data algo]
   (str (some-> (gen-digest data algo) Hex/toHexString))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(c/decl-object CertGist)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn certGist<> "Basic info from cert"
  [^X509Certificate x509]
  (if x509
    (c/object<> CertGist
                {:issuer (.getIssuerX500Principal x509)
                 :subj (.getSubjectX500Principal x509)
                 :notBefore (.getNotBefore x509)
                 :notAfter (.getNotAfter x509)})))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn validCert?
  "" [^X509Certificate x509]
  (c/try!! false (c/do->true (.checkValidity x509 (c/date<>)) )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


