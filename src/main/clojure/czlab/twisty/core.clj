;; Copyright © 2013-2019, Kenneth Leung. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file epl-v10.html at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

(ns ^{:doc "Crypto functions."
      :author "Kenneth Leung"}

  czlab.twisty.core

  (:require [czlab.basal.core :as c]
            [czlab.basal.util :as u]
            [clojure.java.io :as io]
            [clojure.string :as cs]
            [czlab.basal.log :as l]
            [czlab.basal.io :as i]
            [czlab.basal.str :as s]
            [czlab.basal.dates :as d])

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
           [java.lang Math]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;(set! *warn-on-reflection* true)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(c/defenum exform pem 1 der)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defprotocol ContentTypeChecker ""
  (is-encrypted? [_] "")
  (is-signed? [_] "")
  (is-compressed? [_] ""))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(extend-protocol ContentTypeChecker
  String
  (is-encrypted? [me]
    (let [ct (s/lcase me)]
      (and (s/embeds? ct "enveloped-data")
           (s/embeds? ct "application/x-pkcs7-mime"))))
  (is-signed? [me]
    (let [ct (s/lcase me)]
      (or (s/embeds? ct "multipart/signed")
          (and (s/embeds? ct "signed-data")
               (s/embeds? ct "application/x-pkcs7-mime")))))
  (is-compressed? [me]
    (let [ct (s/lcase me)]
      (and (s/embeds? ct "compressed-data")
           (s/embeds? ct "application/pkcs7-mime")))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn assert-jce
  "This function should fail if the non-restricted (unlimited-strength)
   jce files are **not** placed in jre-home.  Not needed after jdk10+"
  []
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
        (.doFinal (i/x->bytes "yo")))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(def ^:dynamic ^Provider *-bc-* (BouncyCastleProvider.))
(Security/addProvider *-bc-*)
(assert-jce)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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
(defmacro with-BC1
  "BC as provider - part of ctor(arg)"
  ([cz p1] `(with-BC1 ~cz ~p1 nil))
  ([cz p1 pv]
   `(-> (new ~cz ~p1)
        (.setProvider (or ~pv ~'czlab.twisty.core/*-bc-*)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmacro with-BC
  "BC as provider - part of ctor"
  ([cz] `(with-BC ~cz nil))
  ([cz pv]
   `(-> (new ~cz)
        (.setProvider (or ~pv ~'czlab.twisty.core/*-bc-*)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- to-xcert
  ^X509Certificate [^X509CertificateHolder h]
  (-> JcaX509CertificateConverter with-BC (.getCertificate h)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- pemencr<>
  ^PEMEncryptor [^chars pwd]
  (if-not (empty? pwd)
    (-> (->> (rand-nth (vec enc-algos))
             (with-BC1 JcePEMEncryptorBuilder ))
        (.setSecureRandom (u/rand<>)) (.build pwd))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn is-jks?
  "Is url pointing to a JKS key file?" [keyUrl]
  (some-> keyUrl io/as-url .getFile s/lcase (.endsWith ".jks")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn msg-digest<>
  "Get a message digest instance:
  MD5
  SHA-1, SHA-256, SHA-384, SHA-512"
  ^MessageDigest
  [algo]
  (-> (s/ucase (s/kw->str algo))
      (s/stror "SHA-512")
      (MessageDigest/getInstance *-bc-*)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn next-serial
  "A random Big Integer" ^BigInteger []
  (BigInteger/valueOf (Math/abs (-> (Random. (u/system-time)) .nextLong))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn dbg-provider
  "List all BC algos"
  {:no-doc true} [^PrintStream os] (c/try! (.list *-bc-* os)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn alias<>
  "A new random name" ^String []
  (format "%s#%04d" (-> (u/jid<>) (.substring 0 4)) (u/seqint)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defrecord PKeyGist [chain cert pkey])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmulti pkey-gist<> "" (fn [a _ _] (class a)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmethod pkey-gist<> PrivateKey
  [pkey cert listOfCerts]
  (PKeyGist. (c/vec-> listOfCerts) ^Certificate cert pkey))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmethod pkey-gist<> KeyStore
  [^KeyStore store ^String alias pwd]
  {:pre [(s/hgl? alias)]}
  (if-some [e (->> (KeyStore$PasswordProtection. (i/x->chars pwd))
                   (.getEntry store alias)
                   (c/cast? KeyStore$PrivateKeyEntry))]
    (pkey-gist<> (.getPrivateKey e)
                 (.getCertificate e)
                 (.getCertificateChain e))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn tcert<>
  "Get cert from store"
  ^Certificate [store alias]
  {:pre [(some? store)]}
  (if-some [e (->> (.getEntry ^KeyStore store ^String alias nil)
                   (c/cast? KeyStore$TrustedCertificateEntry))]
    (.getTrustedCertificate e)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn filter-entries
  "Enumerate entries in the key-store"
  [^KeyStore store entryType]
  {:pre [(some? store)
         (keyword? entryType)]}
  (loop [en (.aliases store) rc (c/tvec*)]
    (if-not (.hasMoreElements en)
      (c/ps! rc)
      (let [n (.nextElement en)]
        (if (cond
              (= :certs entryType)
              (.isCertificateEntry store n)
              (= :keys entryType)
              (.isKeyEntry store n))
          (recur en (conj! rc n)) (recur en rc))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- init-keystore
  "Initialize the key-store."
  ^KeyStore [^KeyStore store arg pwd2]
  {:pre [(some? store)]}
  (let [[del? inp]
        (i/input-stream?? arg)]
    (try (.load store
                ^InputStream inp
                (i/x->chars pwd2))
         store
      (finally (if del? (i/klose inp))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn pkcs12<>
  "Create a PKCS12 key-store."
  {:tag KeyStore}
  ([arg] (pkcs12<> arg nil))
  ([] (pkcs12<> nil nil))
  ([arg pwd2]
   (-> (KeyStore/getInstance "PKCS12" *-bc-*)
       (init-keystore arg pwd2))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn jks<>
  "Create a JKS key-store."
  {:tag KeyStore}
  ([arg] (jks<> arg nil))
  ([] (jks<> nil nil))
  ([arg pwd2]
   (-> (->> (Security/getProvider "SUN")
            (KeyStore/getInstance "JKS"))
       (init-keystore arg pwd2))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn x->certs
  "To a set of Certs (p7b)." [arg]
  (let [[del? inp]
        (i/input-stream?? arg)]
    (try (-> (CertificateFactory/getInstance "X.509")
             (.generateCertificates ^InputStream inp))
         (finally (if del? (i/klose inp))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn x->cert
  "To a Certificate." ^Certificate [arg]
  (let [[del? inp]
        (i/input-stream?? arg)]
    (try (-> (CertificateFactory/getInstance "X.509")
             (.generateCertificate ^InputStream inp))
         (finally (if del? (i/klose inp))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn x->pkey
  "To a Private Key"
  ([arg pwd] (x->pkey arg pwd nil))
  ([arg pwd pwdStore]
   (let [ks (pkcs12<> arg pwdStore)]
     (c/if-some+
       [n (c/_1 (filter-entries ks :keys))] (pkey-gist<> ks n pwd)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn easy-policy<>
  "Enables all permissions" ^Policy []
  (proxy [Policy] []
    (getPermissions [cs]
      (doto (Permissions.) (.add (AllPermission.))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn gen-mac
  "Create Message Auth Code"
  {:tag String}
  ([skey data] (gen-mac skey data nil))
  ([skey data algo]
   {:pre [(some? skey) (some? data)]}
   (let
     [algo (-> (s/kw->str algo)
               s/ucase
               (s/stror def-mac))
      flag (c/long-var)
      mac (Mac/getInstance algo *-bc-*)]
     (->> (SecretKeySpec.
            (i/x->bytes skey) algo) (.init mac))
     (i/chunk-read-stream data
                          (fn [buf offset len end?]
                            (when (pos? len)
                              (c/long-var flag + len)
                              (.update mac buf offset len))))
     (str (some->
            (if (c/spos?
                  (c/long-var flag)) (.doFinal mac)) Hex/toHexString)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- gen-digest* [data algo]
  (let [flag (c/long-var)
        d (msg-digest<> algo)]
    (i/chunk-read-stream data
                         (fn [buf offset len end?]
                           (when (pos? len)
                             (c/long-var flag + len)
                             (.update d buf offset len))))
    (if (c/spos? (c/long-var flag)) (.digest d))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn gen-digest
  "Create Message Digest"
  {:tag String}
  ([data] (gen-digest data nil))
  ([data options]
   (let [{:keys [algo fmt]
          :or {fmt :base64}} options]
     (if-some [x (gen-digest* data algo)]
       (if (= fmt :hex)
         (Hex/toHexString x)
         (Base64/toBase64String x)) ""))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn asym-key-pair<>
  "Create a Asymmetric key-pair"
  {:tag KeyPair}
  ([algo] (asym-key-pair<> algo nil))
  ([^String algo keylen]
   (let [len (c/num?? keylen 1024)]
     (l/debug "gen keypair for algo %s, len %d." algo len)
     (-> (doto (KeyPairGenerator/getInstance algo *-bc-*)
               (.initialize (int len) (u/rand<> true)))
         .generateKeyPair ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn spit-pem
  "Export object in base64 format."
  {:tag String}
  ([obj] (spit-pem obj nil))
  ([obj pwd]
   (let [ec (pemencr<> ^chars pwd)
         sw (StringWriter.)
         pw (PEMWriter. sw)]
     (when obj
       (.writeObject pw
                     (if ec
                       (JcaMiscPEMGenerator. obj ec)
                       (JcaMiscPEMGenerator. obj)))
       (.flush pw)
       (str sw)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn spit-der
  "Export object in binary format." ^bytes [obj]
  (c/condp?? instance? obj
     PrivateKey (.getEncoded ^PrivateKey obj)
     PublicKey (.getEncoded ^PublicKey obj)
     X509Certificate (.getEncoded ^X509Certificate obj)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn csreq<>
  "A PKCS10 (csr-request)."
  ([dnStr keylen] (csreq<> dnStr keylen nil))
  ([dnStr] (csreq<> dnStr 1024 nil))
  ([dnStr keylen pwd]
   {:pre [(s/hgl? dnStr)]}
   (let
     [csb (with-BC1 JcaContentSignerBuilder def-algo)
      len (c/num?? keylen 1024)
      kp (asym-key-pair<> "RSA" len)
      rbr (JcaPKCS10CertificationRequestBuilder.
            (X500Principal. ^String dnStr) (.getPublic kp))
      k (.getPrivate kp)
      rc (->> (.build csb k) (.build rbr))]
     (l/debug "csr: dnStr= %s, key-len= %d" dnStr len)
     [(spit-pem rc)
      (spit-pem k pwd)])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- pemparse2
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
      (to-xcert obj)

      X509TrustedCertificateBlock
      (-> ^X509TrustedCertificateBlock obj
          .getCertificateHolder
          to-xcert)

      SubjectPublicKeyInfo
      (.getPublicKey pc ^SubjectPublicKeyInfo obj)

      X509CertificateHolder
      (to-xcert obj)

      X509CRLHolder
      obj

      PKCS10CertificationRequest
      obj

      obj)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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
       pc (with-BC JcaPEMKeyConverter)
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
(defn spit-keystore
  "Write store to file"
  ^File [store fout pwd2]
  {:pre [(some? store)
         (some? fout)]}
  (let [out (i/baos<>)]
    (. ^KeyStore store store out (i/x->chars pwd2))
    (i/x->file (i/x->bytes out) (io/file fout))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn x->keystore<>
  "Create a KeyStore from cert, default = pkcs12."
  ^KeyStore
  ([cert pk pwd certs] (x->keystore<> cert pk pwd certs nil))
  ([cert pk pwd certs options]
   {:pre [(some? cert)(some? pk)]}
   (let [{:keys [ktype] :or {ktype :pkcs12}} options]
     (doto (if (= :jks ktype) (jks<>) (pkcs12<>))
       (.setKeyEntry (alias<>)
                     ^PrivateKey pk
                     (i/x->chars pwd)
                     (c/vargs Certificate
                              (cons cert (or certs []))))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- scert<>
  "Sign a cert, issuer is self is nil."
  ([args] (scert<> nil args))
  ([{^PrivateKey pkey :pkey
     ^X509Certificate rootc :cert :as issuer}
    {:keys [^String dn algo start end validity keylen style]
     :or {style "RSA" keylen 1024} :as args}]

   (let [^Date end (or end (-> (or validity 12) d/add-months .getTime))
         ^Date start (or start (u/date<>))
         kp (asym-key-pair<> (or (some->
                                   pkey .getAlgorithm) style) keylen)
         subject (X500Principal. dn)
         prv (.getPrivate kp)
         pub (.getPublic kp)
         [^JcaX509ExtensionUtils exu bdr]
         (if issuer
           [(JcaX509ExtensionUtils.)
            (JcaX509v3CertificateBuilder.
              rootc (next-serial) start end subject pub)]
          [nil (JcaX509v1CertificateBuilder.
                 (X500Principal. dn)
                 (next-serial) start end subject pub)])
         cs (->> (if issuer pkey prv)
                 (.build (with-BC1 JcaContentSignerBuilder algo *-bc-*)))
         _ (if issuer
             (doto ^JcaX509v3CertificateBuilder bdr
               (.addExtension
                 X509Extension/authorityKeyIdentifier false
                 (.createAuthorityKeyIdentifier exu rootc))
               (.addExtension
                 X509Extension/subjectKeyIdentifier false
                 (.createSubjectKeyIdentifier exu pub))))
         cert (-> (if issuer
                    (.build ^JcaX509v3CertificateBuilder bdr cs)
                    (.build ^JcaX509v1CertificateBuilder bdr cs)) (to-xcert))]
     (.checkValidity cert (u/date<>))
     (.verify cert (if issuer (.getPublicKey rootc) pub))
     (try
       [prv cert]
       (finally
         (l/debug (str "signed-cert: dn= %s "
                       ",algo= %s,start= %s" ",end=%s") dn algo start end))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn gen-cert
  "" {:tag KeyStore}

  ([dnStr pwd args] (gen-cert nil dnStr pwd args))
  ([issuer dnStr pwd args]
   (let [{:keys [ktype]} args
         ;; JKS uses SUN and hence needs to use DSA
         [pkey cert]
         (scert<> issuer
                  (merge (if (not= :jks ktype)
                           {:algo def-algo}
                           {:style "DSA"
                            :algo "SHA1withDSA"})
                         {:dn dnStr} args))]
     (x->keystore<> cert pkey pwd
                    (if issuer (c/vec-> (:chain issuer)) []) args))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn spit-pkcs7
  "" ^bytes [pkeyGist]
  (let [xxx (CMSProcessableByteArray. (i/x->bytes "?"))
        gen (CMSSignedDataGenerator.)
        {:keys [^X509Certificate cert
                ^PrivateKey pkey chain]} pkeyGist
        bdr (->> (.build (with-BC JcaDigestCalculatorProviderBuilder))
                 JcaSignerInfoGeneratorBuilder.)
        ;;    "SHA1withRSA"
        cs (.build (with-BC1 JcaContentSignerBuilder sha-512-rsa) pkey)]
    (.addSignerInfoGenerator gen
                             (.build bdr cs cert))
    (.addCertificates gen (JcaCertStore. chain))
    (.getEncoded (.generate gen xxx))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn session<>
  "Create a new java-mail session"
  {:tag Session}
  ([user] (session<> user nil))
  ([] (session<> nil nil))
  ([user pwd]
   (Session/getInstance
     (System/getProperties)
     (if (s/hgl? user)
       (->> (if pwd (i/x->str pwd))
            (DefaultAuthenticator. ^String user))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn mime-msg<>
  "Create a new MIME Message"
  {:tag MimeMessage}
  ([^String user pwd ^InputStream inp]
   (let [s (session<> user pwd)]
     (if (nil? inp)
       (MimeMessage. s)
       (MimeMessage. s inp))))
  ([user pwd] (mime-msg<> user pwd nil))
  ([inp] (mime-msg<> "" nil inp))
  ([] (mime-msg<> "" nil nil)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- is-data-xxx? [obj tst?]
  (if-some [[del? inp] (i/input-stream?? obj)]
    (try (tst? (.getContentType
                 (mime-msg<> "" nil inp)))
         (finally (if del? (i/klose inp))))
    (condp instance? obj
      Multipart (tst? (.getContentType (c/cast? Multipart obj)))
      BodyPart (tst? (.getContentType (c/cast? BodyPart obj)))
      (u/throw-IOE "Invalid content: %s." (u/gczn obj)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defprotocol DataTypeChecker ""
  (is-data-compressed? [_] "")
  (is-data-signed? [_] "")
  (is-data-encrypted? [_] ""))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(extend-protocol DataTypeChecker
  Object
  (is-data-encrypted? [me] (is-data-xxx? me is-encrypted?))
  (is-data-signed? [me] (is-data-xxx? me is-signed?))
  (is-data-compressed? [me] (is-data-xxx? me is-compressed?)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn charset??
  "Charset from content-type"
  {:tag String}
  ([cType] (charset?? cType nil))
  ([^String cType ^String dft]
   (s/stror
     (if (s/hgl? cType)
       (c/try! (-> (ContentType. cType)
                 (.getParameter "charset")
                 MimeUtility/javaCharset )))
     (if (s/hgl? dft)
       (MimeUtility/javaCharset dft)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defrecord CertGist [issuer subj notBefore notAfter])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmulti cert-gist<> "" (fn [a] (class a)))
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmethod cert-gist<> X509Certificate
  [^X509Certificate x509]
  (CertGist. (.getIssuerX500Principal x509)
             (.getSubjectX500Principal x509)
             (.getNotBefore x509)
             (.getNotAfter x509)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn is-cert-valid?
  "If cert is valid?" [x509]
  (c/try! (.checkValidity ^X509Certificate x509 (u/date<>)) true))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


