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
;; Copyright © 2013-2022, Kenneth Leung. All rights reserved.

(ns czlab.twisty.core

  "Crypto functions."

  (:require [clojure.java.io :as io]
            [clojure.string :as cs]
            [czlab.basal.io :as i]
            [czlab.basal.util :as u]
            [czlab.basal.core :as c]
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
(c/def- ^String def-algo "SHA1WithRSAEncryption")
(c/def- ^String def-mac "HmacSHA512")
(c/def- enc-algos
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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(def ^String sha-512-rsa "SHA512withRSA")
(def ^String sha-256-rsa "SHA256withRSA")
(def ^String sha1-rsa "SHA1withRSA")
(def ^String md5-rsa "MD5withRSA")
(def ^String blow-fish "BlowFish")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(def ^{:dynamic true
       :tag Provider} *-bc-* (BouncyCastleProvider.))
(Security/addProvider *-bc-*)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(c/defenum exform 1 pem der)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defrecord CertGist [issuer subj notBefore notAfter])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defrecord PKeyGist [chain cert pkey])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn alias<>

  "A new random name."
  {:tag String
   :arglists '([])}
  []

  (format "%s#%04d" (-> (u/jid<>) (subs 0 6)) (u/seqint)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn pkcs12<>

  "Create a PKCS12 key store."
  {:tag KeyStore
   :arglists '([])}
  []

  (doto
    (KeyStore/getInstance "PKCS12" *-bc-*) (.load nil nil)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn jks<>

  "Create a JKS key store."
  {:tag KeyStore
   :arglists '([])}
  []

  (doto
    (KeyStore/getInstance
      "JKS" (Security/getProvider "SUN")) (.load nil nil)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn x->keystore<>

  "Create a key store from input."
  {:tag KeyStore
   :arglists '([c pk pwd certs]
               [c pk pwd certs options])}

  ([c pk pwd certs]
   (x->keystore<> c pk pwd certs nil))

  ([cert pk pwd certs options]
   (let [{:keys [ktype]
          :or {ktype :pkcs12}} options]
     (doto (if (= :jks ktype) (jks<>) (pkcs12<>))
       (.setKeyEntry (alias<>)
                     ^PrivateKey pk
                     (i/x->chars pwd)
                     (c/vargs Certificate
                              (cons cert (or certs []))))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn asym-key-pair*

  "Generate a KeyPair."
  {:tag KeyPair
   :arglists '([algo]
               [algo keylen])}

  ([algo]
   (asym-key-pair* algo nil))

  ([algo keylen]
   {:pre [(string? algo)]}
   (let [len (c/num?? keylen 1024)]
     (-> (doto
           (KeyPairGenerator/getInstance ^String algo *-bc-*)
           (.initialize (int len) (u/rand<> true)))
         .generateKeyPair))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn asym-key-pair<>

  "Generate a public & private key."
  {:arglists '([algo]
               [algo keylen])}

  ([algo] (asym-key-pair<> algo nil))

  ([algo keylen]
   (let [kp (asym-key-pair* algo keylen)]
     [(.getPublic kp) (.getPrivate kp)])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn is-encrypted?

  "Does content-type indicate *encrypted*?"
  {:arglists '([s])}
  [s]
  {:pre [(string? s)]}

  (c/if-some+ [ct (c/lcase s)]
    (and (c/embeds? ct "enveloped-data")
         (c/embeds? ct "application/x-pkcs7-mime"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn is-compressed?

  "Does content-type indicate *compressed*?"
  {:arglists '([s])}
  [s]
  {:pre [(string? s)]}

  (c/if-some+ [ct (c/lcase s)]
    (and (c/embeds? ct "compressed-data")
         (c/embeds? ct "application/pkcs7-mime"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn is-signed?

  "Does content-type indicate *signed*?"
  {:arglists '([s])}
  [s]
  {:pre [(string? s)]}

  (c/if-some+ [ct (c/lcase s)]
    (or (c/embeds? ct "multipart/signed")
        (and (c/embeds? ct "signed-data")
             (c/embeds? ct "application/x-pkcs7-mime")))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn assert-jce

  "This function should fail if the
  non-restricted (unlimited-strength)
  jce files are missing in jre-home.
  **** Not needed after jdk10+"
  {:arglists '([])}
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

  "BC as provider - part of ctor(arg)."
  {:arglists '([cz p1]
               [cz p1 pv])}

  ([cz p1]
   `(with-BC1 ~cz ~p1 nil))

  ([cz p1 pv]
   `(-> (new ~cz ~p1)
        (.setProvider (or ~pv czlab.twisty.core/*-bc-*)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmacro with-BC

  "BC as provider - part of ctor."
  {:arglists '([cz]
               [cz pv])}

  ([cz]
   `(with-BC ~cz nil))

  ([cz pv]
   `(-> (new ~cz)
        (.setProvider (or ~pv czlab.twisty.core/*-bc-*)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- to-xcert

  ^X509Certificate
  [^X509CertificateHolder h]

  (-> JcaX509CertificateConverter with-BC (.getCertificate h)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- pemencr<>

  ^PEMEncryptor
  [^chars pwd]

  (if-not (empty? pwd)
    (-> (->> (rand-nth (seq enc-algos))
             (with-BC1 JcePEMEncryptorBuilder ))
        (.setSecureRandom (u/rand<>)) (.build pwd))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn is-jks?

  "Is url pointing to a JKS key file?"
  {:arglists '([keyUrl])}
  [keyUrl]

  (some-> keyUrl io/as-url .getFile c/lcase (cs/ends-with? ".jks")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn msg-digest<>

  "Get a message digest instance:
  MD5, SHA-1, SHA-256, SHA-384, SHA-512."
  {:arglists '([algo])
   :tag MessageDigest}
  [algo]

  (-> algo c/kw->str c/ucase
      (c/stror "SHA-512")
      (MessageDigest/getInstance *-bc-*)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn next-serial

  "A random Big Integer."
  {:arglists '([])
   :tag BigInteger}
  []

  (BigInteger/valueOf
    (Math/abs (-> (Random. (u/system-time)) .nextLong))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn dbg-provider

  "List all BC algos."
  {:arglists '([os])}
  [os]

  (c/try! (.list *-bc-* ^PrintStream os)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- ksinit

  "Initialize a keystore."
  [^KeyStore store arg pwd2]

  (let [[d? inp]
        (i/input-stream?? arg)]
    (try (.load store
                ^InputStream inp
                (i/x->chars pwd2))
         (finally (if d? (i/klose inp)))) store))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmulti pkey-gist<>

  "Create a PKeyGist object."
  {:arglists '([arg _ _])} (fn [a _ _] (class a)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmethod pkey-gist<>

  PrivateKey
  [pkey cert listOfCerts]

  (PKeyGist. (c/vec-> listOfCerts) cert pkey))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmethod pkey-gist<>

  KeyStore
  [ks alias pwd]

  (if-some [e (->> pwd
                   i/x->chars
                   KeyStore$PasswordProtection.
                   (.getEntry ^KeyStore ks
                              ^String alias)
                   (c/cast? KeyStore$PrivateKeyEntry))]
    (pkey-gist<> (.getPrivateKey e)
                 (.getCertificate e)
                 (.getCertificateChain e))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn spit-keystore

  "Write keystore out to file."
  {:tag File
   :arglists '([ks fout pwd2])}
  [ks fout pwd2]
  {:pre [(c/is? KeyStore ks)]}

  (let [out (i/baos<>)]
    (.store ^KeyStore ks
            out (i/x->chars pwd2))
    (i/x->file (i/x->bytes out) (io/file fout))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn tcert<>

  "Get a trusted certificate from store."
  {:tag Certificate
   :arglists '([ks alias])}
  [ks alias]
  {:pre [(c/is? KeyStore ks)]}

  (if-some
    [e (->> (.getEntry ^KeyStore ks
                       ^String alias nil)
            (c/cast? KeyStore$TrustedCertificateEntry))]
    (.getTrustedCertificate e)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn filter-entries

  "Select entries from the store."
  {:arglists '([ks entryType])}
  [ks entryType]
  {:pre [(c/is? KeyStore ks)]}

  (loop [out (c/tvec*)
         en (.aliases ^KeyStore ks)]
    (if-not (.hasMoreElements en)
      (c/persist! out)
      (let [n (.nextElement en)]
        (recur (if (cond
                     (= :keys entryType)
                     (.isKeyEntry ^KeyStore ks n)
                     (= :certs entryType)
                     (.isCertificateEntry ^KeyStore ks n))
                 (conj! out n) out) en)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn pkcs12*

  "Create and initialize a PKCS12 key store."
  {:tag KeyStore
   :arglists '([arg]
               [arg pwd2])}

  ([arg]
   (pkcs12* arg nil))

  ([arg pwd2]
   (ksinit (pkcs12<>) arg pwd2)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn jks*

  "Create and initialize a JKS key store."
  {:tag KeyStore
   :arglists '([arg]
               [arg pwd2])}

  ([arg]
   (jks* arg nil))

  ([arg pwd2]
   (ksinit (jks<>) arg pwd2)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn spit-pem

  "Export object out in PEM format."
  {:tag String
   :arglists '([obj]
               [obj pwd])}

  ([obj]
   (spit-pem obj nil))

  ([obj pwd]
   (c/do-with-str [sw (StringWriter.)]
     (let [pw (PEMWriter. sw)
           ec (pemencr<> ^chars pwd)]
       (.writeObject pw
                     (if (nil? ec)
                       (JcaMiscPEMGenerator. obj)
                       (JcaMiscPEMGenerator. obj ec)))
       (.flush pw)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn spit-der

  "Export object out in DER format."
  {:tag "[B"
   :arglists '([obj])}
  [obj]

  (c/condp?? instance? obj
    PrivateKey (.getEncoded ^PrivateKey obj)
    PublicKey (.getEncoded ^PublicKey obj)
    X509Certificate (.getEncoded ^X509Certificate obj)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn x->certs

  "Parse input and generate a cert chain."
  {:arglists '([arg])}
  [arg]

  (let [[d? inp]
        (i/input-stream?? arg)]
    (try (-> (CertificateFactory/getInstance "X.509")
             (.generateCertificates ^InputStream inp))
         (finally (if d? (i/klose inp))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn x->cert

  "Parse input and generate a cert."
  {:arglists '([arg])}
  [arg]

  (let [[d? inp]
        (i/input-stream?? arg)]
    (try (-> (CertificateFactory/getInstance "X.509")
             (.generateCertificate ^InputStream inp))
         (finally (if d? (i/klose inp))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn x->pkey

  "Parse input and generate a PKeyGist object."
  {:arglists '([arg pwd]
               [arg pwd pwdStore])}

  ([arg pwd]
   (x->pkey arg pwd nil))

  ([arg pwd pwdStore]
   (let [ks (pkcs12* arg pwdStore)]
     (c/if-some+
       [n (c/_1
            (filter-entries ks :keys))]
       (pkey-gist<> ks n pwd)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn easy-policy<>

  "Enables all permissions."
  {:tag Policy
   :arglists '([])}
  []

  (proxy [Policy] []
    (getPermissions [cs]
      (doto (Permissions.) (.add (AllPermission.))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn gen-mac

  "Create Message Auth Code."
  {:tag String
   :arglists '([skey data]
               [skey data algo])}

  ([skey data]
   (gen-mac skey data nil))

  ([skey data algo]
   {:pre [(some? skey) (some? data)]}
   (let
     [algo (-> algo c/kw->str
               c/ucase (c/stror def-mac))
      flag (c/mu-long)
      mac (Mac/getInstance algo *-bc-*)]
     (->> (SecretKeySpec.
            (i/x->bytes skey) algo) (.init mac))
     (i/chunk-read-stream data
                          (fn [buf offset len end?]
                            (when (pos? len)
                              (c/mu-long flag + len)
                              (.update mac buf offset len))))
     (str (some->
            (if (c/spos?
                  (c/mu-long flag)) (.doFinal mac)) Hex/toHexString)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- gen-digest*

  [data algo]

  (let [flag (c/mu-long)
        d (msg-digest<> algo)]
    (i/chunk-read-stream data
                         (fn [buf offset len end?]
                           (when (pos? len)
                             (c/mu-long flag + len)
                             (.update d buf offset len))))
    (if (c/spos? (c/mu-long flag)) (.digest d))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn gen-digest

  "Create Message Digest."
  {:tag String
   :arglists '([data]
               [data options])}

  ([data]
   (gen-digest data nil))

  ([data options]
   (let [{:keys [algo fmt]
          :or {fmt :base64}} options
         x (gen-digest* data algo)]
     (str
       (if x
         (if (= fmt :hex)
           (Hex/toHexString x)
           (Base64/toBase64String x)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- scert<>

  "Sign a cert, issuer is self is nil."

  ([args]
   (scert<> nil args))

  ([{^PrivateKey pkey :pkey
     ^X509Certificate rootc :cert :as issuer}
    {:keys [^String dn algo
            start end
            validity keylen style]
     :or {style "RSA" keylen 1024} :as args}]
   (let [^Date end (or end (-> (or validity 12)
                               d/add-months .getTime))
         ^Date start (or start (u/date<>))
         subject (X500Principal. dn)
         [^PublicKey pub ^PrivateKey prv]
         (asym-key-pair<> (or (some->
                                pkey .getAlgorithm) style) keylen)
         [^JcaX509ExtensionUtils exu bdr]
         (if issuer
           [(JcaX509ExtensionUtils.)
            (JcaX509v3CertificateBuilder.
              rootc (next-serial) start end subject pub)]
          [nil (JcaX509v1CertificateBuilder.
                 (X500Principal. dn)
                 (next-serial) start end subject pub)])
         cs (->> (if issuer pkey prv)
                 (.build (with-BC1 JcaContentSignerBuilder algo *-bc-*)))]
     (if issuer
       (doto ^JcaX509v3CertificateBuilder bdr
         (.addExtension
           X509Extension/authorityKeyIdentifier false
           (.createAuthorityKeyIdentifier exu rootc))
         (.addExtension
           X509Extension/subjectKeyIdentifier false
           (.createSubjectKeyIdentifier exu pub))))
     (try
       [prv
        (doto (to-xcert (if issuer
                          (.build ^JcaX509v3CertificateBuilder bdr cs)
                          (.build ^JcaX509v1CertificateBuilder bdr cs)))
          (.checkValidity (u/date<>))
          (.verify (if issuer (.getPublicKey rootc) pub)))]
       (finally
         (c/debug (str "signed-cert: dn= %s "
                       ",algo= %s,start= %s" ",end=%s") dn algo start end))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn gen-cert

  "Create a Certificate from the DN."
  {:tag KeyStore
   :arglists '([dnStr pwd args]
               [dnStr issuer pwd args])}

  ([dnStr pwd args]
   (gen-cert dnStr nil pwd args))

  ([dnStr issuer pwd args]
   (let [{:keys [ktype]} args
         ;; JKS uses SUN and hence needs to use DSA
         [pkey cert]
         (scert<> issuer
                  (merge (if (not= :jks ktype)
                           {:algo def-algo}
                           {:style "DSA" :algo "SHA1withDSA"})
                         {:dn dnStr} args))]
     (x->keystore<> cert pkey pwd
                    (if issuer
                      (c/vec-> (:chain issuer)) []) args))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn csreq<>

  "Generate a Certificate Signing Request."
  {:arglists '([dnStr]
               [dnStr keylen]
               [dnStr keylen pwd])}

  ([dnStr keylen]
   (csreq<> dnStr keylen nil))

  ([dnStr]
   (csreq<> dnStr 1024 nil))

  ([dnStr keylen pwd]
   {:pre [(string? dnStr)]}
   (let [csb (with-BC1 JcaContentSignerBuilder def-algo)
         len (c/num?? keylen 1024)
         [pu pv] (asym-key-pair<> "RSA" len)
         rbr (JcaPKCS10CertificationRequestBuilder.
               (X500Principal. ^String dnStr) ^PublicKey pu)
         rc (->> (.build csb pv) (.build rbr))]
     (c/debug "csr: dnStr= %s, key-len= %d" dnStr len)
     [(spit-pem rc)
      (spit-pem pv pwd)])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- pemparse2

  [obj ^JcaPEMKeyConverter pc]

  (condp = (class obj)
    PEMKeyPair
    (.getKeyPair pc ^PEMKeyPair obj)
    KeyPair obj
    PrivateKeyInfo
    (.getPrivateKey pc ^PrivateKeyInfo obj)
    ContentInfo obj
    X509AttributeCertificateHolder
    (to-xcert obj)
    X509TrustedCertificateBlock
    (-> ^X509TrustedCertificateBlock obj .getCertificateHolder to-xcert)
    SubjectPublicKeyInfo
    (.getPublicKey pc ^SubjectPublicKeyInfo obj)
    X509CertificateHolder
    (to-xcert obj)
    X509CRLHolder obj
    PKCS10CertificationRequest obj
    obj))

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

  (c/wo* [rdr (InputStreamReader. inp)]
    (let [obj (-> (PEMParser. rdr) .readObject)
          pc (with-BC JcaPEMKeyConverter)
          dc (.build (JcePEMDecryptorProviderBuilder.) pwd)
          dp (.build (BcPKCS12PBEInputDecryptorProviderBuilder.) pwd)]
      (pemparse2 (condp = (class obj)
                   PKCS8EncryptedPrivateKeyInfo
                   (-> ^PKCS8EncryptedPrivateKeyInfo obj
                       (.decryptPrivateKeyInfo dp))
                   PEMEncryptedKeyPair
                   (->> (-> ^PEMEncryptedKeyPair obj
                            (.decryptKeyPair dc))
                        (.getKeyPair pc))
                   obj)
                 pc))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn is-cert-valid?

  "Test if cert is valid?"
  {:arglists '([c])}
  [c]

  (c/try! (.checkValidity ^X509Certificate c (u/date<>)) true))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn cert-gist<>

  "Create a gist from the cert."
  {:arglists '([c])}
  [c]
  {:pre [(c/is? X509Certificate c)]}

  (let [x509 (c/cast? X509Certificate c)]
    (CertGist. (.getIssuerX500Principal x509)
               (.getSubjectX500Principal x509)
               (.getNotBefore x509)
               (.getNotAfter x509))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn spit-pkcs7

  "Generate PKCS7 from the private-key."
  {:tag "[B"
   :arglists '([pkeyGist])}
  [pkeyGist]

  (let [xxx (CMSProcessableByteArray. (i/x->bytes "?"))
        gen (CMSSignedDataGenerator.)
        {:keys [^X509Certificate cert
                ^PrivateKey pkey chain]} pkeyGist
        bdr (JcaSignerInfoGeneratorBuilder.
              (.build (with-BC JcaDigestCalculatorProviderBuilder)))
        ;;    "SHA1withRSA"
        cs (.build (with-BC1 JcaContentSignerBuilder sha-512-rsa) pkey)]
    (.addSignerInfoGenerator gen (.build bdr cs cert))
    (.addCertificates gen (JcaCertStore. chain))
    (.getEncoded (.generate gen xxx))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn session<>

  "Create a new java-mail session."
  {:tag Session
   :arglists '([]
               [user]
               [user pwd])}

  ([user]
   (session<> user nil))

  ([]
   (session<> nil nil))

  ([user pwd]
   (Session/getInstance
     (System/getProperties)
     (if (c/hgl? user)
       (->> (if pwd (i/x->str pwd))
            (DefaultAuthenticator. ^String user))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn mime-msg<>

  "Create a new MIME Message."
  {:tag MimeMessage
   :arglists '([]
               [inp]
               [user pwd]
               [user pwd inp])}

  ([^String user pwd ^InputStream inp]
   (let [s (session<> user pwd)]
     (if (nil? inp)
       (MimeMessage. s)
       (MimeMessage. s inp))))

  ([inp]
   (mime-msg<> "" nil inp))

  ([]
   (mime-msg<> "" nil nil))

  ([user pwd]
   (mime-msg<> user pwd nil)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- is-data-xxx?

  [obj tst?]

  (if-some [[d? inp] (i/input-stream?? obj)]
    (try (tst? (.getContentType
                 (mime-msg<> "" nil inp)))
         (finally (if d? (i/klose inp))))
    (condp instance? obj
      Multipart (tst? (.getContentType (c/cast? Multipart obj)))
      BodyPart (tst? (.getContentType (c/cast? BodyPart obj)))
      (u/throw-IOE "Invalid content: %s." (u/gczn obj)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn is-data-encrypted?

  "Test if object is *encrypted*?"
  {:arglists '([obj])}
  [obj]

  (is-data-xxx? obj is-encrypted?))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn is-data-signed?

  "Test if object is *signed*?"
  {:arglists '([obj])}
  [obj]

  (is-data-xxx? obj is-signed?))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn is-data-compressed?

  "Test if object is *compressed*?"
  {:arglists '([obj])}
  [obj]

  (is-data-xxx? obj is-compressed?))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn charset??

  "Charset from content-type."
  {:tag String
   :arglists '([cType]
               [cType dft])}

  ([cType]
   (charset?? cType nil))

  ([cType dft]
   (c/stror
     (if (c/hgl? cType)
       (c/try! (-> (ContentType. ^String cType)
                   (.getParameter "charset")
                   MimeUtility/javaCharset )))
     (if (c/hgl? dft)
       (MimeUtility/javaCharset ^String dft)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


