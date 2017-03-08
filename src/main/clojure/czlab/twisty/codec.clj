;; Copyright (c) 2013-2017, Kenneth Leung. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file epl-v10.html at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

(ns ^{:doc "Password Encoders & Decoders."
      :author "Kenneth Leung"}

  czlab.twisty.codec

  (:require [czlab.basal.logging :as log]
            [czlab.basal.io :refer [convBytes baos<>]])

  (:use [czlab.basal.core]
        [czlab.basal.meta]
        [czlab.basal.str])

  (:import [org.bouncycastle.crypto.params DESedeParameters KeyParameter]
           [org.bouncycastle.crypto.paddings PaddedBufferedBlockCipher]
           [java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec]
           [org.bouncycastle.crypto.generators DESedeKeyGenerator]
           [org.jasypt.encryption.pbe StandardPBEStringEncryptor]
           [org.bouncycastle.crypto KeyGenerationParameters]
           [org.apache.commons.codec.binary Base64]
           [javax.crypto.spec SecretKeySpec]
           [org.jasypt.util.text StrongTextEncryptor]
           [java.io ByteArrayOutputStream]
           [java.security Key KeyFactory SecureRandom]
           [javax.crypto Cipher]
           [czlab.twisty Cryptor IPassword]
           [czlab.jasal CU]
           [org.mindrot.jbcrypt BCrypt]
           [org.bouncycastle.crypto.engines
            BlowfishEngine
            AESEngine
            RSAEngine
            DESedeEngine]
           [org.bouncycastle.crypto.modes CBCBlockCipher]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;(set! *warn-on-reflection* true)
;; AES (128,256)
;; DES (8)
;; DESede (TripleDES - 8 x 3 = 24bytes -> 192 bits)
;; RSA  1024 +
;; Blowfish

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; DO NOT change this string as it is used by the caesar.js.  Make sure
;; you change both the front-end and back-end version of this string!
(def
  ^{:private true
    :tag "[C"}
  vis-chs
  (-> (str " @N/\\Ri2}aP`(xeT4F3mt;8~%r0v:L5$+Z{'V)\"CKIc>z.*"
           "fJEwSU7juYg<klO&1?[h9=n,yoQGsW]BMHpXb6A|D#q^_d!-")
      .toCharArray))

(def
  ^{:private true
    :tag "[C"}
  c-key (-> "ed8xwl2XukYfdgR2aAddrg0lqzQjFhbs" .toCharArray))

(def ^:private vischs-len (alength vis-chs))

(def ^:private
  s-asciiChars
  (-> (str "abcdefghijklmnopqrstuvqxyz1234567890"
           "-_ABCDEFGHIJKLMNOPQRSTUVWXYZ" )
      CU/shuffle
      .toCharArray))

(def ^:private
  s-pwdChars
  (-> (str "abcdefghijklmnopqrstuvqxyz"
           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
           "`1234567890-_~!@#$%^&*()")
      CU/shuffle
      .toCharArray))

(def ^:private ^String pwd-pfx "crypt:")
(def ^:private pwd-pfxlen 6)

;; default javax supports this
;; TripleDES
(def ^:private ^String t3-des "DESede")
(def ^:private ^String c-algo t3-des)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- ensureKeySize
  "Key has enough bits?" ^bytes [kee algo]

  (let [bits (* 8 (alength ^bytes kee))]
    (cond
      (and (= t3-des algo)
           (< bits 192)) ;; 8x 3 = 24 bytes
      (throwBadArg "TripleDES key length must be 192")
      (and (= "AES" algo)
           (< bits 128))
      (throwBadArg "AES key length must be 128 or 256")
      :else kee)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- keyAsBits
  "Sanitize the key, maybe chop length" ^bytes [pwd algo]

  (let [blen (alength ^bytes pwd)
        bits (* 8 blen)]
    (condp = algo
      "AES"
      (cond
        (> bits 256) ;; 32 bytes
        (vargs Byte/TYPE (take 32 pwd))
        ;; 128 => 16 bytes
        (and (> bits 128) (< bits 256))
        (vargs Byte/TYPE (take 16 pwd))
        :else pwd)

      t3-des
      (if (> blen 24)
        ;; 24 bytes
        (vargs Byte/TYPE (take 24 pwd))
        pwd)

      pwd)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; caesar cipher
(defmacro ^:private identCh
  "Get a character" [pos] `(aget vis-chs (int ~pos)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- locateCh
  "Locate a character" ^Integer [^Character ch]

  (-> (some #(if (= ch
                    (aget vis-chs %1))
               %1) (range vischs-len)) (or -1)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- slideForward "" [delta cpos]

  (let [ptr (+ cpos delta)]
    (-> (if (>= ptr vischs-len) (- ptr vischs-len) ptr) identCh )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- slideBack "" [delta cpos]
  (let [ptr (- cpos delta)]
    (-> (if (< ptr 0) (+ vischs-len ptr) ptr) identCh )))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- shiftenc "" [shift delta cpos]
  (if (< shift 0) (slideForward delta cpos) (slideBack delta cpos)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- shiftdec "" [shift delta cpos]
  (if (< shift 0) (slideBack delta cpos) (slideForward delta cpos)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- caesarAMapExpr
  "" ^Character [^chars ca pos shiftFunc]

  (let [ch (aget ca pos)
        p (locateCh ch)]
    (if (< p 0) ch (shiftFunc p))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn caesarEncrypt
  "Encrypt by character rotation" ^String [shiftpos ^String text]

  (if (or (szero? shiftpos)
          (nichts? text))
    text
    (let [delta (mod (Math/abs (int shiftpos)) vischs-len)
          pf (partial shiftenc shiftpos delta)
          ca (.toCharArray text)
          out (amap ca pos ret
                    (caesarAMapExpr ca pos pf))]
      (String. ^chars out))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn caesarDecrypt
  "Decrypt caesar'ed text" ^String [shiftpos ^String text]

  (if (or (szero? shiftpos)
          (nichts? text))
    text
    (let [delta (mod (Math/abs (int shiftpos)) vischs-len)
          pf (partial shiftdec shiftpos delta)
          ca (.toCharArray text)
          out (amap ca pos ret
                    (caesarAMapExpr ca pos pf))]
      (String. ^chars out))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; jasypt cryptor
(defn- jaDecr
  "Decrypt via Jasypt" ^String [pkey data]
  {:pre [(instChars? pkey)(string? data)]}

  (-> (doto (StrongTextEncryptor.)
        (.setPasswordCharArray ^chars pkey)) (.decrypt data)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- jaEncr
  "Encrypt via Jasypt" ^String [pkey data]
  {:pre [(instChars? pkey)(string? data)]}

  (-> (doto (StrongTextEncryptor.)
        (.setPasswordCharArray ^chars pkey)) (.encrypt data)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn jasyptCryptor<>
  "Cryptor via Jasypt" ^Cryptor []
  (reify Cryptor
    (decrypt [_ pkey cipherText] (jaDecr pkey cipherText))
    (encrypt [_ pkey data] (jaEncr pkey data))
    (algo [_] "PBEWithMD5AndTripleDES")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; java cryptor
(defn- getCipher
  "" ^Cipher [^bytes pkey mode ^String algo]

  (doto
    (Cipher/getInstance algo)
    (.init (int mode)
           (SecretKeySpec. (keyAsBits pkey algo) algo))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmacro java-decrypt
  ""
  {:private true :no-doc true}
  [pk algo] `(getCipher ~pk Cipher/DECRYPT_MODE ~algo))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmacro java-encrypt
  ""
  {:private true :no-doc true}
  [pk algo] `(getCipher ~pk Cipher/ENCRYPT_MODE ~algo))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- javaCodec
  "" ^bytes [pkey data ^Cipher c]

  (when-some [p (convBytes data)]
    (let
      [plen (alength p)
       baos (baos<>)
       out (->> (.getOutputSize c plen)
                (max BUF_SZ)
                byte-array)
       n (.update c p 0 plen out 0)]
      (if (> n 0)
        (.write baos out 0 n))
      (let [n2 (.doFinal c out 0)]
        (if (> n2 0)
          (.write baos out 0 n2)))
      (.toByteArray baos))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- javaEncr
  "Encrypt via Java" ^bytes [pkey data algo] {:pre [(instBytes? pkey)]}
  (when data (->> (java-encrypt pkey algo) (javaCodec pkey data))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- javaDecr
  "Decrypt via Java" ^bytes [pkey encoded algo] {:pre [(instBytes? pkey)]}
  (when encoded (->> (java-decrypt pkey algo) (javaCodec pkey encoded))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn javaCryptor<>
  "Create a java cryptor" ^Cryptor []

  (reify Cryptor

    (decrypt [this pkey cipher]
      (let [s (.algo this)]
        (ensureKeySize pkey s)
        (javaDecr pkey cipher s)))

    (encrypt [this pkey clear]
      (let [s (.algo this)]
        (ensureKeySize pkey s)
        (javaEncr pkey clear s)))

    (algo [_] t3-des)))
    ;;PBEWithMD5AndDES))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; BC cryptor
(defn- bcXrefCipherEngine "" [algo]
  (condp = algo
    "Blowfish" (BlowfishEngine.)
    "DESede" (DESedeEngine.)
    "AES" (AESEngine.)
    "RSA" (RSAEngine.)
    nil))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; 1024 - 2048 bits RSA
(defn asymEncr
  "Encrypt via a public key,
  returns a base64 encoded cipher" ^bytes [pubKey data]

  (when data
    (let
      [pubKey (convBytes pubKey)
       ^Key pk (-> (KeyFactory/getInstance "RSA")
                   (.generatePublic (X509EncodedKeySpec. pubKey)))
       cipher (doto (->> "RSA/ECB/PKCS1Padding"
                         Cipher/getInstance)
                (.init Cipher/ENCRYPT_MODE pk))]
      (->> (convBytes data)
           (.doFinal cipher )))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn asymDecr
  "Decrypt via a private key,
  input is a base64 encoded cipher" ^bytes [prvKey encoded]
  (when encoded
    (let
      [prvKey (convBytes prvKey)
       ^Key pk (-> (KeyFactory/getInstance "RSA")
                   (.generatePrivate (PKCS8EncodedKeySpec. prvKey)))
       cipher (doto (->> "RSA/ECB/PKCS1Padding"
                         Cipher/getInstance)
                (.init Cipher/DECRYPT_MODE pk))]
      (->> (convBytes encoded)
           (.doFinal cipher )))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; BC cryptor
(defn- bcDecr
  "Decrypt via BouncyCastle" ^bytes [pkey encoded algo]

  (when encoded
    (let
      [cipher (doto (-> (bcXrefCipherEngine algo)
                        CBCBlockCipher.
                        PaddedBufferedBlockCipher.)
                (.init false
                       (KeyParameter.
                         (keyAsBits pkey algo))))
       out (byte-array KiloBytes)
       p (convBytes encoded)
       baos (baos<>)
       c (.processBytes cipher p 0 (alength p) out 0)]
      (if (> c 0)
        (.write baos out 0 c))
      (let [c2 (.doFinal cipher out 0)]
        (if (> c2 0)
          (.write baos out 0 c2)))
      (.toByteArray baos))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- bcEncr
  "Encrypt via BouncyCastle,
  returning a base64 encoded cipher" ^bytes [pkey data algo]

  (when data
    (let
      [cipher (doto (-> (bcXrefCipherEngine algo)
                        CBCBlockCipher.
                        PaddedBufferedBlockCipher.)
                (.init true
                       (KeyParameter.
                         (keyAsBits pkey algo))))
       out (byte-array BUF_SZ)
       baos (baos<>)
       p (convBytes data)
       c (.processBytes cipher p 0 (alength p) out 0)]
      (if (> c 0)
        (.write baos out 0 c))
      (let [c2 (.doFinal cipher out 0)]
        (if (> c2 0)
          (.write baos out 0 c2)))
      (.toByteArray baos))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn bcastleCryptor<>
  "Create a BouncyCastle cryptor" ^Cryptor []

  (reify Cryptor

    (decrypt [this pkey cipher]
      (let [s (.algo this)]
        (ensureKeySize pkey s)
        (bcDecr pkey cipher s)))

    (encrypt [this pkey clear]
      (let [s (.algo this)]
        (ensureKeySize pkey s)
        (bcEncr pkey clear s)))

    (algo [_] t3-des)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; passwords
(defn- createXXX
  "" ^String [^chars chArray len]

  (let [alen (alength chArray)
        b Integer/MAX_VALUE
        r (rand<>)]
    (cond
      (== len 0) ""
      (< len 0) nil
      :else
      (let
        [^chars
         c
         (amap
           (char-array len)
           pos ret
           (->> (mod (.nextInt r b) alen)
                (aget chArray)))]
        (String. c)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- mkPwd
  "" [^String pwdStr ^chars pkey]

  (reify Object

    (toString [this] (.text this))
    (equals [this obj]
      (and (ist? IPassword obj)
           (= (.toString this) (str obj))))
    (hashCode [this]
      (.hashCode (str (.text this))))

    IPassword

    (toCharArray [_]
      (if (nil? pwdStr)
        (char-array 0)
        (.toCharArray pwdStr)))

    (stronglyHashed [_]
      (if (hgl? pwdStr)
        (let [s (BCrypt/gensalt 12)]
          {:hash (BCrypt/hashpw pwdStr s)
           :salt s})
        {:hash "" :salt ""}))

    (hashed [_]
      (if (hgl? pwdStr)
        (let [s (BCrypt/gensalt 10)]
          {:hash (BCrypt/hashpw pwdStr s)
           :salt s})
        {:hash "" :salt ""}))

    (validateHash [this pwdHashed]
      (BCrypt/checkpw (.text this) pwdHashed))

    (encoded [_]
      (cond
        (nil? pwdStr)
        nil
        (nichts? pwdStr)
        ""
        :else
        (str pwd-pfx (.encrypt (jasyptCryptor<>)
                               pkey
                               pwdStr))))

    (text [_] (if (hgl? pwdStr) (str pwdStr)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn passwd<>
  "Create a password object" {:tag IPassword}

  ([pwdStr] (passwd<> pwdStr nil))

  ([^String pwdStr pkey]
   {:pre [(or (nil? pkey)(instChars? pkey))]}
   (let [pkey (or pkey c-key)]
     (if
       (.startsWith (str pwdStr) pwd-pfx)
       (mkPwd
         (.decrypt (jasyptCryptor<>)
                   pkey
                   (.substring pwdStr pwd-pfxlen)) pkey)
       (mkPwd pwdStr pkey)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn randomStr
  "Generate random text"
  ^String [len] (createXXX s-asciiChars len))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn strongPasswd<>
  "Generate a strong password"
  ^IPassword [len] (passwd<> (createXXX s-pwdChars len)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF

