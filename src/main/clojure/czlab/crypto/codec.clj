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

(ns ^{:doc "Password Encoders & Decoders."
      :author "Kenneth Leung" }

  czlab.crypto.codec

  (:require [czlab.xlib.logging :as log]
            [czlab.xlib.io :refer [baos<>]])

  (:use [czlab.xlib.consts]
        [czlab.xlib.core]
        [czlab.xlib.meta]
        [czlab.xlib.str])

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
           [czlab.crypto Cryptor IPassword]
           [czlab.xlib CU]
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
;;
(def
  ^{:private true
    :tag (charsClass)}
  VISCHS
  (->
    (CU/shuffle (str " @N/\\Ri2}aP`(xeT4F3mt;8~%r0v:L5$+Z{'V)\"CKIc>z.*"
                     "fJEwSU7juYg<klO&1?[h9=n,yoQGsW]BMHpXb6A|D#q^_d!-"))
    (.toCharArray)))

(def ^:private ^String C_KEY "ed8xwl2XukYfdgR2aAddrg0lqzQjFhbs")
(def ^:private VISCHS_LEN (alength VISCHS))

(def
  ^{:private true
    :tag (charsClass)}
  s_asciiChars
  (-> (CU/shuffle (str "abcdefghijklmnopqrstuvqxyz1234567890"
                       "-_ABCDEFGHIJKLMNOPQRSTUVWXYZ" ))
      (.toCharArray)))

(def
  ^{:private true
    :tag (charsClass) }
  s_pwdChars
  (-> (CU/shuffle (str "abcdefghijklmnopqrstuvqxyz"
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       "`1234567890-_~!@#$%^&*()" ))
      (.toCharArray)))

(def ^:private ^String PWD_PFX "crypt:" )
(def ^:private PWD_PFXLEN 6)

;; default javax supports this
;; TripleDES
(def ^:private ^String T3_DES "DESede" )
(def ^:private ^String C_ALGO T3_DES)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- ensureKeySize
  "Make sure the key has enough bits"
  ^bytes
  [^bytes kee algo]
  (let [bits (* 8 (alength kee))]
    (cond
      (and (= T3_DES algo)
           (< bits 192)) ;; 8x 3 = 24 bytes
      (throwBadArg "TripleDES key length must be 192")
      (and (= "AES" algo)
           (< bits 128))
      (throwBadArg "AES key length must be 128 or 256")
      :else kee)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- keyAsBits
  "Sanitize the key, maybe chop length"
  ^bytes
  [^bytes pwd algo]
  (let [blen (alength pwd)
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

      T3_DES
      (if (> blen 24)
        ;; 24 bytes
        (vargs Byte/TYPE (take 24 pwd))
        pwd)

      pwd)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; caesar cipher
(defmacro ^:private identCh
  "Get a character" [pos] `(aget VISCHS (int ~pos)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- locateCh
  "Locate a character"
  ^Integer
  [^Character ch]
  (-> (some #(if (= ch (aget VISCHS %1)) %1) (range VISCHS_LEN)) (or -1)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- slideForward
  ""
  [delta cpos]
  (let [ptr (+ cpos delta)]
    (-> (if (>= ptr VISCHS_LEN)
          (- ptr VISCHS_LEN) ptr)
        (identCh ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- slideBack
  ""
  [delta cpos]
  (let [ptr (- cpos delta)]
    (-> (if (< ptr 0)
          (+ VISCHS_LEN ptr) ptr)
        (identCh ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- shiftenc
  ""
  [shiftpos delta cpos]
  (if (< shiftpos 0)
    (slideForward delta cpos)
    (slideBack delta cpos)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- shiftdec
  ""
  [shiftpos delta cpos]
  (if (< shiftpos 0)
    (slideBack delta cpos)
    (slideForward delta cpos)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- caesarAMapExpr
  ""
  ^Character
  [^chars ca pos shiftFunc]
  (let [ch (aget ca pos)
        p (locateCh ch)]
    (if (< p 0) ch (shiftFunc p))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn caesarEncrypt
  "Encrypt clear text by character rotation"
  ^String
  [shiftpos ^String text]
  (if (or (== shiftpos 0)
          (nichts? text))
    text
    (let [delta (mod (Math/abs (int shiftpos)) VISCHS_LEN)
          pf (partial shiftenc shiftpos delta)
          ca (.toCharArray text)
          out (amap ca pos ret
                    (caesarAMapExpr ca pos pf))]
      (String. ^chars out))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn caesarDecrypt
  "Decrypt text which was encrypted by the caesar method"
  ^String
  [shiftpos ^String text]
  (if (or (== shiftpos 0)
          (nichts? text))
    text
    (let [delta (mod (Math/abs (int shiftpos)) VISCHS_LEN)
          pf (partial shiftdec shiftpos delta)
          ca (.toCharArray text)
          out (amap ca pos ret
                    (caesarAMapExpr ca pos pf))]
      (String. ^chars out))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; jasypt cryptor
(defn- jaDecr
  "Decrypt using Jasypt"
  ^String
  [pkey data]
  {:pre [(instChars? pkey)(string? data)]}
  (-> (doto
        (StrongTextEncryptor.)
        (.setPasswordCharArray ^chars pkey))
      (.decrypt data)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- jaEncr
  "Encrypt using Jasypt"
  ^String
  [pkey data]
  {:pre [(instChars? pkey)(string? data)]}
  (-> (doto
        (StrongTextEncryptor.)
        (.setPasswordCharArray ^chars pkey))
      (.encrypt data)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn jasyptCryptor<>
  "Cryptor using Jasypt lib"
  ^Cryptor
  []
  (reify Cryptor
    (decrypt [_ pkey cipherText] (jaDecr pkey cipherText))
    (encrypt [_ pkey data] (jaEncr pkey data))
    (algo [_] "PBEWithMD5AndTripleDES")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; java cryptor
(defn- getCipher
  ""
  ^Cipher
  [^bytes pkey mode ^String algo]
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
(defn- coerce
  ""
  ^bytes
  [obj]
  (cond
    (string? obj) (bytesify obj)
    (instBytes? obj) obj
    (nil? obj) nil
    :else (throwBadArg "bad type %s" (class obj))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- javaCodec
  ""
  ^bytes
  [pkey data ^Cipher c]
  (when-some [p (coerce data)]
    (let
      [plen (alength p)
       baos (baos<>)
       out (->> (.getOutputSize c plen)
                (max BUF_SZ)
                (byte-array))
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
  "Encrypt using Java"
  ^bytes
  [pkey data algo]
  {:pre [(instBytes? pkey)]}
  (when (some? data)
    (->> (java-encrypt pkey algo)
         (javaCodec pkey data))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- javaDecr
  "Decrypt using Java"
  ^bytes
  [pkey encoded algo]
  {:pre [(instBytes? pkey)]}
  (when (some? encoded)
    (->> (java-decrypt pkey algo)
         (javaCodec pkey encoded))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn javaCryptor<>
  "Make a Standard Java cryptor"
  ^Cryptor
  []
  (reify Cryptor

    (decrypt [this pkey cipher]
      (let [s (.algo this)]
        (ensureKeySize pkey s)
        (javaDecr pkey cipher s)))

    (encrypt [this pkey clear]
      (let [s (.algo this)]
        (ensureKeySize pkey s)
        (javaEncr pkey clear s)))

    (algo [_] T3_DES)))
    ;;PBEWithMD5AndDES))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; BC cryptor
(defn- bcXrefCipherEngine
  ""
  [algo]
  (condp = algo
    "Blowfish" (BlowfishEngine.)
    "DESede" (DESedeEngine.)
    "AES" (AESEngine.)
    "RSA" (RSAEngine.)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; 1024 - 2048 bits RSA
(defn asymEncr
  "Encrypt using a public key, returns a base64 encoded cipher"
  ^bytes
  [^bytes pubKey data]
  (when (some? data)
    (let
      [^Key pk (-> (KeyFactory/getInstance "RSA")
                   (.generatePublic
                     (X509EncodedKeySpec. pubKey)))
       cipher (doto (->> "RSA/ECB/PKCS1Padding"
                         (Cipher/getInstance))
                    (.init Cipher/ENCRYPT_MODE pk))]
      (->> (coerce data)
           (.doFinal cipher )))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn asymDecr
  "Decrypt using a private key, input is a base64 encoded cipher"
  ^bytes
  [^bytes prvKey encoded]
  (when (some? encoded)
    (let
      [^Key pk (-> (KeyFactory/getInstance "RSA")
                   (.generatePrivate
                     (PKCS8EncodedKeySpec. prvKey)))
       cipher (doto (->> "RSA/ECB/PKCS1Padding"
                         (Cipher/getInstance ))
                   (.init Cipher/DECRYPT_MODE pk))]
      (->> (coerce encoded)
           (.doFinal cipher )))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; BC cryptor
(defn- bcDecr
  "Decrypt using BouncyCastle"
  ^bytes
  [pkey encoded algo]
  (when (some? encoded)
    (let
      [cipher (doto (-> (bcXrefCipherEngine algo)
                        (CBCBlockCipher. )
                        (PaddedBufferedBlockCipher. ))
                (.init false
                       (KeyParameter.
                         (keyAsBits pkey algo))))
       out (byte-array KiloBytes)
       p (coerce encoded)
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
  "Encrypt using BouncyCastle, returning a base64 encoded cipher"
  ^bytes
  [pkey data algo]
  (when (some? data)
    (let
      [cipher (doto (-> (bcXrefCipherEngine algo)
                        (CBCBlockCipher. )
                        (PaddedBufferedBlockCipher. ))
                (.init true
                       (KeyParameter.
                         (keyAsBits pkey algo))))
       out (byte-array BUF_SZ)
       baos (baos<>)
       p (coerce data)
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
  "Make a cryptor using BouncyCastle"
  ^Cryptor
  []
  (reify Cryptor

    (decrypt [this pkey cipher]
      (let [s (.algo this)]
        (ensureKeySize pkey s)
        (bcDecr pkey cipher s)))

    (encrypt [this pkey clear]
      (let [s (.algo this)]
        (ensureKeySize pkey s)
        (bcEncr pkey clear s)))

    (algo [_] T3_DES)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; passwords
(defn- createXXX
  ""
  ^String
  [^chars chArray len]
  (cond
    (== len 0) ""
    (< len 0) nil
    :else
    (let
      [^chars c
       (amap
         (char-array len)
         pos ret
         (->> (alength chArray)
              (mod (->> Integer/MAX_VALUE
                        (.nextInt (rand<>) )))
              (aget chArray)))]
      (String. c))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- mkPwd
  ""
  [^String pwdStr ^String pkey]
  (reify Object

    (toString [this] (.text this))
    (equals [this obj]
      (and (inst? IPassword obj)
           (= (.toString this)
              (str obj))))
    (hashCode [this]
      (.hashCode (str (.text this))))

    IPassword

    (toCharArray [_]
      (if (nil? pwdStr)
        (char-array 0)
        (.toCharArray pwdStr)))

    (stronglyHashed [_]
      (if-not (nil? pwdStr)
        (let [s (BCrypt/gensalt 12)]
          {:hash (BCrypt/hashpw pwdStr s)
           :salt s})
        {:hash "" :salt ""}))

    (hashed [_]
      (if-not (nil? pwdStr)
        (let [s (BCrypt/gensalt 10) ]
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
        (str PWD_PFX (.encrypt (jasyptCryptor<>)
                               (.toCharArray pkey)
                               pwdStr))))

    (text [_] (if (hgl? pwdStr) (str pwdStr)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn passwd<>
  "Create a password object"
  {:tag IPassword}

  ([pwdStr] (passwd<> pwdStr nil))

  ([^String pwdStr pkey]
   {:pre [(or (nil? pkey)(string? pkey))]}
   (let [pkey (stror pkey C_KEY)]
     (if
       (.startsWith (str pwdStr) PWD_PFX)
       (mkPwd
         (.decrypt (jasyptCryptor<>)
                   (.toCharArray pkey)
                   (.substring pwdStr PWD_PFXLEN)) pkey)
       (mkPwd pwdStr pkey)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn randomStr
  "Generate random text"
  ^String [len] (createXXX s_asciiChars len))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn strongPwd<>
  "Generate a strong password"
  ^IPassword [len] (passwd<> (createXXX s_pwdChars len)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


