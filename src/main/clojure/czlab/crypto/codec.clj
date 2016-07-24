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

  (:require
    [czlab.xlib.meta :refer [charsClass bytesClass]]
    [czlab.xlib.str :refer [stror hgl?]]
    [czlab.xlib.core
     :refer [srandom<>
             bytesify
             stringify
             throwBadArg]]
    [czlab.xlib.logging :as log]
    [czlab.xlib.io :refer [baos<>]])

  (:use [czlab.xlib.consts])

  (:import
    [org.bouncycastle.crypto.params DESedeParameters KeyParameter]
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
    [czlab.crypto Cryptor PasswordAPI]
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
  ^:private
  VISCHS
  (->
    (CU/shuffle (str " @N/\\Ri2}aP`(xeT4F3mt;8~%r0v:L5$+Z{'V)\"CKIc>z.*"
                     "fJEwSU7juYg<klO&1?[h9=n,yoQGsW]BMHpXb6A|D#q^_d!-"))
    (.toCharArray)))

(def ^:private ^String C_KEY "ed8xwl2XukYfdgR2aAddrg0lqzQjFhbs" )
(def ^:private VISCHS_LEN (alength ^chars VISCHS))

(def
  ^:private
  s_asciiChars
  (-> (CU/shuffle (str "abcdefghijklmnopqrstuvqxyz1234567890"
                       "-_ABCDEFGHIJKLMNOPQRSTUVWXYZ" ))
      (.toCharArray)))

(def
  ^:private
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

  "Given an algo, make sure the key has enough bits"
  ^bytes
  [^bytes kkey ^String algo]

  (let [bits (* 8 (alength kkey))]
    (when (and (= T3_DES algo)
               (< bits 192)) ;; 8x 3 = 24 bytes
      (throwBadArg "TripleDES key length must be 192"))
    (when (and (= "AES" algo)
               (< bits 128))
      (throwBadArg "AES key length must be 128 or 256"))
    kkey))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- keyAsBits

  "Given the algo, sanitize the key, chop length if necessary"
  ^bytes
  [^bytes pwd ^String algo]

  (let [blen (alength pwd)
        bits (* 8 blen)]
    (condp = algo
      "AES"
      (cond
        (> bits 256) ;; 32 bytes
        (into-array Byte/TYPE (take 32 pwd))
        ;; 128 => 16 bytes
        (and (> bits 128) (< bits 256))
        (into-array Byte/TYPE (take 16 pwd))
        :else pwd)

      T3_DES
      (if (> blen 24)
        ;; 24 bytes
        (into-array Byte/TYPE (take 24 pwd))
        pwd)

      pwd)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; caesar cipher
(defn- identCh

  "Lookup a character by the given index"
  ^Character
  [pos]

  (aget ^chars VISCHS ^long pos))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- locateCh

  "Given a character, return the index"
  ^long
  [^Character ch]

  (-> (some #(if (= ch (aget ^chars VISCHS %1))
               %1 nil)
            (range VISCHS_LEN))
      (or -1)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- slideForward

  ""
  [delta cpos]

  (let [ptr (+ cpos delta)]
    (-> (if (>= ptr VISCHS_LEN) (- ptr VISCHS_LEN) ptr)
        (identCh ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- slideBack

  ""
  [delta cpos]

  (let [ptr (- cpos delta)]
    (-> (if (< ptr 0) (+ VISCHS_LEN ptr) ptr)
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
    (if (< p 0)
      ch
      (shiftFunc p))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn caesarEncrypt

  "Encrypt clear text by character rotation"
  ^String
  [^String text shiftpos]

  (if (or (== shiftpos 0)
          (empty? text))
    text
    (let [delta (mod (Math/abs (int shiftpos)) VISCHS_LEN)
          pf (partial shiftenc shiftpos delta)
          ca (.toCharArray text)
          out (amap ca pos ret
                    (caesarAMapExpr ca pos pf)) ]
      (String. ^chars out))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn caesarDecrypt

  "Decrypt text which was encrypted by the caesar method"
  ^String
  [^String text shiftpos]

  (if (or (== shiftpos 0)
          (empty? text))
    text
    (let [delta (mod (Math/abs (int shiftpos)) VISCHS_LEN)
          pf (partial shiftdec shiftpos delta)
          ca (.toCharArray text)
          out (amap ca pos ret
                    (caesarAMapExpr ca pos pf)) ]
      (String. ^chars out))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; jasypt cryptor
(defn- jaDecr

  "Decrypt using Jasypt"
  ^String
  [pkey data]
  {:pre [(= (charsClass) (class pkey))
         (instance? String data)]}

  (-> (doto (StrongTextEncryptor.)
            (.setPasswordCharArray ^chars pkey))
      (.decrypt data)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- jaEncr

  "Encrypt using Jasypt"
  ^String
  [pkey data]
  {:pre [(= (charsClass) (class pkey))
         (instance? String data)]}

  (-> (doto (StrongTextEncryptor.)
            (.setPasswordCharArray ^chars pkey))
      (.encrypt data)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn jasypt<>

  "Make a cryptor using Jasypt lib"
  ^Cryptor
  []

  (reify

    Cryptor

    (decrypt [_ pkey cipherText]
      (jaDecr pkey cipherText))

    (encrypt [_ pkey data]
      (jaEncr pkey data))

    (algo [_] "PBEWithMD5AndTripleDES")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; java cryptor
(defn- getCipher

  ""
  ^Cipher
  [^bytes pkey mode ^String algo]

  (doto (Cipher/getInstance algo)
        (.init (int mode)
               (SecretKeySpec. (keyAsBits pkey algo) algo))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmacro java-decrypt

  ""
  {:private true :no-doc true}
  [pk algo]

  `(getCipher ~pk Cipher/DECRYPT_MODE ~algo))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmacro java-encrypt

  ""
  {:private true :no-doc true}
  [pk algo]

  `(getCipher ~pk Cipher/ENCRYPT_MODE ~algo))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- javaEncr

  "Encrypt using Java"
  ^bytes
  [pkey data ^String algo]
  {:pre [(= (bytesClass) (class pkey))]}

  (when-not (empty? data)
    (let [c (java-encrypt pkey algo)
          ^bytes
          p (if (string? data)
              (bytesify data)
              data)
          plen (alength p)
          baos (byteOS)
          out (->> (.getOutputSize c plen)
                   (max BUF_SZ)
                   (byte-array ))
          n (.update c p 0 plen out 0)]
      (when (> n 0)
        (.write baos out 0 n))
      (let [n2 (.doFinal c out 0)]
        (when (> n2 0)
          (.write baos out 0 n2)))
      (.toByteArray baos))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- javaDecr

  "Decrypt using Java"
  ^bytes
  [pkey encoded ^String algo]
  {:pre [(= (bytesClass) (class pkey))]}

  (when-not (empty? encoded)
    (let [c (java-decrypt pkey algo)
          ^bytes
          p (if (string? encoded)
              (bytesify encoded)
              encoded)
          plen (alength p)
          baos (byteOS)
          out (->> (.getOutputSize c plen)
                   (max BUF_SZ)
                   (byte-array ))
          n (.update c p 0 plen out 0)]
      (when (> n 0)
        (.write baos out 0 n))
      (let [n2 (.doFinal c out 0)]
        (when (> n2 0)
          (.write baos out 0 n2)))
      (.toByteArray baos))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn javaCryptor<>

  "Make a Standard Java cryptor"
  ^Cryptor
  []

  (reify

    Cryptor

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
  [^String algo]

  (condp = algo
    "Blowfish" (BlowfishEngine.)
    "DESede" (DESedeEngine.)
    "AES" (AESEngine.)
    "RSA" (RSAEngine.)
    nil))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; 1024 - 2048 bits RSA
(defn asymEncr

  "Encrypt using a public key, returns a base64 encoded cipher"
  ^bytes
  [^bytes pubKey data]

  (when-not (empty? data)
    (let [^Key pk (-> (KeyFactory/getInstance "RSA")
                      (.generatePublic (X509EncodedKeySpec. pubKey)))
          cipher (doto (Cipher/getInstance "RSA/ECB/PKCS1Padding")
                       (.init Cipher/ENCRYPT_MODE pk)) ]
      (->> ^bytes
           (if (string? data)
             (bytesify  data)
             data)
           (.doFinal cipher )))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn asymDecr

  "Decrypt using a private key, input is a base64 encoded cipher"
  ^bytes
  [^bytes prvKey encoded]

  (when-not (empty? encoded)
    (let [^Key pk (-> (KeyFactory/getInstance "RSA")
                      (.generatePrivate (PKCS8EncodedKeySpec. prvKey)))
          cipher (doto (Cipher/getInstance "RSA/ECB/PKCS1Padding")
                   (.init Cipher/DECRYPT_MODE pk))]
      (->> ^bytes
           (if (string? encoded)
             (bytesify encoded)
             encoded)
           (.doFinal cipher )))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; BC cryptor
(defn- bcDecr

  "Decrypt using BouncyCastle"
  ^bytes
  [pkey encoded ^String algo]

  (when-not (empty? encoded)
    (let [cipher (doto (-> (bcXrefCipherEngine algo)
                           (CBCBlockCipher. )
                           (PaddedBufferedBlockCipher. ))
                   (.init false
                          (KeyParameter. (keyAsBits pkey algo))))
          ^bytes
          p (if (string? encoded)
              (bytesify encoded)
              encoded)
          out (byte-array KiloBytes)
          baos (byteOS)
          c (.processBytes cipher p 0 (alength p) out 0)]
      (when (> c 0)
        (.write baos out 0 c))
      (let [c2 (.doFinal cipher out 0)]
        (when (> c2 0)
          (.write baos out 0 c2)))
      (.toByteArray baos))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- bcEncr

  "Encrypt using BouncyCastle, returning a base64 encoded cipher"
  ^bytes
  [pkey data ^String algo]

  (when-not (empty? data)
    (let [cipher (doto (-> (bcXrefCipherEngine algo)
                           (CBCBlockCipher. )
                           (PaddedBufferedBlockCipher. ))
                   (.init true
                          (KeyParameter. (keyAsBits pkey algo))))
          out (byte-array BUF_SZ)
          baos (byteOS)
          ^bytes
          p (if (string? data)
              (bytesify data)
              data)
          c (.processBytes cipher p 0 (alength p) out 0)]
      (when (> c 0)
        (.write baos out 0 c))
      (let [c2 (.doFinal cipher out 0)]
        (when (> c2 0)
          (.write baos out 0 c2)))
      (.toByteArray baos))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn bcastle<>

  "Make a cryptor using BouncyCastle"
  ^Cryptor
  []

  (reify

    Cryptor

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
  [^chars chArray len]

  (cond
    (== len 0) ""
    (< len 0) nil
    :else
    (let [ostr (char-array len)
          cl (alength chArray)
          r (srandom<>)
          rc (amap ^chars ostr
               pos
               ret
               (let [n (mod (.nextInt r Integer/MAX_VALUE) cl) ]
                 (aget chArray n))) ]
      (String. ^chars rc))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- reifyPassword

  ""
  [^String pwdStr ^String pkey]

  (reify

    Object

    (toString [this] (.text this))

    (equals [this obj]
      (and (instance? PasswordAPI obj)
           (= (.toString this)
              (str obj))) )

    (hashCode [this]
      (.hashCode (str (.text this))))

    PasswordAPI

    (toCharArray [_]
      (if (nil? pwdStr)
        (char-array 0)
        (.toCharArray pwdStr)))

    (stronglyHashed [_]
      (if-not (nil? pwdStr)
        (let [s (BCrypt/gensalt 12) ]
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
        (empty? pwdStr)
        ""
        :else
        (str PWD_PFX (.encrypt (jasypt<>)
                               (.toCharArray pkey)
                               pwdStr))))

    (text [_] (when-not (empty? pwdStr) (str pwdStr) )) ))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn passwd<>

  "Create a password object"
  ^PasswordAPI
  [^String pwdStr & [pkey]]

  {:pre [(or (nil? pwdStr)(string? pwdStr))
         (or (nil? pkey)(string? pkey))]}

  (let [^String pkey (stror pkey C_KEY)]
    (if
      (.startsWith (str pwdStr) PWD_PFX)
      (reifyPassword
        (.decrypt (jasypt<>)
                  (.toCharArray pkey)
                  (.substring pwdStr PWD_PFXLEN)) pkey)
      ;else
      (reifyPassword pwdStr pkey))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn randomStr

  "Randomly generate some text"
  ^String
  [len]

  (createXXX  s_asciiChars len))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn strongPwd

  "Generate a strong password"
  ^PasswordAPI
  [len]

  (passwd<> (createXXX  s_pwdChars len)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


