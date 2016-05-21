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

  czlab.crypto.codec

  (:require
    [czlab.xlib.meta :refer [charsClass bytesClass]]
    [czlab.xlib.core
     :refer [newRandom
             bytesify stringify throwBadArg]]
    [clojure.math.numeric-tower :as math]
    [czlab.xlib.logging :as log]
    [czlab.xlib.io :refer [byteOS]])

  (:import
    [org.bouncycastle.crypto.params DESedeParameters KeyParameter]
    [org.bouncycastle.crypto.paddings PaddedBufferedBlockCipher]
    [org.bouncycastle.crypto.generators DESedeKeyGenerator]
    [org.jasypt.encryption.pbe StandardPBEStringEncryptor]
    [org.apache.commons.codec.binary Base64]
    [org.apache.commons.lang3.tuple ImmutablePair]
    [javax.crypto.spec SecretKeySpec]
    [org.jasypt.util.text StrongTextEncryptor]
    [java.io ByteArrayOutputStream]
    [java.security Key KeyFactory SecureRandom]
    [java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec]
    [javax.crypto Cipher]
    [czlab.crypto Cryptor PasswordAPI]
    [org.mindrot.jbcrypt BCrypt]
    [org.bouncycastle.crypto KeyGenerationParameters]
    [org.bouncycastle.crypto.engines
     BlowfishEngine
     AESEngine RSAEngine DESedeEngine]
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
;;(def ^:private ACHS "abcdefghijklmnopqrstuvqxyz1234567890-_ABCDEFGHIJKLMNOPQRSTUVWXYZ" )
;;(def ^:private PCHS "abcdefghijklmnopqrstuvqxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`1234567890-_~!@#$%^&*()" )

(def ^:private ^chars
  VISCHS (.toCharArray (str " @N/\\Ri2}aP`(xeT4F3mt;8~%r0v:L5$+Z{'V)\"CKIc>z.*"
                            "fJEwSU7juYg<klO&1?[h9=n,yoQGsW]BMHpXb6A|D#q^_d!-")))
(def ^:private VISCHS_LEN (alength ^chars VISCHS))

(def ^:private ^String
  PCHS (str "Ha$4Jep8!`g)GYkmrIRN72^cObZ%oXlSPT39qLMD&"
            "iC*UxKWhE#F5@qvV6j0f1dyBs-~tAQn(z_u" ))
(def ^:private ^String
  ACHS "nhJ0qrIz6FmtPCduWoS9x8vT2-KMaO7qlgApVX5_keyZDjfE13UsibYRGQ4NcLBH" )

(def ^:private ^chars s_asciiChars (.toCharArray ACHS))
(def ^:private ^chars s_pwdChars (.toCharArray PCHS))

(def ^:private ^String PWD_PFX "CRYPT:" )
(def ^:private PWD_PFXLEN (.length PWD_PFX))

(def ^:private ^String C_KEY "ed8xwl2XukYfdgR2aAddrg0lqzQjFhbs" )
(def ^:private ^String T3_DES "DESede" ) ;; TripleDES
(def ^:private ^chars C_KEYCS (.toCharArray C_KEY))
(def ^:private ^bytes C_KEYBS (bytesify C_KEY))

(def ^:private ^String C_ALGO T3_DES) ;; default javax supports this
;;(def ^:private ALPHA_CHS 26)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- ensureKeySize

  "Given an algo, make sure the key has enough bits"

  ^bytes
  [^bytes keyBits ^String algo]

  (let [len (* 8 (alength keyBits))]
    (when (and (= T3_DES algo)
               (< len 192)) ;; 8x 3 = 24 bytes
      (throwBadArg "TripleDES key length must be 192."))
    (when (and (= "AES" algo)
               (< len 128))
      (throwBadArg "AES key length must be 128 or 256."))
    keyBits))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- keyAsBits

  "Given the algo, sanitize the key, chop length if necessary"

  ^bytes
  [^bytes pwd ^String algo]

  (let [blen (alength pwd)
        len (* 8 blen) ]
    (condp = algo
      "AES"
      (cond
        (> len 256) ;; 32 bytes
        (into-array Byte/TYPE (take 32 pwd))
        ;; 128 => 16 bytes
        (and (> len 128) (< len 256))
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
(defn- identify-ch

  "Lookup a character by the given index"

  ^Character
  [pos]

  (aget ^chars VISCHS ^long pos))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- locate-ch

  "Given a character, return the index"

  ^long
  [^Character ch]

  (-> (some #(if (= ch (aget ^chars VISCHS %1)) %1 nil)
                  (range VISCHS_LEN))
      (or -1)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- slide-forward ""

  ^Character
  [delta cpos]

  (let [ptr (+ cpos delta)]
    (->> (if (>= ptr VISCHS_LEN) (- ptr VISCHS_LEN) ptr)
         (identify-ch ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- slide-back ""

  ^Character
  [delta cpos]

  (let [ptr (- cpos delta)]
    (->> (if (< ptr 0) (+ VISCHS_LEN ptr) ptr)
         (identify-ch ))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- shiftenc ""

  ^Character
  [shiftpos delta cpos]

  (if (< shiftpos 0)
    (slide-forward delta cpos)
    (slide-back delta cpos)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- shiftdec ""

  ^Character
  [shiftpos delta cpos]

  (if (< shiftpos 0)
    (slide-back delta cpos)
    (slide-forward delta cpos)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- caesar-amap-expr ""

  ^Character
  [^chars ca pos shiftFunc]

  (let [ch (aget ca pos)
        p (locate-ch ch) ]
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
    (let [delta (mod (math/abs shiftpos) VISCHS_LEN)
          ca (.toCharArray text)
          pf (partial shiftenc shiftpos delta)
          out (amap ca pos ret
                    (caesar-amap-expr ca pos pf)) ]
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
    (let [delta (mod (math/abs shiftpos) VISCHS_LEN)
          ca (.toCharArray text)
          pf (partial shiftdec shiftpos delta)
          out (amap ca pos ret
                    (caesar-amap-expr ca pos pf)) ]
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
(defn jasyptCryptor

  "Make a cryptor using Jasypt lib"

  ^Cryptor
  []

  (reify

    Cryptor

    (decrypt [_ pkey cipher]
      (jaDecr pkey cipher))

    (encrypt [_ pkey data]
      (jaEncr pkey data))

    (algo [_] "PBEWithMD5AndTripleDES")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; java cryptor
(defn- getCipher

  "Given an algo, create a Java Cipher instance"

  ^Cipher
  [^bytes pkey mode ^String algo]

  (doto (Cipher/getInstance algo)
        (.init (int mode)
               (SecretKeySpec. (keyAsBits pkey algo) algo))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- javaEncr

  "Encrypt using Java"

  ^bytes
  [pkey data ^String algo]

  {:pre [(= (bytesClass) (class pkey))]}

  (if (empty? data)
    nil
    (let [c (getCipher pkey Cipher/ENCRYPT_MODE algo)
          ^bytes
          p (if (string? data)
              (bytesify data)
              data)
          plen (alength p)
          baos (byteOS)
          out (byte-array (max 4096 (.getOutputSize c plen)))
          n (.update c p 0 plen out 0) ]
      (when (> n 0) (.write baos out 0 n))
      (let [n2 (.doFinal c out 0) ]
        (when (> n2 0) (.write baos out 0 n2)))
        (.toByteArray baos))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- javaDecr

  "Decrypt using Java"

  ^bytes
  [pkey encoded ^String algo]

  {:pre [(= (bytesClass) (class pkey))]}

  (if (empty? encoded)
    nil
    (let [c (getCipher pkey Cipher/DECRYPT_MODE algo)
          ^bytes
          p (if (string? encoded)
              (bytesify encoded)
              encoded)
          plen (alength p)
          baos (byteOS)
          out (byte-array (max 4096 (.getOutputSize c plen)))
          n (.update c p 0 plen out 0)]
      (when (> n 0) (.write baos out 0 n))
      (let [n2 (.doFinal c out 0) ]
        (when (> n2 0) (.write baos out 0 n2)))
      (.toByteArray baos))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn javaCryptor

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
(defn- bcXrefCipherEngine ""

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

  (if (empty? data)
    nil
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

  (if (empty? encoded)
    nil
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
(defn bcDecr

  "Decrypt using BouncyCastle"

  ^bytes
  [pkey encoded ^String algo]

  (if (empty? encoded)
    nil
    (let [cipher (doto (-> (bcXrefCipherEngine algo)
                           (CBCBlockCipher. )
                           (PaddedBufferedBlockCipher. ))
                   (.init false
                          (KeyParameter. (keyAsBits pkey algo))))
          ^bytes
          p (if (string? encoded)
              (bytesify encoded)
              encoded)
          out (byte-array 1024)
          baos (byteOS)
          c (.processBytes cipher p 0 (alength p) out 0) ]
      (when (> c 0) (.write baos out 0 c))
      (let [c2 (.doFinal cipher out 0) ]
        (when (> c2 0) (.write baos out 0 c2)))
        (.toByteArray baos))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn bcEncr

  "Encrypt using BouncyCastle, returning a base64 encoded cipher"

  ^bytes
  [pkey data ^String algo]

  (if (empty? data)
    nil
    (let [cipher (doto (-> (bcXrefCipherEngine algo)
                           (CBCBlockCipher. )
                           (PaddedBufferedBlockCipher. ))
                   (.init true
                          (KeyParameter. (keyAsBits pkey algo))))
          out (byte-array 4096)
          baos (byteOS)
          ^bytes
          p (if (string? data)
              (bytesify data)
              data)
          c (.processBytes cipher p 0 (alength p) out 0) ]
      (when (> c 0) (.write baos out 0 c))
      (let [c2 (.doFinal cipher out 0) ]
        (when (> c2 0) (.write baos out 0 c2)) )
        (.toByteArray baos))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn bouncyCryptor

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
(defn- createXXX ""

  [len ^chars chArray]

  (cond
    (== len 0) ""
    (< len 0) nil
    :else
    (let [ostr (char-array len)
          cl (alength chArray)
          r (newRandom)
          rc (amap ^chars ostr pos ret
                    (let [n (mod (.nextInt r Integer/MAX_VALUE) cl) ]
                      (aget chArray n))) ]
      (String. ^chars rc))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- reifyPassword ""

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
      (if (nil? pwdStr)
        (ImmutablePair/of ""  "")
        (let [s (BCrypt/gensalt 12) ]
          (ImmutablePair/of (BCrypt/hashpw pwdStr s) s ))))

    (hashed [_]
      (if (nil? pwdStr)
        (ImmutablePair/of "" "")
        (let [s (BCrypt/gensalt 10) ]
          (ImmutablePair/of (BCrypt/hashpw pwdStr s) s))))

    (validateHash [this pwdHashed]
      (BCrypt/checkpw (.text this) pwdHashed))

    (encoded [_]
      (cond
        (nil? pwdStr)
        nil
        (empty? pwdStr)
        ""
        :else
        (str PWD_PFX (.encrypt (jasyptCryptor)
                               (.toCharArray pkey)
                               pwdStr))))

    (text [_] (when-not (empty? pwdStr) (str pwdStr) )) ))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn pwdify

  "Create a password object"

  ^PasswordAPI
  [^String pwdStr & [pkey]]

  (let [^String pkey (or pkey C_KEY)]
    (if
      (.startsWith (str pwdStr) PWD_PFX)
      (reifyPassword
        (.decrypt (jasyptCryptor)
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

  (createXXX len s_asciiChars))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn strongPwd

  "Generate a strong password"

  ^PasswordAPI
  [len]

  (pwdify (createXXX len s_pwdChars)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


