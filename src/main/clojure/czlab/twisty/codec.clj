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
  (charsit
    (str " @N/\\Ri2}aP`(xeT4F3mt;8~%r0v:L5$+Z{'V)\"CKIc>z.*"
         "fJEwSU7juYg<klO&1?[h9=n,yoQGsW]BMHpXb6A|D#q^_d!-")))

(def
  ^{:private true
    :tag "[C"}
  c-key (charsit "ed8xwl2XukYfdgR2aAddrg0lqzQjFhbs"))

(def ^:private vischs-len (alength vis-chs))

(def ^:private
  s-asciiChars
  (-> (str "abcdefghijklmnopqrstuvqxyz1234567890"
           "-_ABCDEFGHIJKLMNOPQRSTUVWXYZ" ) CU/shuffle charsit))

(def ^:private
  s-pwdChars
  (-> (str "abcdefghijklmnopqrstuvqxyz"
           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
           "`1234567890-_~!@#$%^&*()") CU/shuffle charsit))

(def ^:private ^String pwd-pfx "crypt:")
(def ^:private pwd-pfxlen 6)
(def ^:private CZERO (.toCharArray ""))

;; default javax supports this
;; TripleDES
(def ^:private ^String t3-des "DESede")
(def ^:private ^String c-algo t3-des)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defprotocol Cryptor
  ""
  (decrypt [_ pkey data] "")
  (encrypt [_ pkey data] "")
  (^String algo [_] ""))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn- ensureKeySize
  "Key has enough bits?"
  ^bytes [kee algo]
  {:pre [(instBytes? kee)]}
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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;"Encrypt by character rotation"
(decl-object CaesarCryptor
  Cryptor
  (encrypt [_ shiftpos text]
    (if (or (szero? shiftpos)
            (nichts? text))
      text
      (let [delta (mod (Math/abs (int shiftpos)) vischs-len)
            pf (partial shiftenc shiftpos delta)
            ca (.toCharArray ^String text)
            out (amap ca pos ret
                      (caesarAMapExpr ca pos pf))]
        (String. ^chars out))))
  (decrypt [_ shiftpos text]
    (if (or (szero? shiftpos)
            (nichts? text))
      text
      (let [delta (mod (Math/abs (int shiftpos)) vischs-len)
            pf (partial shiftdec shiftpos delta)
            ca (.toCharArray ^String text)
            out (amap ca pos ret
                      (caesarAMapExpr ca pos pf))]
        (String. ^chars out))))
  (algo [_] ""))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmacro caesar<> "" []
  `~(with-meta (object<> CaesarCryptor) {:tag 'czlab.twisty.codec.Cryptor}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; jasypt cryptor
(decl-object JasyptCryptor
  Cryptor
  (decrypt [_ pkey data]
    (-> (doto (StrongTextEncryptor.)
          (.setPasswordCharArray (charsit pkey)))
        (.decrypt (strit data))))

  (encrypt [_ pkey data]
    (-> (doto (StrongTextEncryptor.)
          (.setPasswordCharArray (charsit pkey)))
        (.encrypt (strit data))))

  (algo [_] "PBEWithMD5AndTripleDES"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmacro jasypt<> "" []
  `~(with-meta (object<> JasyptCryptor) {:tag 'czlab.twisty.codec.Cryptor}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; java cryptor
(defn- getCipher
  "" ^Cipher [pkey mode ^String algo]
  (doto
    (Cipher/getInstance algo)
    (.init (int mode)
           (SecretKeySpec. (keyAsBits pkey algo) algo))))

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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmacro ^:private
  jcryptorImpl "" [pkey data algo mode]
  `(when ~data
     (test-cond "pkey != bytes" (instBytes? ~pkey))
     (ensureKeySize ~pkey ~algo)
     (->> (getCipher ~pkey ~mode ~algo)
          (javaCodec ~pkey ~data))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(decl-object JavaCryptor
  Cryptor
  (decrypt [me pkey cipher]
    (jcryptorImpl pkey cipher (.algo me) Cipher/DECRYPT_MODE))
  (encrypt [me pkey clear]
    (jcryptorImpl pkey clear (.algo me) Cipher/ENCRYPT_MODE))
  ;;PBEWithMD5AndDES
  (algo [_] t3-des))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmacro jcrypt<> "" []
  `~(with-meta (object<> JavaCryptor) {:tag 'czlab.twisty.codec.Cryptor}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; 1024 - 2048 bits RSA
(decl-object AsymCryptor
  Cryptor
  (encrypt [me pubKey data]
    (when data
      (let
        [k (convBytes pubKey)
         ^Key pk (-> (KeyFactory/getInstance "RSA")
                     (.generatePublic (X509EncodedKeySpec. k)))
         cipher (doto (Cipher/getInstance (.algo me))
                  (.init Cipher/ENCRYPT_MODE pk))]
        (->> (convBytes data)
             (.doFinal cipher )))))
  (decrypt [me prvKey data]
    (when data
      (let
        [k (convBytes prvKey)
         ^Key pk (-> (KeyFactory/getInstance "RSA")
                     (.generatePrivate (PKCS8EncodedKeySpec. k)))
         cipher (doto (Cipher/getInstance (.algo me))
                  (.init Cipher/DECRYPT_MODE pk))]
        (->> (convBytes data)
             (.doFinal cipher )))))
  (algo [_] "RSA/ECB/PKCS1Padding"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmacro asym<> "" []
  `~(with-meta (object<> AsymCryptor) {:tag 'czlab.twisty.codec.Cryptor}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; BC cryptor
(defn- bcXXX
  "" ^bytes [pkey data algo mode]
  (when data
    (ensureKeySize pkey algo)
    (let
      [eng (condp = algo
             "Blowfish" (BlowfishEngine.)
             "DESede" (DESedeEngine.)
             "AES" (AESEngine.)
             "RSA" (RSAEngine.)
             (test-cond "no crypto engine" false))
       cipher (doto (-> eng CBCBlockCipher.
                            PaddedBufferedBlockCipher.)
                (.init mode
                       (KeyParameter.
                         (keyAsBits pkey algo))))
       out (byte-array BUF_SZ)
       p (convBytes data)
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
(decl-object BCastleCryptor
  Cryptor
  (decrypt [me pkey cipher]
    (bcXXX pkey cipher (.algo me) false))
  (encrypt [me pkey clear]
    (bcXXX pkey clear (.algo me) true))
  (algo [_] t3-des))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmacro bcastle<> "" []
  `~(with-meta (object<> BCastleCryptor) {:tag 'czlab.twisty.codec.Cryptor}))

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
(defprotocol Password
  ""
  (valid-hash? [_ ^String targetHashed] "")
  (^String strongly-hashed [_] "")
  (^String stringify [_] "")
  (^String hashed [_] "")
  (^chars p-encoded [_] "")
  (^chars p-text [_] ""))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(decl-object PasswordObj
  Password
  (strongly-hashed [me]
    (let [{:keys [pwd]} me]
      (if (and pwd
               (not-empty pwd))
        (->> (BCrypt/gensalt 12)
             (BCrypt/hashpw (stringify me))) "")))
  (hashed [me]
    (let [{:keys [pwd]} me]
      (if (and pwd
               (not-empty pwd))
        (->> (BCrypt/gensalt 10)
             (BCrypt/hashpw (stringify me))) "")))
  (valid-hash? [me pwdHashed]
    (BCrypt/checkpw (stringify me) pwdHashed))
  (p-encoded [me]
    (let [{:keys [pkey pwd]} me]
      (cond
        (nil? pwd) nil
        (empty? pwd) CZERO
        :else (charsit (str pwd-pfx
                            (.encrypt (jasypt<>)
                                      pkey (stringify me)))))))
  (stringify [me] (strit (p-text me)))
  (p-text [me] (:pwd me)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defmacro ^:private mkPwd "" [pwd pkey]
  `(object<> PasswordObj
             {:pwd (charsit ~pwd)
              :pkey (charsit ~pkey)}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn pwd<>
  "Create a password object"

  ([pwd] (pwd<> pwd nil))

  ([pwd pkey]
   (let [pkey (or (charsit pkey) c-key)
         s (strit pwd)]
     (if
       (some-> s (.startsWith pwd-pfx))
       (mkPwd
         (.decrypt (jasypt<>)
                   pkey (.substring s pwd-pfxlen)) pkey)
       (mkPwd pwd pkey)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn randomStr
  "Generate random text"
  ^String [len] (createXXX s-asciiChars len))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defn strongPwd<>
  "Generate a strong password"
  [len]
  (pwd<> (charsit (createXXX s-pwdChars len))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF

