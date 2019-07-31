;; Copyright © 2013-2019, Kenneth Leung. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file epl-v10.html at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

(ns ^{:doc "Password Encoders & Decoders."
      :author "Kenneth Leung"}

  czlab.twisty.codec

  (:require [czlab.basal.core :as c]
            [czlab.basal.log :as l]
            [czlab.basal.io :as i]
            [czlab.basal.str :as s]
            [czlab.basal.util :as u])

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
(def ^{:private true :tag "[C"}
  VISCHS
  (i/x->chars (str " @N/\\Ri2}aP`(xeT4F3mt;8~%r0v:L5$+Z{'V)\"CKIc>z.*"
                   "fJEwSU7juYg<klO&1?[h9=n,yoQGsW]BMHpXb6A|D#q^_d!-")))

(def ^{:private true :tag "[C"}
  CKEY (i/x->chars "ed8xwl2XukYfdgR2aAddrg0lqzQjFhbs"))

(def ^:private VISCHS-LEN (alength VISCHS))

(def ^:private s-ascii-chars
  (-> (str "abcdefghijklmnopqrstuvqxyz1234567890"
           "-_ABCDEFGHIJKLMNOPQRSTUVWXYZ") s/shuffle i/x->chars))

(def ^:private s-pwd-chars
  (-> (str "abcdefghijklmnopqrstuvqxyz"
           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
           "`1234567890-_~!@#$%^&*()") s/shuffle i/x->chars))

(def ^:private ^String pwd-pfx "crypt:")
(def ^:private pwd-pfxlen 6)
(def ^:private CZERO (char-array 0))

;; default javax supports this
;; TripleDES
(def ^:private ^String t3-des "DESede")
(def ^:private ^String c-algo t3-des)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defprotocol Cryptor
  (algo [_] "Encryption algorithm used")
  (decrypt [_ pkey data] "Decrypt some data")
  (encrypt [_ pkey data] "Encrypt some data"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- ensure-key-size
  "Key has enough bits?"
  ^bytes [kee algo]
  {:pre [(c/is? u/BSCZ kee)]}
  (let [bits (* 8 (alength ^bytes kee))]
    (cond
      (and (< bits 192)
           (= t3-des algo)) ;; 8x 3 = 24 bytes
      (u/throw-BadArg "TripleDES key length must be 192")
      (and (< bits 128)
           (= "AES" algo))
      (u/throw-BadArg "AES key length must be 128 or 256")
      :else kee)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- key->bits
  "Sanitize the key, maybe chop length"
  ^bytes [pwd algo]
  (let [blen (alength ^bytes pwd)
        bits (* 8 blen)]
    (cond
      (= "AES" algo)
      (cond
        (> bits 256) ;; 32 bytes
        (c/vargs Byte/TYPE (take 32 pwd))
        ;; 128 => 16 bytes
        (and (> bits 128) (< bits 256))
        (c/vargs Byte/TYPE (take 16 pwd))
        :else pwd)
      (= algo t3-des)
      (if (> blen 24)
        ;; 24 bytes
        (c/vargs Byte/TYPE (take 24 pwd))
        pwd)
      :else pwd)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; caesar cipher
(defmacro ^:private ident-ch
  "Get a character" [pos] `(aget VISCHS (int ~pos)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- locate-ch
  "Locate a character" ^Integer [^Character ch]
  (-> (some #(if (= ch
                    (aget VISCHS %1))
               %1) (range VISCHS-LEN)) (or -1)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- slide-forward [delta cpos]
  (let [ptr (+ cpos delta)]
    (-> (if (>= ptr VISCHS-LEN) (- ptr VISCHS-LEN) ptr) ident-ch)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- slide-back [delta cpos]
  (let [ptr (- cpos delta)]
    (-> (if (< ptr 0) (+ VISCHS-LEN ptr) ptr) ident-ch)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- shiftenc [shift delta cpos]
  (if (< shift 0) (slide-forward delta cpos) (slide-back delta cpos)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- shiftdec [shift delta cpos]
  (if (< shift 0) (slide-back delta cpos) (slide-forward delta cpos)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- caesar-amap-expr
  ^Character [^chars ca pos shiftFunc]
  (let [ch (aget ca pos)
        p (locate-ch ch)]
    (if (< p 0) ch (shiftFunc p))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn caesar<>
  "Encrypt by character rotation" []
  (reify Cryptor
    (algo [_] "caesar")
    (encrypt [_ shiftpos text]
      (if (or (s/nichts? text)
              (c/szero? shiftpos))
        text
        (let [delta (mod (Math/abs (int shiftpos)) VISCHS-LEN)
              pf (partial shiftenc shiftpos delta)
              ca (i/x->chars text)
              out (amap ca pos ret
                        (caesar-amap-expr ca pos pf))]
          (i/x->str out))))
    (decrypt [_ shiftpos text]
      (if (or (s/nichts? text)
              (c/szero? shiftpos))
        text
        (let [delta (mod (Math/abs (int shiftpos)) VISCHS-LEN)
              pf (partial shiftdec shiftpos delta)
              ca (i/x->chars text)
              out (amap ca pos ret
                        (caesar-amap-expr ca pos pf))]
          (i/x->str out))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn jasypt<>
  "jasypt cryptor" []
  (reify Cryptor
    (algo [_] "PBEWithMD5AndTripleDES")
    (decrypt [_ pkey data]
      (let [e (StrongTextEncryptor.)]
        (.setPasswordCharArray e (i/x->chars pkey))
        (.decrypt e (i/x->str data))))
    (encrypt [_ pkey data]
      (let [e (StrongTextEncryptor.)]
        (.setPasswordCharArray e (i/x->chars pkey))
        (.encrypt e (i/x->str data))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; java cryptor
(defn- get-cipher
  ^Cipher [pkey mode ^String algo]
  (doto
    (Cipher/getInstance algo)
    (.init (int mode)
           (SecretKeySpec. (key->bits pkey algo) algo))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- java-codec
  ^bytes [pkey data ^Cipher c]
  (when-some [p (i/x->bytes data)]
    (let
      [plen (alength p)
       baos (i/baos<>)
       out (byte-array (max c/BUF-SZ
                            (.getOutputSize c plen)))
       n (.update c p 0 plen out 0)]
      (if (pos? n)
        (.write baos out 0 n))
      (let [n2 (.doFinal c out 0)]
        (if (pos? n2)
          (.write baos out 0 n2)))
      (i/x->bytes baos))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defmacro ^:private
  jcryptor-impl [pkey data algo mode]
  `(when ~data
     (c/test-cond "pkey != bytes" (c/is? u/BSCZ ~pkey))
     (ensure-key-size ~pkey ~algo)
     (java-codec ~pkey ~data (get-cipher ~pkey ~mode ~algo))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn jcrypt<> "" []
  (reify Cryptor
    ;;PBEWithMD5AndDES
    (algo [_] t3-des)
    (decrypt [me pkey cipher]
      (jcryptor-impl pkey cipher (.algo me) Cipher/DECRYPT_MODE))
    (encrypt [me pkey clear]
      (jcryptor-impl pkey clear (.algo me) Cipher/ENCRYPT_MODE))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; 1024 - 2048 bits RSA
(defn asym<> "" []
  (reify Cryptor
    (algo [_] "RSA/ECB/PKCS1Padding")
    (encrypt [me pubKey data]
      (when data
        (let [k (i/x->bytes pubKey)
              pk (-> (KeyFactory/getInstance "RSA")
                     (.generatePublic (X509EncodedKeySpec. k)))
              cipher (doto (Cipher/getInstance (.algo me))
                       (.init Cipher/ENCRYPT_MODE ^Key pk))]
          (.doFinal cipher (i/x->bytes data)))))
    (decrypt [me prvKey data]
      (when data
        (let [k (i/x->bytes prvKey)
              pk (-> (KeyFactory/getInstance "RSA")
                     (.generatePrivate (PKCS8EncodedKeySpec. k)))
              cipher (doto (Cipher/getInstance (.algo me))
                       (.init Cipher/DECRYPT_MODE ^Key pk))]
          (.doFinal cipher (i/x->bytes data)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; BC cryptor
(defn- bcXXX
  ^bytes [pkey data algo mode]
  (when data
    (ensure-key-size pkey algo)
    (let [eng (condp = algo
                "Blowfish" (BlowfishEngine.)
                "DESede" (DESedeEngine.)
                "AES" (AESEngine.)
                "RSA" (RSAEngine.)
                (c/test-cond "no crypto engine" false))
          cipher (doto (-> eng CBCBlockCipher.
                           PaddedBufferedBlockCipher.)
                   (.init mode (KeyParameter. (key->bits pkey algo))))
          out (byte-array c/BUF-SZ)
          p (i/x->bytes data)
          baos (i/baos<>)
          c (.processBytes cipher p 0 (alength p) out 0)]
      (if (pos? c) (.write baos out 0 c))
      (let [c2 (.doFinal cipher out 0)]
        (if (pos? c2) (.write baos out 0 c2)))
      (i/x->bytes baos))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn bcastle<> "" []
  (reify Cryptor
    (algo [_] t3-des)
    (encrypt [me pkey clear]
      (bcXXX pkey clear (.algo me) true))
    (decrypt [me pkey cipher]
      (bcXXX pkey cipher (.algo me) false))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; passwords
(defn- create-xxx
  ^String [^chars chArray len]
  (let [b Integer/MAX_VALUE
        r (u/rand<>)
        alen (alength chArray)]
    (cond (zero? len) ""
          (neg? len) nil
          :else
          (i/x->str (amap (char-array len)
                          pos ret
                          (aget chArray
                                (mod (.nextInt r b) alen)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defprotocol Password
  (valid-hash? [_ targetHashed] "Check to match")
  (strongly-hashed [_] "Get (string) hash value")
  (stringify [_] "Get as string")
  (hashed [_] "Get hash value")
  (p-encoded [_] "Get encoded value")
  (p-text [_] "Get clear text value"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- mkpwd [pwd pkey]
  (let [_pwd (i/x->chars pwd)
        _pkey (i/x->chars pkey)]
  (reify Password
    (strongly-hashed [me]
      (if (and _pwd
               (not-empty _pwd))
        (->> (BCrypt/gensalt 12)
             (BCrypt/hashpw (.stringify me))) ""))
    (hashed [me]
      (if (and _pwd
               (not-empty _pwd))
        (->> (BCrypt/gensalt 10)
             (BCrypt/hashpw (.stringify me))) ""))
    (valid-hash? [me pwdHashed]
      (BCrypt/checkpw (.stringify me) pwdHashed))
    (stringify [me] (i/x->str (.p-text me)))
    (p-text [_] _pwd)
    (p-encoded [me]
      (cond (nil? _pwd) nil
            (empty? _pwd) CZERO
            :else
            (i/x->chars (str pwd-pfx
                             (encrypt (jasypt<>)
                                      _pkey
                                      (.stringify me)))))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn pwd<>
  "Create a password object"
  ([pwd] (pwd<> pwd nil))
  ([pwd pkey]
   (let [s (i/x->str pwd)
         pk (i/x->chars (or pkey CKEY))]
     (if-not (some-> s (.startsWith pwd-pfx))
       (mkpwd pwd pk)
       (mkpwd (decrypt (jasypt<>)
                       pk
                       (.substring s pwd-pfxlen)) pk)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn random-str
  "Generate random text"
  ^String [len] (create-xxx s-ascii-chars len))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn strong-pwd<>
  "Generate a strong password"
  [len]
  (pwd<> (i/x->chars (create-xxx s-pwd-chars len))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF

