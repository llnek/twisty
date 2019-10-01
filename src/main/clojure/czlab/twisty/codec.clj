;; Copyright © 2013-2019, Kenneth Leung. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file epl-v10.html at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

(ns
  ^{:doc "Password Encoders & Decoders."
    :author "Kenneth Leung"}

  czlab.twisty.codec

  (:require [clojure.string :as cs]
            [czlab.basal
             [log :as l]
             [io :as i]
             [util :as u]
             [core :as c]])

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
(c/def-
  ^{:tag "[C"} VISCHS
  (i/x->chars (str " @N/\\Ri2}aP`(xeT4F3mt;8~%r0v:L5$+Z{'V)\"CKIc>z.*"
                   "fJEwSU7juYg<klO&1?[h9=n,yoQGsW]BMHpXb6A|D#q^_d!-")))

(c/def-
  ^{:tag "[C"}
  CKEY (i/x->chars "ed8xwl2XukYfdgR2aAddrg0lqzQjFhbs"))

(c/def- VISCHS-LEN (alength VISCHS))

(c/def- s-ascii-chars
  (-> (str "abcdefghijklmnopqrstuvqxyz1234567890"
           "-_ABCDEFGHIJKLMNOPQRSTUVWXYZ") u/shuffle i/x->chars))

(c/def- s-pwd-chars
  (-> (str "abcdefghijklmnopqrstuvqxyz"
           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
           "`1234567890-_~!@#$%^&*()") u/shuffle i/x->chars))

(c/def- ^String pwd-pfx "crypt:")
(c/def- pwd-pfxlen 6)
(c/def- CZERO (char-array 0))

;; default javax supports this
;; TripleDES
(c/def- ^String t3-des "DESede")
(c/def- ^String c-algo t3-des)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defprotocol Cryptor
  ""
  (cr-algo [_] "Encryption algorithm used")
  (cr-decrypt [_ pkey data] "Decrypt some data")
  (cr-encrypt [_ pkey data] "Encrypt some data"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- ensure-key-size
  "Key has enough bits?"
  ^bytes [^bytes kee algo]
  (let [bits (* 8 (alength kee))]
    (if
      (and (< bits 192)
           (= t3-des algo)) ;; 8x 3 = 24 bytes
      (u/throw-BadArg "TripleDES key length must be 192."))
    (if
      (and (< bits 128)
           (= "AES" algo))
      (u/throw-BadArg "AES key length must be 128 or 256."))
    ;ok
    kee))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- key->bits
  "Sanitize the key, maybe chop length"
  ^bytes [^bytes pwd algo]
  (let [blen (alength pwd)
        bits (* 8 blen)]
    (cond (= "AES" algo)
          (cond (> bits 256) ;; 32 bytes
                (c/vargs Byte/TYPE (take 32 pwd))
                ;; 128 => 16 bytes
                (and (> bits 128) (< bits 256))
                (c/vargs Byte/TYPE (take 16 pwd))
                :else pwd)
          (= algo t3-des)
          (if (> blen 24) ;; 24 bytes
            (c/vargs Byte/TYPE (take 24 pwd)) pwd)
          :else pwd)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; caesar cipher
(c/defmacro- ident-ch
  "Get a character." [pos] `(aget VISCHS (int ~pos)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- locate-ch
  "Locate a character." ^Integer [ch]
  (or (some #(if (= ^Character ch
                    (aget VISCHS %1))
               %1) (range VISCHS-LEN)) -1))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- slide-forward
  [delta cpos]
  (let [ptr (+ cpos delta)]
    (-> (if (>= ptr VISCHS-LEN) (- ptr VISCHS-LEN) ptr) ident-ch)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- slide-back
  [delta cpos]
  (let [ptr (- cpos delta)]
    (-> (if (< ptr 0) (+ VISCHS-LEN ptr) ptr) ident-ch)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- shiftenc
  [shift delta cpos]
  (if (< shift 0) (slide-forward delta cpos) (slide-back delta cpos)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- shiftdec
  [shift delta cpos]
  (if (< shift 0) (slide-back delta cpos) (slide-forward delta cpos)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- caesar-amap-expr
  ^Character [^chars ca pos shiftFunc]
  (let [ch (aget ca pos)
        p (locate-ch ch)]
    (if (< p 0) ch (shiftFunc p))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn caesar<>
  "Encrypt by character rotation." []
  (let [F (fn [shiftpos text func']
            (if (or (c/nichts? text)
                    (c/szero? shiftpos))
              text
              (let [delta (mod (Math/abs (int shiftpos)) VISCHS-LEN)
                    pf (partial func' shiftpos delta)
                    ca (i/x->chars text)]
                (i/x->str (amap ca pos ret
                                (caesar-amap-expr ca pos pf))))))]
  (reify Cryptor
    (cr-encrypt [_ shiftpos text]
      (F shiftpos text shiftenc))
    (cr-algo [_] "caesar")
    (cr-decrypt [_ shiftpos text]
      (F shiftpos text shiftdec)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn jasypt<>
  "jasypt cryptor" []
  (let [F #(doto
             (StrongTextEncryptor.)
             (.setPasswordCharArray (i/x->chars %1)))]
  (reify Cryptor
    (cr-algo [_] "PBEWithMD5AndTripleDES")
    (cr-decrypt [_ pkey data]
      (.decrypt ^StrongTextEncryptor (F pkey) (i/x->str data)))
    (cr-encrypt [_ pkey data]
      (.encrypt ^StrongTextEncryptor (F pkey) (i/x->str data))))))

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
(c/defmacro- jcryptor-impl
  [pkey data algo mode]
  `(when ~data
     (c/test-cond "pkey != bytes" (bytes? ~pkey))
     (ensure-key-size ~pkey ~algo)
     (java-codec ~pkey ~data (get-cipher ~pkey ~mode ~algo))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn jcrypt<>
  "" []
  (reify Cryptor
    ;;PBEWithMD5AndDES
    (cr-decrypt [me pkey cipher]
      (jcryptor-impl pkey cipher (cr-algo me) Cipher/DECRYPT_MODE))
    (cr-algo [_] t3-des)
    (cr-encrypt [me pkey clear]
      (jcryptor-impl pkey clear (cr-algo me) Cipher/ENCRYPT_MODE))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn asym<>
  "1024 - 2048 bits RSA"
  []
  (reify Cryptor
    (cr-algo [_] "RSA/ECB/PKCS1Padding")
    (cr-encrypt [me pubKey data]
      (when data
        (let [k (i/x->bytes pubKey)
              pk (-> (KeyFactory/getInstance "RSA")
                     (.generatePublic (X509EncodedKeySpec. k)))
              cipher (doto
                       (Cipher/getInstance (cr-algo me))
                       (.init Cipher/ENCRYPT_MODE ^Key pk))]
          (.doFinal cipher (i/x->bytes data)))))
    (cr-decrypt [me prvKey data]
      (when data
        (let [k (i/x->bytes prvKey)
              pk (-> (KeyFactory/getInstance "RSA")
                     (.generatePrivate (PKCS8EncodedKeySpec. k)))
              cipher (doto
                       (Cipher/getInstance (cr-algo me))
                       (.init Cipher/DECRYPT_MODE ^Key pk))]
          (.doFinal cipher (i/x->bytes data)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; BC cryptor
(defn- bc-xxx
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
(defn bcastle<>
  "" []
  (reify Cryptor
    (cr-encrypt [me pkey clear]
      (bc-xxx pkey clear (cr-algo me) true))
    (cr-algo [_] t3-des)
    (cr-decrypt [me pkey cipher]
      (bc-xxx pkey cipher (cr-algo me) false))))

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
  ""
  (pw-strongly-hashed [_] "Get (string) hash value")
  (pw-hash-valid? [_ targetHashed] "Check to match")
  (pw-stringify [_] "Get as string")
  (pw-hashed [_] "Get hash value")
  (pw-encoded [_] "Get encoded value")
  (pw-text [_] "Get clear text value"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn- mkpwd
  [pwd pkey]
  (let [_pwd (i/x->chars pwd)
        _pkey (i/x->chars pkey)]
  (reify Password
    (pw-strongly-hashed [me]
      (if-not (empty? _pwd)
        (->> (BCrypt/gensalt 12)
             (BCrypt/hashpw (pw-stringify me))) ""))
    (pw-hashed [me]
      (if-not (empty? _pwd)
        (->> (BCrypt/gensalt 10)
             (BCrypt/hashpw (pw-stringify me))) ""))
    (pw-hash-valid? [me pwdHashed]
      (BCrypt/checkpw (pw-stringify me) pwdHashed))
    (pw-stringify [me] (i/x->str (pw-text me)))
    (pw-text [_] _pwd)
    (pw-encoded [me]
      (cond (nil? _pwd) nil
            (empty? _pwd) CZERO
            :else
            (i/x->chars (str pwd-pfx
                             (cr-encrypt (jasypt<>)
                                         _pkey
                                         (pw-stringify me)))))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defn pwd<>
  "Create a password object."
  ([pwd] (pwd<> pwd nil))
  ([pwd pkey]
   (let [s (i/x->str pwd)
         pk (i/x->chars (or pkey CKEY))]
     (if-not (some-> s (cs/starts-with? pwd-pfx))
       (mkpwd pwd pk)
       (mkpwd (cr-decrypt (jasypt<>)
                          pk
                          (subs s pwd-pfxlen)) pk)))))

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

