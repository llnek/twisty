(set-env!

  :license {:name "Apache License 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :description ""
  :url "https://github.com/llnek/crypto"

  :dependencies '[

    [org.clojure/math.numeric-tower "0.0.4" ]
    [org.bouncycastle/bcprov-jdk15on "1.54"]
    [org.bouncycastle/bcmail-jdk15on "1.54"]
    [org.bouncycastle/bcpkix-jdk15on "1.54"]
    [org.jasypt/jasypt "1.9.2" ]
    ;;[org.mindrot/jbcrypt "0.3m" ]

    [org.apache.commons/commons-email "1.4" ]
    [com.sun.mail/javax.mail "1.5.5" ]
    [org.clojure/clojure "1.8.0" ]

    [czlab/czlab-xlib "1.0.0" ]

    [codox/codox "0.9.5" :scope "provided"]
    ;; boot/clj stuff
    ;;[boot/base "2.6.0" :scope "provided"]
    ;;[boot/core "2.6.0" :scope "provided"]
    ;;[boot/pod "2.6.0" :scope "provided"]
    ;;[boot/worker "2.6.0" :scope "provided"]
    ;; this is causing the RELEASE_6 warning
    ;;[boot/aether "2.6.0" :scope "provided"]

  ]

  :source-paths #{"src/main/clojure" "src/main/java"}
  :test-runner "czlabtest.crypto.ClojureJUnit"
  :version "1.0.0"
  :debug true
  :project 'czlab/czlab-crypto)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(require
  '[czlab.tpcl.boot
    :as b
    :refer [artifactID fp! ge]]
  '[clojure.tools.logging :as log]
  '[clojure.java.io :as io]
  '[clojure.string :as cs]
  '[czlab.xlib.antlib :as a])

(import '[java.io File])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(b/bootEnv!)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;  task defs below !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
;;
(deftask tst

  "for test only"
  []

  (comp (b/testJava)
        (b/testClj)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(deftask dev

  "for dev only"
  []

  (comp (b/initBuild)
        (b/libjars)
        (b/buildr)
        (b/pom!)
        (b/jar!)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(deftask rel

  ""
  [d doco bool "Generate doc"]

  (b/toggleDoco doco)
  (comp (dev)
        (b/localInstall)
        (b/packDistro)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


