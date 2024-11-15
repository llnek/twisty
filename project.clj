;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defproject io.czlab/twisty "2.2.0"

  :license {:url "https://www.apache.org/licenses/LICENSE-2.0.txt"
            :name "Apache License"}

  :description "Useful s/mime, crypto functions"
  :url "https://github.com/llnek/twisty"

  :dependencies [[org.bouncycastle/bcprov-jdk18on "1.79"]
                 [org.bouncycastle/bcpkix-jdk18on "1.79"]
                 [org.bouncycastle/bcjmail-jdk18on "1.79"]
                 ;[org.apache.commons/commons-email "1.6.0"]
                 [commons-codec/commons-codec "1.17.1"]
                 ;[com.sun.mail/javax.mail "1.6.2"]
                 [com.sun.mail/jakarta.mail "2.0.1"]
                 ;[jakarta.mail/jakarta.mail-api "2.1.3"]
                 [jakarta.activation/jakarta.activation-api "2.1.3"]
                 [org.jasypt/jasypt "1.9.3"]
                 [org.mindrot/jbcrypt "0.4"]
                 [io.czlab/basal "2.2.0"]]

  :plugins [[cider/cider-nrepl "0.50.2" :exclusions [nrepl]]
            [lein-codox "0.10.8"]
            [lein-cljsbuild "1.1.8"]]

  :profiles {:provided {:dependencies
                        [[org.clojure/clojure "1.12.0"]]}
             :uberjar {:aot :all}}

  :test-selectors {:core :test-core
                   :mime :test-mime}

  :global-vars {*warn-on-reflection* true}
  :target-path "out/%s"
  :aot :all

  :coordinate! "czlab"
  :omit-source true

  :java-source-paths ["src/main/java" "src/test/java"]
  :source-paths ["src/main/clojure"]
  :test-paths ["src/test/clojure"]

  :jvm-opts ["-Dlog4j.configurationFile=file:attic/log4j2.xml"]
  :javac-options ["-source" "16"
                  "-target" "22"
                  "-Xlint:unchecked" "-Xlint:-options" "-Xlint:deprecation"])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


