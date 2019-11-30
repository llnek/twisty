;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defproject io.czlab/twisty "1.1.0"

  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}

  :description "Useful s/mime, crypto functions"
  :url "https://github.com/llnek/twisty"

  :dependencies [[org.bouncycastle/bcprov-jdk15on "1.64"]
                 [org.bouncycastle/bcmail-jdk15on "1.64"]
                 [org.bouncycastle/bcpkix-jdk15on "1.64"]
                 [org.apache.commons/commons-email "1.5"]
                 [commons-codec/commons-codec "1.13"]
                 [com.sun.mail/javax.mail "1.6.2"]
                 [org.jasypt/jasypt "1.9.3"]
                 [org.mindrot/jbcrypt "0.4"]
                 [io.czlab/basal "1.1.0"]]

  :plugins [[cider/cider-nrepl "0.22.4"]
            [lein-codox "0.10.7"]
            [lein-cprint "1.3.2"]]

  :profiles {:provided {:dependencies
                        [[org.clojure/clojure "1.10.1" :scope "provided"]]}
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
  :javac-options [;"-source" "8"
                  "-Xlint:unchecked" "-Xlint:-options" "-Xlint:deprecation"])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


