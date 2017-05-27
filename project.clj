;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defproject io.czlab/twisty "1.0.0"

  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}

  :description "Useful s/mime, crypto functions"
  :url "https://github.com/llnek/twisty"

  :dependencies [[org.bouncycastle/bcprov-jdk15on "1.57"]
                 [org.bouncycastle/bcmail-jdk15on "1.57"]
                 [org.bouncycastle/bcpkix-jdk15on "1.57"]
                 [org.apache.commons/commons-email "1.4"]
                 [commons-codec/commons-codec "1.10"]
                 [com.sun.mail/javax.mail "1.5.6"]
                 [org.jasypt/jasypt "1.9.2"]
                 [org.mindrot/jbcrypt "0.4"]
                 [io.czlab/basal "1.0.3"]]

  :plugins [[cider/cider-nrepl "0.14.0"]
            [lein-codox "0.10.3"]
            [lein-cprint "1.2.0"]]

  :profiles {:provided {:dependencies
                        [[org.clojure/clojure "1.8.0" :scope "provided"]]}
             :uberjar {:aot :all}}

  :test-selectors {:all :travis}

  :global-vars {*warn-on-reflection* true}
  :target-path "out/%s"
  :aot :all

  :coordinate! "czlab"
  :omit-source true

  :java-source-paths ["src/main/java" "src/test/java"]
  :source-paths ["src/main/clojure"]
  :test-paths ["src/test/clojure"]

  :jvm-opts ["-Dlog4j.configurationFile=file:attic/log4j2.xml"]
  :javac-options ["-source" "8"
                  "-Xlint:unchecked" "-Xlint:-options" "-Xlint:deprecation"])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;EOF


