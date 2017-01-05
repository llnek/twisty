;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
(defproject czlab/czlab-twisty "0.1.0"

  :description ""
  :url "https://github.com/llnek/twisty"

  :license {:name "Apache License 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}

  :dependencies [[org.bouncycastle/bcprov-jdk15on "1.56"]
                 [org.bouncycastle/bcmail-jdk15on "1.56"]
                 [org.bouncycastle/bcpkix-jdk15on "1.56"]
                 [org.apache.commons/commons-email "1.4"]
                 [commons-codec/commons-codec "1.10"]
                 [com.sun.mail/javax.mail "1.5.6"]
                 [org.jasypt/jasypt "1.9.2"]
                 ;;[org.mindrot/jbcrypt "0.3m"]
                 [czlab/czlab-xlib "0.1.0"]]

  :profiles {:provided {:dependencies
                        [[net.mikera/cljunit "0.6.0" :scope "test"]
                         [junit/junit "4.12" :scope "test"]
                         [org.clojure/clojure "1.8.0" :scope "provided"]
                         [codox/codox "0.10.2" :scope "provided"]]}
             :uberjar {:aot :all}}

  :global-vars {*warn-on-reflection* true}
  :target-path "out/%s"
  :aot :all

  :java-source-paths ["src/main/java" "test/main/java"]
  :source-paths ["src/main/clojure"]
  :test-paths ["src/test/clojure"]
  :resource-paths ["src/main/resources"]

  :jvm-opts ["-Dlog4j.configurationFile=file:attic/log4j2.xml"]
  :javac-options ["-source" "8"
                  "-Xlint:unchecked" "-Xlint:-options" "-Xlint:deprecation"])


