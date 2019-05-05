(in-package #:cl-user)
(defpackage #:cl-scram-asd
  (:use #:cl #:asdf))
(in-package #:cl-scram-asd)

(asdf:defsystem #:cl-scram
    :name        "cl-scram"
    :author      "Matt Prelude <me@mprelu.de>"
    :version     "0.1"
    :license     "Revised BSD License (see LICENSE)"
    :description "Common lisp library to implement SCRAM-SHA1 SASL mechanism."
    :depends-on  ("cl-sasl"
                  "cl-base64"
                  "ironclad"
                  "secure-random"
                  "split-sequence")
    :components  ((:module "src"
                           :serial t
                           :components ((:file "packages")
                                        (:file "conditions")
                                        (:file "utils")
                                        (:file "scram")))
                  (:static-file "README.md")
                  (:static-file "LICENSE"))
  :in-order-to ((test-op (test-op "cl-scram/tests"))))

(defsystem "cl-scram/tests"
  :name "cl-scram/tests"
  :version "0.1"
  :author "Timo Myyrä <timo.myyra@bittivirhe.fi>"
  :maintainer "Timo Myyrä <timo.myyra@bittivirhe.fi>"
  :description "Unit tests for the cl-scram."
  :license "Revised BSD License (see LICENSE)"
  :depends-on ("cl-scram" "rove")
  :serial t
  :components ((:module "tests"
                :components ((:file "scram"))))
  :perform (test-op (op c)
                    (funcall (read-from-string "rove:run")
                             :cl-scram/tests :style :spec)))
