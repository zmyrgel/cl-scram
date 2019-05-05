(in-package :cl-user)
(defpackage cl-scram.tests
  (:use :cl :rove
        :cl-scram))
(in-package :cl-scram.tests)

(deftest base64-api-tests
    (testing "Verifying that public API functions work"
             (ok (string= (base64-decode "Zm9vYmFy") "foobar")
                 "base64 decoding should work for ASCII strings")
             (ok (string= (base64-encode "foobar") "Zm9vYmFy")
                 "base64 encoding should work for ASCII strings.")
             (ok (string= (base64-encode-octets #(102 111 111 98 97 114)) "Zm9vYmFy")
                 "base64 encoding should work on octets")))

(deftest sasl-password-tests
    (testing "Verify SASL password works"
             (ok (string= (gen-sasl-password "foo") "foo"))))

(deftest client-api-tests
    (testing "Client API functions"
             (ok (= (length (gen-client-nonce)) 32))
             (ok (string= (gen-client-encoded-initial-message :username "foo"
                                                              :nonce "bar")
                          "biwsbj1mb28scj1iYXI="))
             (ok (string= (gen-client-initial-message :username "foo"
                                                      :nonce "bar")
                          "n,,n=foo,r=bar"))
             (ok (let ((nonce (gen-client-nonce)))
                   (string= (gen-client-final-message :password "foobar"
                                                      :client-nonce nonce
                                                      :client-initial-message "foo"
                                                      :server-response "foo")
                            "foo")))
             ))

(deftest parsing-tests
  (testing "Server parsing function tests"
    (let ((resp "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096"))
      (ok (tree-equal (parse-server-nonce :response resp)
                      '(("r" . "fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j")
                        ("s" . "QSXCR+Q6sek8bf92")
                        ("i" . "4096"))
                      :test 'equalp)))
             (ok (string= (parse-server-salt :response resp)
                          "A%ÂGä:±é<mÿv"))
             (ok (= (parse-server-iterations :response resp)
                    4096))))
