;;;; SCRAM functions.
(in-package #:cl-scram)

(defvar *default-digest* :sha1
  "Defines the default digest algorithm to use for SCRAM functions.
   Currently it should be either :sha1 or :sha2")

(defun gen-client-initial-message (&key username nonce)
  "Generate the SCRAM-SHA1 initial SASL message."
  (check-type username string)
  (check-type nonce string)
  (format nil "n,,n=~a,r=~a" username nonce))

(defun generate-salted-password (password server-response &key (digest *default-digest*))
  "Utility function to generate salted password from given PASSWORD string and SERVER-RESPONSE."
  (ironclad:pbkdf2-hash-password
   (ironclad:ascii-string-to-byte-array password)
   :salt (ironclad:ascii-string-to-byte-array
          (parse-server-salt :response server-response))
   :digest digest
   :iterations (parse-server-iterations :response server-response)))

(defun generate-auth-message (client-initial-message server-response final-message-bare)
  "Utility function to generate auth-message from given CLIENT-INTIAL-MESSAGE, SERVER-RESPONSE and FINAL-MESSAGE-BARE."
  (format nil "~a,~a,~a"
          (if (string= "n,," (subseq client-initial-message 0 3))
              (subseq client-initial-message 3)
              client-initial-message)
          server-response
          final-message-bare))

(defun gen-client-final-message
    (&key password client-nonce client-initial-message server-response)
  "Takes a password, the initial client nonce, the initial client message & the server response.
   Generates the final client message, and returns it along with the server signature."
  (check-type client-nonce string)
  (check-type client-initial-message string)
  (check-type server-response string)
  (check-type password string)
  (let* ((digest             *default-digest*)
         (server-nonce       (parse-server-nonce :nonce client-nonce :response server-response))
         (final-message-bare (format nil "c=biws,r=~a" server-nonce))
         (salted-password    (generate-salted-password password server-response :digest digest))
         (client-key         (gen-hmac-digest salted-password "Client Key" :digest digest))
         (stored-key         (ironclad:digest-sequence digest client-key))
         (auth-message       (generate-auth-message client-initial-message
                                                    server-response
                                                    final-message-bare))
         (client-signature   (gen-hmac-digest stored-key auth-message :digest digest))
         (client-proof       (ironclad:integer-to-octets
                              (logxor (ironclad:octets-to-integer client-key)
                                      (ironclad:octets-to-integer client-signature))))
         (server-key         (gen-hmac-digest salted-password "Server Key" :digest digest))
         (server-signature   (gen-hmac-digest server-key auth-message :digest digest))
         (final-message      (format nil "~a,p=~a"
                                     final-message-bare
                                     (base64-encode-octets client-proof))))
    (pairlis '(final-message
               server-signature)
             (list final-message
                   (base64-encode-octets server-signature)))))

(defun gen-client-encoded-initial-message (&key username nonce)
  "Generate a base64-encoded initial request message."
  (check-type username string)
  (check-type nonce string)
  (base64-encode (gen-client-initial-message :username username :nonce nonce)))

(defun parse-server-response (&key response)
  "Takes a non-encoded server RESPONSE and returns three item list with:
   - The server nonce, base64 encoded salt and the number of iterations."
  (check-type response string)
  (loop :for entry :in (split-sequence:split-sequence #\, response)
        :collect (let ((split-marker (position #\= entry)))
                   (cons (subseq entry 0 split-marker)
                         (subseq entry (1+ split-marker))))))

(defun parse-server-nonce (&key response nonce)
  "Gets the server nonce from the base64-decoded response string.
   Validates that the server nonce starts with the client nonce."
  (check-type response string)
  (check-type nonce string)
  (let* ((server-nonce
           (cdr (assoc "r"
                       (parse-server-response :response response)
                       :test #'equal)))
         (found (search nonce server-nonce)))
    (if (or (null found) (/= found 0))
        (error 'unexpected-nonce :text "The server nonce does not begin with the client nonce.")
        server-nonce)))

(defun parse-server-salt (&key response)
  "Gets the base64-decoded salt from the base64-decoded response string."
  (check-type response string)
  (base64-decode (cdr (assoc "s"
                             (parse-server-response :response response)
                             :test #'equal))))

(defun parse-server-iterations (&key response)
  "Gets the number of iterations from the base64-decoded response string."
  (check-type response string)
  (parse-integer (cdr (assoc "i"
                             (parse-server-response :response response)
                             :test #'equal))))
