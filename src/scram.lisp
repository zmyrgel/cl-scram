;;;; SCRAM functions.
(in-package #:cl-scram)

(defun gen-client-initial-message (&key username nonce)
  "Generate the SCRAM-SHA1 initial SASL message."
  (check-type username string)
  (check-type nonce string)
  (format nil "n,,n=~a,r=~a" username nonce))

(define-condition unexpected-nonce (error)
  ((text :initarg :text :reader text)))

(defun gen-client-final-message
    (&key password client-nonce client-initial-message server-response)
  "Takes a password, the initial client nonce, the initial client message & the server response.
   Generates the final client message, and returns it along with the server signature."
  (check-type client-nonce string)
  (check-type client-initial-message string)
  (check-type server-response string)
  (check-type password string)
  (if (eq nil (parse-server-nonce :nonce client-nonce :response server-response))
      (error 'unexpected-nonce :text "The server nonce does not begin with the client nonce."))
  (let* ((final-message-bare (format nil "c=biws,r=~a" (parse-server-nonce :nonce client-nonce
                                                                           :response server-response)))
         (salted-password    (ironclad:pbkdf2-hash-password
                              (ironclad:ascii-string-to-byte-array password)
                              :salt       (ironclad:ascii-string-to-byte-array
                                           (parse-server-salt :response server-response))
                              :digest     :sha1
                              :iterations (parse-server-iterations :response server-response)))
         (client-key         (gen-hmac-digest :key salted-password
                                              :message (ironclad:ascii-string-to-byte-array "Client Key")))
         (stored-key         (gen-sha1-digest :key client-key))
         (auth-message       (format nil "~a,~a,~a"
                                     (if (= 0 (search "n,," client-initial-message))
                                         (subseq client-initial-message 3
                                                 (format nil "~a" client-initial-message)))
                                     server-response
                                     final-message-bare))
         (client-signature   (gen-hmac-digest :key stored-key
                                              :message (ironclad:ascii-string-to-byte-array auth-message)))
         (client-proof       (ironclad:integer-to-octets
                              (logxor (ironclad:octets-to-integer client-key)
                                      (ironclad:octets-to-integer client-signature))))
         (server-key         (gen-hmac-digest :key salted-password
                                              :message (ironclad:ascii-string-to-byte-array "Server Key")))
         (server-signature   (gen-hmac-digest :key server-key
                                              :message (ironclad:ascii-string-to-byte-array auth-message)))
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
  "Takes a non-encoded server response, & returns three values:
   - The server nonce,
   - The (base64-encoded) salt,
   - The number of iterations."
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
  (let ((server-nonce
          (cdr (assoc "r"
                      (parse-server-response :response response)
                      :test #'equal))))
    (when (= 0 (search nonce server-nonce))
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
