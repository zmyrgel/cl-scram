;;;; Utility functions required to implement SCRAM-SHA1.
(in-package #:cl-scram)

(defun base64-encode (string)
  "Returns Base64 encoded version of given STRING."
  (check-type string string)
  (cl-base64:string-to-base64-string string))

(defun base64-encode-octets (octets)
  "Returns given OCTETS as Base64 encoded string."
  (cl-base64:usb8-array-to-base64-string octets))

(defun base64-decode (string)
  "Decodes given STRING with Base64 algorithm and returns results as string."
  (check-type string string)
  (cl-base64:base64-string-to-string string))

; Function taken from cl-sasl library.
(defun gen-sasl-password (password)
  "Get a normalized SASL password."
  (check-type password string)
  password)

(defun gen-client-nonce ()
  "Generate a random 32-character nonce."
  (let ((chars "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
        (length 32)
        (password (make-string 32)))
    (dotimes (i length)
      (setf (aref password i) (aref chars (secure-random:number (length chars)))))
    password))

(defun gen-hmac-digest (key message &key (digest :sha1))
  "Takes KEY and MESSAGE strings and generates a HMAC digest out of them."
  (ironclad:hmac-digest
   (ironclad:update-hmac (ironclad:make-hmac key digest)
                         (ironclad:ascii-string-to-byte-array message))))

(defun bit-vector->integer (bit-vector)
  "Create a positive integer from a bit-vector."
  (reduce #'(lambda (first-bit second-bit)
              (+ (* first-bit 2) second-bit))
          bit-vector))

(defun integer->bit-vector (integer)
  "Create a bit-vector from a positive integer."
  (labels ((integer->bit-list (int &optional accum)
             (cond ((> int 0)
                    (multiple-value-bind (i r) (truncate int 2)
                      (integer->bit-list i (push r accum))))
                   ((null accum) (push 0 accum))
                   (t accum))))
    (coerce (integer->bit-list integer) 'bit-vector)))
