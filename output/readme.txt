for n_sender file: the n output of the sender proccess
	elgamal shared parameter N (number of bits used to generate the prime number)
	elgamal shared parameter p (the prime number)
	elgamal shared parameter g (the generator)
	elgamal generated public key of alice ( this is usually called y) (integer format)
	elgamal generated private key of alice ( this is usually called x) (integer format)
	r component of the signature generated from the testcase_n message using the private key of alice
	s component of the signature generated from the testcase_n message using the private key of alice
	cipher text of the message after rsa encrpytion using bob public key OR None if there is error in verification the certificate returned from CA

for n_rec file: the n output of the receiver process
	elgamal shared parameter N (number of bits used to generate the prime number)
	elgamal shared parameter p (the prime number)
	elgamal shared parameter g (the generator)
	rsa generated public key of bob (pem encoding format)
	rsa generated private key of bob (pem encoding format)
	does the certificate is coming from the trusted CA (bool format)
	r component of the signature recieved in the message
	s component of the signature recieved in the message
	does the message is really come from that sender (bool format) OR None if there is error in verification the certificate returned from CA
	cipher text of the message recieved in the message OR None if there is error in verification the certificate returned from CA
	the final plain text obtained from decrpyting the cipher text using bob private key
