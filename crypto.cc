//http://alumni.cs.ucr.edu/~anirban/Anir%20-%20NCW03.pdf

#include "gmp/gmpxx.h"



// Size of the RSA modulus in bits.
#define BITSTRENGTH 512
#define PUBLIC_EXPONENT 65537
// Break message up into chunks of this size.
#define MSG_CHUNK_LENGTH 100

// TODO: Only call srand ONCE!!!

// GCD function for mpz_class large numbers.
// Source: http://www.math.umn.edu/~garrett/crypto/Code/c++.html
mpz_class mpz_gcd(mpz_class m, mpz_class n) {  
  mpz_class r;

  if (m < 0)
	 m = -m;
  if (n < 0)
	 n = -n;

  r = m % n;

  if (r == 0)
	 return n;

  while(r > 0) {
    m = n;
	 n = r;
	 r = m % n;
  }

  return n;
}

// Generate large prime number.
string gen_large_prime() {
	srand(time(0));
	mpz_class p;

	// Create char arrays to represent large prime p.
	char arr_p[BITSTRENGTH + 1] = {0};

	// First digit of p is nonzero.
	arr_p[0] = 48 + (std::rand() % 9 + 1);
	
	// Randomly assign each digit of p.
	for (int i = 1; i < BITSTRENGTH; i++) {
		arr_p[i] = 48 + rand() % 10;

		// qDebug() << arr_p[i];
	}
	// Convert arrays to type mpz_t (big integer).
	mpz_t q;
	mpz_init_set_str(q, arr_p, 10);
	
	mpz_nextprime(q, q);
	p = mpz_class(q);

	return p.get_str(10);
}

// Return vector is in the form {product, pub_key, priv_key}.
vector<string> gen_keys() {
	// Find two large primes.
	mpz_class p, q;
	p = mpz_class(gen_large_prime(), 10);
	q = mpz_class(gen_large_prime(), 10);

	mpz_class n;
	n = p * q;

	mpz_class x;
	x = (p - 1) * (q - 1);
	
	// Public key
	mpz_class e;
	e = PUBLIC_EXPONENT;
	
	while (mpz_gcd(x, e) != 1)
		e += 2;

	// Private key
	mpz_class d;
	mpz_t inverse;
	mpz_init(inverse);
	// Find inverse of e (mod x)
	mpz_invert(inverse, e.get_mpz_t(), x.get_mpz_t());
	d = mpz_class(inverse);

	string prod = n.get_str(10);
	string pub = e.get_str(10);
	string priv = d.get_str(10);
	
	// qDebug() << "product: " << QString(prod.c_str()) << "\npublic key: " << QString(pub.c_str()) << "\nprivate key: " << QString(priv.c_str());

	vector<string> key_vec {prod, pub, priv};
	// key_vec.push_back(prod).push_back(pub).push_back(priv);

	return key_vec;
}

// Quickly find base^exp modulo mod. 
string fast_modular_exp(mpz_class base, mpz_class exp, mpz_class mod) {
	mpz_class i = 0;
	mpz_class temp = 1;

	while (i < exp) {
		qDebug() << i.get_str(10).c_str();
		i += 1;
		temp = (base * temp) % mod;

		// qDebug() << "temp:" << temp.get_str(10).c_str();
	}

	return temp.get_str(10);
}

// Encode a string chunk of size MSG_CHUNK_LENGTH.
// What does encoding mean?
string encode_chunk(string chunk) {
	if (chunk.length() > MSG_CHUNK_LENGTH)
		return NULL;

	// Add 1 for the terminating null char, and 1 for the prepended padding.
	vector<char> code;

	code.push_back('1');
	for (uint i = 0; i < chunk.length(); i++) {
 		string cur_char = to_string((int) chunk[i]).c_str();
 		// qDebug() << cur_char.c_str();
 		if (cur_char.length() < 3) {
 			code.push_back('0');
 			code.push_back(cur_char[0]);
 			code.push_back(cur_char[1]);
 		}
 		else {
 			code.push_back(cur_char[0]);
 			code.push_back(cur_char[1]);
 			code.push_back(cur_char[2]);
 		}
	}

	return string(code.data());
}

string decode_chunk(string chunk) {
	chunk = chunk.substr(1, chunk.length());

	int len = chunk.length();
	if (len % 3 != 0)
		return NULL;
	
	vector<char> msg;

	for (uint i = 0; i < chunk.length(); i++) {
		string cur_char = chunk.substr(i, 3);
		char c = (char) stoi(cur_char, NULL, 10);
		msg.push_back(c);
	}

	return string(msg.data());
}

// Encrypt msg using RSA encryption algorithm.
string rsa_encrypt(string msg, string pub_key, string prod) {
	mpz_class e = mpz_class(pub_key);
	mpz_class n = mpz_class(prod);
	
	string encoded_msg;

	for (uint i = 0; i < msg.length(); i += MSG_CHUNK_LENGTH) 
		encoded_msg.append(encode_chunk(msg.substr(i, MSG_CHUNK_LENGTH)));	
	
	mpz_class m = mpz_class(encoded_msg);
	qDebug() << "Encoded message (pre-encryption): " << QString(m.get_str(10).c_str());

	string res = fast_modular_exp(m, e, n);
	qDebug() << "Encrypted message: " << QString(res.c_str());
	return res;
}

string rsa_decrypt(string code, string priv_key, string prod) {
	mpz_class c = mpz_class(code);
	mpz_class e = mpz_class(priv_key);
	mpz_class n = mpz_class(prod);

	string res = fast_modular_exp(c, e, n);
	qDebug() << "Decrypted message: " << QString(res.c_str());
	return res;
}
	