//http://alumni.cs.ucr.edu/~anirban/Anir%20-%20NCW03.pdf

#include "gmp/gmpxx.h"



// Size of the RSA modulus in bits.
#define BITSTRENGTH 512
#define PUBLIC_EXPONENT 65537
// Break message up into chunks of this size.
#define MSG_CHUNK_LENGTH 4

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
	p = mpz_class(gen_large_prime());
	q = mpz_class(gen_large_prime());
	
	// qDebug() << "Primes: " << p.get_str().c_str() << "\n\n\n" << q.get_str().c_str();

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
	
	// Test that multiplicative inverse d is correct.
	// mpz_class inv_test = (d * e) % x;
	// qDebug() << "INVERT RESULT!!!! " << inv_test.get_str(10).c_str();

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
		// qDebug() << i.get_str(10).c_str();
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
		return "";

	vector<char> code;

	for (uint i = 0; i < chunk.length(); i++) {
 		string cur_char = to_string((int) chunk[i]).c_str();
 		// qDebug() << "Current character: " << cur_char.c_str();
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

	code.push_back('\0');
	return string(code.data());
}



// Encrypt msg using RSA encryption algorithm.
string rsa_encrypt(string msg, string pub_key, string prod) {
	mpz_class e = mpz_class(pub_key);
	mpz_class n = mpz_class(prod);
	
	string encoded_msg = "1";

	for (uint i = 0; i < msg.length(); i += MSG_CHUNK_LENGTH) 
		encoded_msg.append(encode_chunk(msg.substr(i, MSG_CHUNK_LENGTH)));	
	
	mpz_class m = mpz_class(encoded_msg);
	qDebug() << "Encoded message (pre-encryption): " << QString(m.get_str(10).c_str());
	
	// mpz_powm_sec
	// x.get_mpz_t()
	mpz_t rop;
	mpz_init(rop);

	mpz_powm_sec(rop, m.get_mpz_t(), e.get_mpz_t(), n.get_mpz_t());

	string res = mpz_class(rop).get_str(10);
	qDebug() << "Encrypted message: " << QString(res.c_str());

	// string test = fast_modular_exp(m, e, n);
	// qDebug() << "Encrypt test: " << QString(test.c_str());
	return res;
}

string decode_chunk(string chunk) {
	if (chunk.length() > 3 * MSG_CHUNK_LENGTH)
		return "";

	// int len = chunk.length();
	// if (len % 3 != 0)
	// 	return "";
	
	vector<char> msg;
	
	for (uint i = 0; i < chunk.length(); i+=3) {
		string cur_char = chunk.substr(i, 3);
		// qDebug() << cur_char;

		char c = (char) stoi(cur_char);
		qDebug() << c;
		msg.push_back(c);
	}

	msg.push_back('\0');
	return string(msg.data());
}

string decode_msg(string msg) {
	string decoded_msg = "";

	// Start at 1, to throw away 0-index bit (which was used as padding).
	for (uint i = 1; i < msg.length(); i += MSG_CHUNK_LENGTH * 3) {
		qDebug() << "To decrypt: " << msg.substr(i, 3 * MSG_CHUNK_LENGTH).c_str();
		// qDebug() << "Decrypt chunk: " << decode_chunk(msg.substr(i, 3 * MSG_CHUNK_LENGTH)).c_str();
		decoded_msg.append(decode_chunk(msg.substr(i, 3 * MSG_CHUNK_LENGTH)));	
	}
	
	return decoded_msg;
}

string rsa_decrypt(string code, string priv_key, string prod) {
	mpz_class c = mpz_class(code);
	mpz_class d = mpz_class(priv_key);
	mpz_class n = mpz_class(prod);

	mpz_t rop;
	mpz_init(rop);
	mpz_powm_sec(rop, c.get_mpz_t(), d.get_mpz_t(), n.get_mpz_t());
	string res = decode_msg(mpz_class(rop).get_str(10));
	qDebug() << "Decrypted message: " << QString(res.c_str());

	return res;
}
	