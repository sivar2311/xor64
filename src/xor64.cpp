#include "xor64.h"
#include "lib/base64.h"
#include "WString.h"

void xorBuf(char* buf, const char* input, const char* key, int input_len, int key_len) {
  for (int i=0; i<input_len; i++) {
    buf[i] = input[i] ^ key[i % key_len];
  }
}

/**
 * @brief Encode a plain-text string to a xor-encrypted base64 string using key string for xor encryption
 * 
 * @param input 
 * @param key 
 * @return String 
 */
String xorEncode64(String input, String key) {
  size_t input_len = input.length();
  size_t key_len = key.length();
  
  char* xor_buf = new char[input_len+1];
  xorBuf(xor_buf, input.c_str(), key.c_str(), input_len, key_len);

  size_t b64_enc_len = base64_enc_len(input_len);
  
  char* b64_buf = new char[b64_enc_len+1];
  base64_encode(b64_buf, xor_buf, input_len);

  String result(b64_buf);

  delete[] b64_buf;
  delete[] xor_buf;

  return result;
}

/**
 * @brief Decode a xor-encrypted base64 string to plain-text using key string for xor decryption
 * 
 * @param input 
 * @param key 
 * @return String 
 */
String xorDecode64(String input, String key) {
  size_t input_len = input.length();
  size_t key_len = key.length();

  size_t b64_dec_len = base64_dec_len((char*) input.c_str(), input_len);
  char* b64_buf = new char[b64_dec_len+1];
  base64_decode(b64_buf, (char*) input.c_str(), input_len);

  char* xor_buf = new char[b64_dec_len+1];
  xorBuf(xor_buf, b64_buf, key.c_str(), b64_dec_len, key_len);
  xor_buf[b64_dec_len] = '\0';

  String result(xor_buf);

  delete[] xor_buf;
  delete[] b64_buf;

  return result;
}
