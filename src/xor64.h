/**
 * @file xor64.h
 * @author Boris Jäger (sivar2311@googlemail.com)
 * @brief xor-base64 encryption and decryption
 * @version 0.1
 * @date 2020-10-23
 * 
 * @copyright Copyright (c) 2020
 * 
 */

#ifndef _XOR64_H_
#define _XOR64_H_

#include "WString.h"

String xorEncode64(String input, String key);
String xorDecode64(String input, String key);

#endif