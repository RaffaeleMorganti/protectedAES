/**
 * AES base class: support AES128, AES192, AES256.
 * this class only allow encryption and decription of 16 bytes blocks.
 **/

#ifndef _PROTECTEDAES_H_
#define _PROTECTEDAES_H_

#include <Arduino.h>
#include "config.h"

class AES {
public:
  AES(short keyLength); // keyLength: 128, 192, 256
  ~AES();
  void setKey(const byte key[]);
  void encryptBlock(byte output[], const byte input[]);
  void decryptBlock(byte output[], const byte input[]);
  #if defined DEBUG && defined MASKING
  byte debugMasking[6];
  #endif
  #if defined DEBUG && defined HIDING
  static volatile byte debugHiding[6];
  #endif
  #if defined MASKING || defined HIDING
  static void seed_random();
  #endif
  #ifdef HIDING
  static void rand_interrupt();
  #endif
protected:
  static void AddRoundKey(byte *state, const byte *roundKey);
  static void SubBytesAndShiftRows(byte *state, const byte *sbox);
  static void MixColumns(byte *state);
  static void InvSubBytesAndShiftRows(byte *state, const byte *rsbox);
  static void InvMixColumns(byte *state);
  byte Nk; // words of the key
  byte Nr; // AES rounds
  byte Sk; // expanded key size
  byte *RoundKey;
  byte state[16];
  #ifdef MASKING
  static void remask(byte *s, byte mi[4], byte mf);
  void initMask(byte *mask);
  #endif
  #if defined MASKING || defined HIDING
  static unsigned long get_random();
  static volatile unsigned long rng_state[4];
  static volatile unsigned long seed;
  static volatile char seed_bit;
  #endif
};


#endif // _AES_H_
