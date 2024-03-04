/**
 * AES base implementation.
 **/

#include "protectedAES.h"
#include "lut.h"
#include "config.h"

// UTILITY FUNCTIONS

// x2 in GF(2^8)
#define xtime(x) \
  ((x << 1) ^ (((x >> 7) & 1) * 0x1B))

// Multiply is used to multiply numbers in the field GF(2^8)
#define Multiply(x, y) \
  (((y & 1) * x) ^                           \
   ((y >> 1 & 1) * xtime(x)) ^               \
   ((y >> 2 & 1) * xtime(xtime(x))) ^        \
   ((y >> 3 & 1) * xtime(xtime(xtime(x)))))

#ifdef HIDING

// timer1 interrupts, see ATMEGA328 datasheet
#define timerSetup(x) {TCCR1A = 0; TCCR1B = 0; TCNT1 = 0; OCR1A = x;}
#define timerStart() TCCR1B = _BV(WGM12) | _BV(CS10)
#define timerStop() TCCR1B = _BV(WGM12)

#endif


// PUBLIC METHODS

// constructor: keyLength must be one of 128, 192, 256
AES::AES(short keyLength) {
  #if defined MASKING || defined HIDING
  MCUSR = 0; WDTCSR |= _BV(WDCE) | _BV(WDE); WDTCSR = _BV(WDIE); // generate entropy
  #endif
  switch (keyLength) {
    case 128:
      Nk = 4;
      Nr = 10;
      break;
    case 192:
      Nk = 6;
      Nr = 12;
      break;
    case 256:
      Nk = 8;
      Nr = 14;
      break;
    default:
      return;
  }
  Sk = 16 * (Nr + 1);
  RoundKey = malloc(Sk* sizeof(byte));
  #ifdef HIDING
  timerSetup(1);
  TIMSK1 = _BV(OCIE1A);
  #endif
}

//destructor
AES::~AES() {
  free(RoundKey);
}

// This function perform key expansion and produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
void AES::setKey(const byte *Key) {
  byte i, j, k, l;
  byte tempa[5];  // Used for the column/row operations

  memcpy(RoundKey, Key, Nk * 4); // The first round key is the key itself.

  for (i = Nk; i < 4 * (Nr + 1); ++i) { // All other round keys are found from the previous round keys.
    
    memcpy(tempa, RoundKey + (i - 1) * 4, 4);
    
    if (i % Nk == 0) {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
      // then applies the S-box to each of the four bytes to produce an output word.
      tempa[4] = tempa[0];
      for (j = 0; j < 4; ++j)
        tempa[j] = LUT(sbox + tempa[j+1]);
      tempa[0] ^= LUT(Rcon + i / Nk);

    } else if (Nk == 8 && i % Nk == 4) {
      for (j = 0; j < 4; ++j) // Function Subword()
        tempa[j] = LUT(sbox + tempa[j]);
    }

    l = i * 4;
    k = (i - Nk) * 4;
    for (j = 0; j < 4; ++j)
      RoundKey[l + j] = RoundKey[k + j] ^ tempa[j];
  }
}

// block encryption both input and output must be 16 bytes long
void AES::encryptBlock(byte *output, const byte *input) {
  short i;
  #ifdef HIDING
  #ifdef DEBUG
  for(i=0;i<6;i++) debugHiding[i] = 0;
  #endif
  timerStart(); // start random interrupts
  #endif
  memcpy(state, input, 16); // copy input into internal state
  
  byte round;

  //SETUP MASKS
  #ifdef MASKING
  byte RoundKeyMasked[Sk];
  byte boxMasked[256];
  byte mask[10];
  byte zero[4] = {0,0,0,0};

  memcpy(RoundKeyMasked, RoundKey, Sk);

  //Randomly generate the masks: m1 m2 m3 m4 m m'
  initMask(mask);

  //Calculate m1',m2',m3',m4'
  mask[6] = xtime(mask[0]) ^ xtime(mask[1]) ^ mask[2]        ^ mask[3]        ^ mask[1];
  mask[7] = mask[0]        ^ xtime(mask[1]) ^ xtime(mask[2]) ^ mask[3]        ^ mask[2];
  mask[8] = mask[0]        ^ mask[1]        ^ xtime(mask[2]) ^ xtime(mask[3]) ^ mask[3];
  mask[9] = xtime(mask[0]) ^ mask[1]        ^ mask[2]        ^ xtime(mask[3]) ^ mask[0];

  //Calculate the the sbox to change from Mask m to Mask m'
  for (i = 0; i < 256; i++)
    boxMasked[i ^ mask[4]] = LUT(sbox+i) ^ mask[5];


  //Init masked key
  //	Last round mask M' to mask 0
  remask(RoundKeyMasked + (Nr * 16), zero, mask[5]);

  // Mask change from M1',M2',M3',M4' to M
  for (i = 0; i < Nr; i++)
    remask(RoundKeyMasked + (i * 16), mask + 6, mask[4]);
  #else // if no masking copy plain sbox
  byte *RoundKeyMasked = RoundKey;
  byte boxMasked[256];
  memcpy_P(boxMasked, sbox, 256);
  #endif

  #ifdef MASKING
  //Plain text masked with m1',m2',m3',m4'
  remask(state, mask + 6, 0);
  #endif
  
  // Masks change from M1',M2',M3',M4' to M
  AddRoundKey(state, RoundKeyMasked);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without MixColumns()
  for (round = 1;; round++) {
    // Mask changes from M to M'
    SubBytesAndShiftRows(state, boxMasked);
    
    if (round == Nr) break;
    //Change mask from M' to
    // M1 for first row
    // M2 for second row
    // M3 for third row
    // M4 for fourth row
    #ifdef MASKING
    remask(state, mask, mask[5]);
    #endif

    // Masks change from M1,M2,M3,M4 to M1',M2',M3',M4'
    MixColumns(state);

    // Add the First round key to the state before starting the rounds.
    // Masks change from M1',M2',M3',M4' to M
    AddRoundKey(state, RoundKeyMasked + (round * 16));
  }

  // Mask are removed by the last addroundkey
  // From M' to 0
  AddRoundKey(state, RoundKeyMasked + (Nr * 16));

  memcpy(output, state, 16);
  #ifdef HIDING
  timerStop();
  #endif
}

// block decryption both input and output must be 16 bytes long
void AES::decryptBlock(byte *output, const byte *input) {
  short i;
  #ifdef HIDING
  #ifdef DEBUG
  for(i=0;i<6;i++) debugHiding[i] = 0;
  #endif
  timerStart(); // start random interrupts
  #endif
  memcpy(state, input, 16); // copy input into internal state
  byte round;

  //SETUP MASK
  #ifdef MASKING
  byte RoundKeyMasked[Sk];
  byte boxMasked[256];
  byte mask[10];
  byte zero[4] = {0};

  memcpy(RoundKeyMasked, RoundKey, Sk);

  //Randomly generate the masks: m1 m2 m3 m4 m m'
  initMask(mask);

  //Calculate m1',m2',m3',m4'
  mask[6] = Multiply(mask[0], 14) ^ Multiply(mask[1], 11) ^ Multiply(mask[2], 13) ^ Multiply(mask[3], 9);
  mask[7] = Multiply(mask[0], 9)  ^ Multiply(mask[1], 14) ^ Multiply(mask[2], 11) ^ Multiply(mask[3], 13);
  mask[8] = Multiply(mask[0], 13) ^ Multiply(mask[1], 9)  ^ Multiply(mask[2], 14) ^ Multiply(mask[3], 11);
  mask[9] = Multiply(mask[0], 11) ^ Multiply(mask[1], 13) ^ Multiply(mask[2], 9)  ^ Multiply(mask[3], 14);

  //Calculate the the ReverseSbox to change from Mask m to Mask m'
  for (i = 0; i < 256; i++)
    boxMasked[i ^ mask[4]] = LUT(rsbox+i) ^ mask[5];

  //Init masked key
  remask(RoundKeyMasked + (Nr * 16), zero, mask[4]);

  for (i = 0; i < Nr; i++)
    remask(RoundKeyMasked + (i * 16), mask, mask[5]);
  #else  // if no masking copy plain invsbox
  byte *RoundKeyMasked = RoundKey;
  byte boxMasked[256];
  memcpy_P(boxMasked, rsbox, 256);
  #endif

  // Add the First round key to the state before starting the rounds.
  // Mask: 0 -> M
  AddRoundKey(state, RoundKeyMasked + (Nr * 16));

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without InvMixColumn()
  //for (round = (Nr - 1);; --round)
  for (round = (Nr - 1);; --round){
    //Mask: M -> M'
    InvSubBytesAndShiftRows(state, boxMasked);

    // Mask: M' -> M1, M2, M3, M4
    AddRoundKey(state, RoundKeyMasked + (round * 16));

    if (round == 0) break;
    
    // M1,M2,M3,M4 -> M1',M2',M3',M4'
    InvMixColumns(state);

    #ifdef MASKING
    //M1',M2',M3',M4' -> M
    remask(state, mask + 6, mask[4]);
    #endif
  }

  #ifdef MASKING
  //M1,M2,M3,M4 -> 0
  remask(state, mask, 0);
  #endif

  memcpy(output, state, 16);
  #ifdef HIDING
  timerStop();
  #endif
}

// OTHER METHODS

#if defined MASKING || defined HIDING
// PRNG based on Jenkins, Bob (2009). "A small noncryptographic PRNG" https://burtleburtle.net/bob/rand/smallprng.html
// seeded with an improved version of Entropy library https://code.google.com/p/avr-hardware-random-number-generation/

#define rot32(x,k) (((x)<<(k))|((x)>>(32-(k))))

volatile unsigned long AES::seed;
volatile char AES::seed_bit = 32;
volatile unsigned long AES::rng_state[4] = {0xF1EA5EED, 0,0,0};

unsigned long AES::get_random(){
  unsigned long tmp = rng_state[0] - rot32(rng_state[1], 27);
  rng_state[0] = rng_state[1] ^ rot32(rng_state[2], 17);
  rng_state[1] = rng_state[2] + rng_state[3];
  rng_state[2] = rng_state[3] + tmp;
  rng_state[3] = tmp + rng_state[0];
  return rng_state[3];
}


void AES::seed_random(){
  if(seed_bit > 0){
    seed_bit--;  // every time the WDT interrupt is triggered
    seed ^= (unsigned long) rot32(TCNT1L, seed_bit); // Record the Timer 1 low byte (higher bits aren't really random)
  }else{
    WDTCSR = 0; // stop entropy generator
    // The following code is an implementation of JSF
    for (byte i = 1; i < 4; i++) rng_state[i] = seed;
    for (byte i = 0; i < 20; i++) get_random();
  }
}

ISR(WDT_vect) {
  AES::seed_random();
}
#endif


#ifdef MASKING
// masking approach of Stefan Mangard, Elisabeth Oswald, Thomas Popp - Power Analysis Attacks Revealing the Secrets of Smart Cards (Advances in Information Security) (2007) 
// based on MELITY project implementation https://github.com/CENSUS/masked-aes-c
// mask: 4 bytes for MixColumns and 2 for SubBytes 

void AES::initMask(byte * mask){
    for (byte i = 0; i < 6; i++)
      mask[i] = get_random() % 0xFF;
    #ifdef DEBUG
    memcpy(debugMasking, mask, 6);
    #endif
}
#endif

#ifdef HIDING

#define NOP __asm__ __volatile__ ("nop\n\t")

#ifdef DEBUG
static volatile byte AES::debugHiding[6];
#endif

#ifdef MASKING
#define rand_interval 2000
#else
#define rand_interval 1500
#endif

void AES::rand_interrupt(){
  // 1 clock cycle = 0.0625 µs
  byte state[16];
  byte func = get_random() % 6;
  switch(func){
    case 0:
      AES::SubBytesAndShiftRows(state,(const)state);
      break;
    case 1:
      AES::InvSubBytesAndShiftRows(state,(const)state);
      break;
    case 2:
      AES::MixColumns(state);
      break;
    case 3:
      AES::InvMixColumns(state);
      break;
    case 4:
      AES::AddRoundKey(state,(const)state);
      break;
    case 5:
      for(byte i = get_random(); i > 0; --i)NOP;
      break;
  }
  #ifdef DEBUG
  AES::debugHiding[func]++;
  #endif
  timerSetup(get_random() % rand_interval + rand_interval);
  timerStart();
}

ISR(TIMER1_COMPA_vect){
  AES::rand_interrupt();
}
#endif


//Mask the input Array[16] with:
//	[....]				  [m1^m5|m1^m5|m1^m5|m1^m5]
//	[....]	EXOR		  [m2^m6|m2^m6|m2^m6|m2^m6]
//	[....]				  [m3^m7|m3^m7|m3^m7|m3^m7]
//	[....]				  [m4^m8|m4^m8|m5^m8|m4^m8]
#ifdef MASKING
void AES::remask(byte *s, byte* mi, byte mf) {
  // precompute xor between masks to avoid leakage
  byte t[4];
  for (byte i = 0; i < 4; i++)
    t[i] = mi[i] ^ mf;
  for (byte i = 0; i < 16; i++)
    s[i] ^= t[i%4];
}
#endif


// This function adds the masked round key to state.
// The round key is added to the state by an XOR function.
void AES::AddRoundKey(byte *state, const byte *roundKey) {
  for (byte i = 0; i < 16; i++)
    state[i] ^= roundKey[i];
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an masked S-box.
// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
void AES::SubBytesAndShiftRows(byte *state, const byte *sbox) {
  byte temp;
  
  state[0] = sbox[state[0]];
  state[4] = sbox[state[4]];
  state[8] = sbox[state[8]];
  state[12] = sbox[state[12]];

  // Rotate first row 1 columns to left
  temp = state[1];
  state[1] = sbox[state[5]];
  state[5] = sbox[state[9]];
  state[9] = sbox[state[13]];
  state[13] = sbox[temp];

  // Rotate second row 2 columns to left
  temp = state[2];
  state[2] = sbox[state[10]];
  state[10] = sbox[temp];
  temp = state[6];
  state[6] = sbox[state[14]];
  state[14] = sbox[temp];

  // Rotate third row 3 columns to left
  temp = state[3];
  state[3] = sbox[state[15]];
  state[15] = sbox[state[11]];
  state[11] = sbox[state[7]];
  state[7] = sbox[temp];
}

// MixColumns function mixes the columns of the state matrix
void AES::MixColumns(byte *state) {
  byte a, b, c, d;
  for (byte i = 0; i < 16; i+=4) {
    a = state[i + 0];
    b = state[i + 1];
    c = state[i + 2];
    d = state[i + 3];

    state[i + 0] = xtime(a) ^ xtime(b) ^      (c) ^      (d) ^ b;
    state[i + 1] =      (a) ^ xtime(b) ^ xtime(c) ^      (d) ^ c;
    state[i + 2] =      (a) ^      (b) ^ xtime(c) ^ xtime(d) ^ d;
    state[i + 3] = xtime(a) ^      (b) ^      (c) ^ xtime(d) ^ a;
  }
}

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
void AES::InvMixColumns(byte *state) {
  byte a, b, c, d;
  for (byte i = 0; i < 16; i+=4) {
    a = state[i + 0];
    b = state[i + 1];
    c = state[i + 2];
    d = state[i + 3];

    state[i + 0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    state[i + 1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    state[i + 2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    state[i + 3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}


// The InvSubBytes Function Substitutes the values in the
// state matrix with values in an masked invS-box.
void AES::InvSubBytesAndShiftRows(byte *state, const byte *rsbox) {
  byte temp;

  state[0] = rsbox[state[0]];
  state[4] = rsbox[state[4]];
  state[8] = rsbox[state[8]];
  state[12] = rsbox[state[12]];


  // Rotate first row 1 columns to right
  temp = state[13];
  state[13] = rsbox[state[9]];
  state[9] = rsbox[state[5]];
  state[5] = rsbox[state[1]];
  state[1] = rsbox[temp];

  // Rotate second row 2 columns to right
  temp = state[2];
  state[2] = rsbox[state[10]];
  state[10] = rsbox[temp];
  temp = state[6];
  state[6] = rsbox[state[14]];
  state[14] = rsbox[temp];

  // Rotate third row 3 columns to right
  temp = state[3];
  state[3] = rsbox[state[7]];
  state[7] = rsbox[state[11]];
  state[11] = rsbox[state[15]];
  state[15] = rsbox[temp];
}
