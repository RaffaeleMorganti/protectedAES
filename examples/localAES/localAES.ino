#include <protectedAES.h>

void setup() {
  Serial.begin(9600);
}


void loop() {
  const byte key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
  };

  AES aes(256); // new AES object with 256 bit key
  aes.setKey(key); // set the key

  byte pText[16] = "16 bytes of text";
  
  // Encryption of a 16 bytes block
  byte cText[16];
  aes.encryptBlock(cText, pText);
  
  // Decryption of a 16 bytes block
  byte dText[16];
  aes.decryptBlock(dText, cText);

  // Show results
  Serial.print("\nPlain text: ");
  Serial.write(pText, 16);
  Serial.print("\nCiphertext: ");
  Serial.write(cText, 16);
  Serial.print("\nDeciphered: ");
  Serial.write(dText, 16);
  Serial.println("\n");
  delay(1000);
}
