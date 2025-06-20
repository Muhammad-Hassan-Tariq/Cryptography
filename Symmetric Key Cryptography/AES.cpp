/*----------------------------------------------------AES Core Implementation (128-bit) 🔐 ----------------------------------------------------*/
/* Author      : Hassan (a.k.a. The Eagle 🦅)
 * Description : Core logic for AES block cipher operations, including:
 *               - Galois Field multiplication (GF(2^8))
 *               - S-box and Inverse S-box generation
 *               - Key expansion (AES-128)
 *
 * Note        : This is a minimal, clean AES core for educational and experimental use.
 *               No dependencies, no fluff — just pure C++ logic.
 *
 * License     : Public Domain / MIT — use it, break it, improve it 👨‍💻
 * GitHub      : [your GitHub URL if you want to add it]
 *
 * To-Do       :
 *               - Add full AES encrypt/decrypt functions
 *               - Implement MixColumns, ShiftRows, and AddRoundKey
 *               - Integrate with CBC/CTR/ECB mode as needed
 *
 * Last Updated: 20 June 2025
 */

#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>
#include <vector>
using std::cout;
using std::endl;
constexpr size_t BLOCK_SIZE = 16;
namespace aes {

}

/*----------------------------------------------------Structure for Returning State & Key----------------------------------------------------*/
// Holds both the AES state and the round key for encryption/decryption
struct Statekey {
   uint8_t state[16], key[16];
};

/*----------------------------------------------------AES Sboxes----------------------------------------------------*/
// Used in SubBytes for encryption (forward transformation)
static uint8_t sbox[16][16] = {
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}};
// Used in SubBytes for decryption (reverse transformation)
static uint8_t inv_sbox[16][16] = {
    {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
    {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
    {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
    {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
    {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
    {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
    {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
    {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
    {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
    {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
    {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
    {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
    {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
    {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
    {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}};

class AES {
 private:
   /*----------------------------------------------------AES Private Data----------------------------------------------------*/
   uint8_t state[4][4], key[4][4];                               // State & Key [4x4]
   std::vector<std::array<std::array<uint8_t, 4>, 4>> roundKeys; // Round Keys vector<[4x4]>
   static const uint8_t Rcon[11];                                // Round Constant [11]

   /*----------------------------------------------------Sub-Bytes Functions----------------------------------------------------*/
   //  Sub-Bytes --> Encryption
   void subBytes() {
      for (int r = 0; r < 4; r++)
         for (int c = 0; c < 4; c++) {
            uint8_t b = state[r][c];
            state[r][c] = sbox[b >> 4][b & 0xF];
         }
   }
   //  Sub-Bytes --> Decryption
   void invSubBytes() {
      for (int r = 0; r < 4; r++)
         for (int c = 0; c < 4; c++) {
            uint8_t b = state[r][c];
            state[r][c] = inv_sbox[b >> 4][b & 0xF];
         }
   }
   /*----------------------------------------------------Shift Row Functions----------------------------------------------------*/
   //  Shift Rows --> Encryption
   void shiftRows() {
      for (int i = 1; i < 4; i++) {
         uint8_t tmp[4];
         for (int j = 0; j < 4; j++)
            tmp[j] = state[i][(j + i) % 4];
         for (int j = 0; j < 4; j++)
            state[i][j] = tmp[j];
      }
   }
   //  Shift Rows --> Decryption
   void invShiftRows() {
      for (int i = 1; i < 4; i++) {
         uint8_t tmp[4];
         for (int j = 0; j < 4; j++)
            tmp[(j + i) % 4] = state[i][j];
         for (int j = 0; j < 4; j++)
            state[i][j] = tmp[j];
      }
   }
   /*----------------------------------------------------Mix Column Functions----------------------------------------------------*/
   //  Helper Functions
   uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0)); }
   uint8_t mul(uint8_t x, uint8_t y) {
      uint8_t res = 0;
      while (y) {
         if (y & 1)
            res ^= x;
         x = xtime(x);
         y >>= 1;
      }
      return res;
   }
   //  Mix Columns --> Encryption
   void mixCols() {
      for (int c = 0; c < 4; c++) {
         uint8_t a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
         state[0][c] = mul(a0, 2) ^ mul(a1, 3) ^ a2 ^ a3;
         state[1][c] = a0 ^ mul(a1, 2) ^ mul(a2, 3) ^ a3;
         state[2][c] = a0 ^ a1 ^ mul(a2, 2) ^ mul(a3, 3);
         state[3][c] = mul(a0, 3) ^ a1 ^ a2 ^ mul(a3, 2);
      }
   }
   //  Mix Columns --> Decryption
   void invMixCols() {
      for (int c = 0; c < 4; c++) {
         uint8_t a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
         state[0][c] = mul(a0, 14) ^ mul(a1, 11) ^ mul(a2, 13) ^ mul(a3, 9);
         state[1][c] = mul(a0, 9) ^ mul(a1, 14) ^ mul(a2, 11) ^ mul(a3, 13);
         state[2][c] = mul(a0, 13) ^ mul(a1, 9) ^ mul(a2, 14) ^ mul(a3, 11);
         state[3][c] = mul(a0, 11) ^ mul(a1, 13) ^ mul(a2, 9) ^ mul(a3, 14);
      }
   }
   /*----------------------------------------------------Key Generation Functions----------------------------------------------------*/
   //  Function to Get Random Bytes for Key Generation
   uint8_t getRandomByte() {
      std::random_device rd;
      return (uint8_t)(rd() & 0xFF);
   }
   //  Adding Round Key to State
   void addRoundKey(int r) {
      for (int i = 0; i < 16; i++) {
         state[i % 4][i / 4] ^= roundKeys[r][i % 4][i / 4];
      }
   }
   // Key expansion helper
   std::array<uint8_t, 4> rotWord(std::array<uint8_t, 4> w) {
      uint8_t t = w[0];
      w[0] = w[1];
      w[1] = w[2];
      w[2] = w[3];
      w[3] = t;
      return w;
   }
   // Key expansion helper
   std::array<uint8_t, 4> subWord(const std::array<uint8_t, 4> &w) {
      std::array<uint8_t, 4> res;
      for (int i = 0; i < 4; i++) {
         res[i] = sbox[w[i] >> 4][w[i] & 0xF];
      }
      return res;
   }
   // Round Keys Generator Function
   void generateRoundKeys() {
      std::array<std::array<uint8_t, 4>, 44> W;
      // Copy initial key (column-wise) into W[0..3]
      for (int c = 0; c < 4; c++) {
         for (int r = 0; r < 4; r++) {
            W[c][r] = key[r][c];
         }
      }
      for (int i = 4; i < 44; i++) {
         auto temp = W[i - 1];
         if (i % 4 == 0) {
            temp = rotWord(temp);
            temp = subWord(temp);
            temp[0] ^= Rcon[i / 4];
         }
         for (int j = 0; j < 4; j++) {
            W[i][j] = W[i - 4][j] ^ temp[j];
         }
      }
      roundKeys.resize(11);
      for (int r = 0; r < 11; r++) {
         for (int c = 0; c < 4; c++) {
            for (int rr = 0; rr < 4; rr++) {
               roundKeys[r][rr][c] = W[r * 4 + c][rr];
            }
         }
      }
   }

   /*----------------------------------------------------Encryption Function----------------------------------------------------*/
   void encrypt() {
      addRoundKey(0);
      for (int r = 1; r < 10; r++) {
         subBytes();
         shiftRows();
         mixCols();
         addRoundKey(r);
      }
      subBytes();
      shiftRows();
      addRoundKey(10);
   }

   /*----------------------------------------------------Decryption Function----------------------------------------------------*/
   void decrypt() {
      addRoundKey(10);
      for (int r = 9; r >= 1; r--) {
         invShiftRows();
         invSubBytes();
         addRoundKey(r);
         invMixCols();
      }
      invShiftRows();
      invSubBytes();
      addRoundKey(0);
   }

 public:
   /*----------------------------------------------------Encrypt Function----------------------------------------------------*/
   Statekey encryptData(const uint8_t in[BLOCK_SIZE], bool isVerbose = false) {
      // Load input plaintext into the AES state matrix (column-major order)
      for (int i = 0; i < 16; i++) {
         state[i % 4][i / 4] = in[i];
      }

      // Generate a fresh random 128-bit key (16 bytes)
      for (int i = 0; i < 16; i++) {
         key[i / 4][i % 4] = getRandomByte();
      }
      // Expand the key for all AES rounds
      generateRoundKeys();

      // Print initial state and key if verbose mode is ON
      if (isVerbose) {
         cout << "Initial State and Key:" << endl;
         printState();
         printKey();
      }

      // Perform AES encryption on the state
      encrypt();
      // Print encrypted result if verbose mode is ON
      if (isVerbose) {
         cout << "\nEncrypted State (Ciphertext):" << endl;
         printState();
      }

      // Package state and key into a return struct
      Statekey result;
      for (int i = 0; i < 16; i++) {
         result.state[i] = state[i % 4][i / 4];
         result.key[i] = key[i % 4][i / 4];
      }

      return result;
   }

   /*----------------------------------------------------Decrypt Function----------------------------------------------------*/
   Statekey decryptData(const Statekey &encrypted, bool isVerbose = false) {
      // Load ciphertext into the AES state matrix (column-major order)
      for (int i = 0; i < 16; i++) {
         state[i % 4][i / 4] = encrypted.state[i];
      }

      // Load the original encryption key into the key matrix
      for (int i = 0; i < 16; i++) {
         key[i % 4][i / 4] = encrypted.key[i];
      }
      // Expand the decryption round keys
      generateRoundKeys();

      // Print initial state and key if verbose mode is ON
      if (isVerbose) {
         cout << "Initial State and Key:" << endl;
         printState();
         printKey();
      }

      // Perform AES decryption on the state
      decrypt();
      // Print decrypted result if verbose mode is ON
      if (isVerbose) {
         cout << "\nDecrypted State (Plaintext):" << endl;
         printState();
      }

      // Package decrypted state and key into return struct
      Statekey result;
      for (int i = 0; i < 16; i++) {
         result.state[i] = state[i % 4][i / 4];
         result.key[i] = key[i % 4][i / 4];
      }
      return result;
   }

   /*----------------------------------------------------Debug Print State----------------------------------------------------*/
   void printState() const {
      cout << "State Matrix:" << endl;
      for (int r = 0; r < 4; r++) {
         for (int c = 0; c < 4; c++) {
            cout << std::hex << std::setw(2) << std::setfill('0') << (int)state[r][c] << " ";
         }
         cout << endl;
      }
   }

   /*----------------------------------------------------Debug Print Key----------------------------------------------------*/
   void printKey() const {
      cout << "Key Matrix:" << endl;
      for (int r = 0; r < 4; r++) {
         for (int c = 0; c < 4; c++) {
            cout << std::hex << std::setw(2) << std::setfill('0') << (int)key[r][c] << " ";
         }
         cout << endl;
      }
   }
};
const uint8_t AES::Rcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

int main() {
   // 16-byte plaintext block
   uint8_t test[BLOCK_SIZE] = {
       'T', 'H', 'E', ' ',
       ' ', ' ', ' ', ' ',
       ' ', ' ', ' ', 'E',
       'A', 'G', 'L', 'E'};
   AES sample;
   Statekey encrypted = sample.encryptData(test);
   Statekey decrypted = sample.decryptData(encrypted);

   /*----------------------------------------------------Verification----------------------------------------------------*/
   cout << "Original Text: ";
   for (int i = 0; i < BLOCK_SIZE; i++) {
      cout << test[i];
   }
   cout << "\nEncrypted Text: ";
   for (int i = 0; i < BLOCK_SIZE; i++) {
      cout << encrypted.state[i];
   }
   cout << "\nDecrypted Text: ";
   for (int i = 0; i < BLOCK_SIZE; i++) {
      cout << decrypted.state[i];
   }
   /*----------------------------------------------------Ending Note----------------------------------------------------*/
   std::string slogan = "<------------------------The Eagle------------------------>";
   cout << endl
        << std::setw(160) << slogan;
}