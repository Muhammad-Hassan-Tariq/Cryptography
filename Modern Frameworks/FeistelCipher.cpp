#include <bitset>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
using std::bitset;
using std::cout;
using std::endl;
using std::invalid_argument;
using std::setw;
using std::string;
using std::vector;

#define SIZE 128
#define HALF_SIZE SIZE / 2

// ------------------ CONVERT STRING TO 128-BIT BITSET[FOR KEYS] ------------------
bitset<SIZE> stringToBitsetFromChars(const string &input) {
  bitset<SIZE> result;
  size_t totalBits = input.size() * 8;
  if (SIZE < totalBits)
    throw invalid_argument("Bitset too small for input string!");

  for (size_t i = 0; i < input.size(); ++i) {
    bitset<8> charBits(input[i]);
    for (size_t b = 0; b < 8; ++b) {
      result[(input.size() - 1 - i) * 8 + b] = charBits[b];
    }
  }
  return result;
}

// ------------------ CONVERT STRING TO 64-BIT BITSET[FOR KEYS] ------------------

bitset<HALF_SIZE> stringToHalfBitsetFromChars(const string &input) {
  bitset<HALF_SIZE> result;
  size_t totalBits = input.size() * 8;
  if (HALF_SIZE < totalBits)
    throw invalid_argument("Bitset too small for input string!");

  for (size_t i = 0; i < input.size(); ++i) {
    bitset<8> charBits(input[i]);
    for (size_t b = 0; b < 8; ++b) {
      result[(input.size() - 1 - i) * 8 + b] = charBits[b];
    }
  }
  return result;
}

// ------------------ 128-BIT PRINTING FUNCTION ------------------
void printBitset(bitset<SIZE> data) {
  for (size_t i = 0; i < data.size(); ++i) {
    if (i % 8 == 0)
      cout << " ";
    cout << data[i];
  }
  cout << endl;
}

// ------------------ 64-BIT PRINTING FUNCTION ------------------
void printHalfBitset(bitset<HALF_SIZE> data) {
  for (size_t i = 0; i < data.size(); ++i) {
    if (i % 8 == 0)
      cout << " ";
    cout << data[i];
  }
  cout << endl;
}

class FeistelCipher {
private:
  // ------------------ F(R, K) = R ⊕ K ------------------
  bitset<HALF_SIZE> Function(bitset<HALF_SIZE> right, bitset<HALF_SIZE> key) {
    bitset<HALF_SIZE> result;
    for (int i = 0; i < HALF_SIZE; i++)
      result[i] = right[i] ^ key[i];
    return result;
  }

public:
  // ------------------ ENCRYPTION FUNCTION ------------------
  bitset<SIZE> encrypt(bitset<SIZE> data, vector<bitset<HALF_SIZE>> keys) {
    int rounds = keys.size();
    bitset<SIZE> result = data;

    bitset<HALF_SIZE> left, right;
    for (int i = 0; i < HALF_SIZE; i++) {
      left[i] = result[i];
      right[i] = result[i + HALF_SIZE];
    }

    for (int i = 0; i < rounds; i++) {
      bitset<HALF_SIZE> temp = Function(right, keys[i]);
      for (int j = 0; j < HALF_SIZE; j++) {
        temp[j] = temp[j] ^ left[j];
      }

      left = right;
      right = temp;

      for (int j = 0; j < HALF_SIZE; j++) {
        result[j] = left[j];
        result[j + HALF_SIZE] = right[j];
      }
    }

    // Final swap
    for (int j = 0; j < HALF_SIZE; j++) {
      result[j] = right[j];
      result[j + HALF_SIZE] = left[j];
    }

    return result;
  }

  // ------------------ DECRYPTION FUNCTION ------------------
  bitset<SIZE> decrypt(bitset<SIZE> data, vector<bitset<HALF_SIZE>> keys) {
    int rounds = keys.size();
    bitset<SIZE> result = data;

    bitset<HALF_SIZE> left, right;
    for (int i = 0; i < HALF_SIZE; i++) {
      left[i] = result[i];
      right[i] = result[i + HALF_SIZE];
    }

    for (int i = rounds - 1; i >= 0; i--) {
      bitset<HALF_SIZE> temp = Function(right, keys[i]);
      for (int j = 0; j < HALF_SIZE; j++) {
        temp[j] = temp[j] ^ left[j];
      }

      left = right;
      right = temp;

      for (int j = 0; j < HALF_SIZE; j++) {
        result[j] = left[j];
        result[j + HALF_SIZE] = right[j];
      }
    }

    // Final swap
    for (int j = 0; j < HALF_SIZE; j++) {
      result[j] = right[j];
      result[j + HALF_SIZE] = left[j];
    }

    return result;
  }
};

// ------------------ MAIN FUNCTION ------------------
int main() {
  // Convert input and keys to bitsets
  bitset<SIZE> data = stringToBitsetFromChars("<--The Eagle-->");
  bitset<HALF_SIZE> key0 = stringToHalfBitsetFromChars("IJK123OP");
  bitset<HALF_SIZE> key1 = stringToHalfBitsetFromChars("98K92340");

  vector<bitset<HALF_SIZE>> keys = {key0, key1};

  // 🔐 Printing input + keys
  cout << "Original Plaintext Bitset:   ";
  printBitset(data);

  cout << "\nKey 1:   ";
  printHalfBitset(key0);

  cout << "Key 2:   ";
  printHalfBitset(key1);

  cout << "\nEncrypting...";
  FeistelCipher TheEagle;
  bitset<SIZE> encrypted = TheEagle.encrypt(data, keys);

  cout << "\nEncrypted Bitset:   ";
  printBitset(encrypted);

  cout << "\nDecrypting...";
  bitset<SIZE> decrypted = TheEagle.decrypt(encrypted, keys);

  cout << "\nDecrypted Bitset:   ";
  printBitset(decrypted);

  // Just a styled slogan at the end ✨
  string slogan = "<------------------------The Eagle------------------------>";
  cout << "\n"
       << setw(80) << slogan << "\n";
}
