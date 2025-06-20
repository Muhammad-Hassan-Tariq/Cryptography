/*----------------------------------------------------RSA + Random Number Generator 🛡️----------------------------------------------------*/
/* Author      : Hassan (a.k.a. The Eagle 🦅)
 * Description : Core RSA encryption/decryption system using:
 *               - Random prime number generation
 *               - Public/private key pair generation
 *               - Modular exponentiation
 *
 *
 * Note        : This is a pure C++ RSA educational module. No 3rd-party libs used.
 *
 * License     : Public Domain / MIT — use it, break it, improve it 👨‍💻
 *
 * Last Updated: 20 June 2025
 */

#include <bitset>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
using namespace std;

/*----------------------------------------------------🎲 Random Number + Prime Generator ----------------------------------------------------*/
class RandomNo {
 public:
   int generateRandom(int r1, int r2) {
      random_device rd;
      mt19937 eng(rd());
      uniform_int_distribution<> distr(r1, r2);
      return distr(eng);
   }

   bool isPrime(int n) {
      if (n <= 1)
         return false;
      if (n <= 3)
         return true;
      if (n % 2 == 0 || n % 3 == 0)
         return false;
      for (int i = 5; i * i <= n; i += 6)
         if (n % i == 0 || n % (i + 2) == 0)
            return false;
      return true;
   }

   int generateRandomPrime(int lower, int upper) {
      random_device rd;
      mt19937 eng(rd());
      uniform_int_distribution<> distr(lower, upper);
      int prime;
      do {
         prime = distr(eng);
      } while (!isPrime(prime));
      return prime;
   }
};

/*----------------------------------------------------🔐 RSA Encryption / Decryption Core ----------------------------------------------------*/
class RSA : private RandomNo {

 private:
   int privateKey, publicKey, prime01, prime02, product, totient;

   int generatePublicKey() {
      for (int i = totient / 2; i < totient; i++) {
         if (!isPrime(i))
            continue;

         bool isFactor = false;
         for (int j = 0; j < i; j++) {
            if (j * i == totient) {
               isFactor = true;
               break;
            }
         }
         if (!isFactor)
            return i;
      }
      return -1;
   }

   int generatePrivateKey() {
      int i = 1;
      while (true) {
         int temp = (publicKey * i) % totient;
         if (temp == 1 && i != publicKey)
            return i;
         i++;
      }
   }

 public:
   RSA() {
      prime01 = generateRandomPrime(1, 160);
      prime02 = generateRandomPrime(161, 1600);
      product = prime01 * prime02;
      totient = (prime01 - 1) * (prime02 - 1);
      publicKey = generatePublicKey();
      cout << "\nPublic Key: " << publicKey;
      privateKey = generatePrivateKey();
      cout << "\nPrivate Key: " << privateKey << endl;
   }

   unsigned long long modular_pow(unsigned long long base, unsigned long long exp, unsigned long long mod) {
      unsigned long long result = 1;
      base = base % mod;
      while (exp > 0) {
         if (exp % 2 == 1)
            result = (result * base) % mod;
         exp = exp >> 1;
         base = (base * base) % mod;
      }
      return result;
   }

   vector<unsigned long long> encrypt(const string &str) {
      vector<unsigned long long> encrypted;
      for (char c : str) {
         int ascii = static_cast<int>(c);
         encrypted.push_back(modular_pow(ascii, publicKey, product));
      }
      return encrypted;
   }

   string decrypt(const vector<unsigned long long> &data) {
      string result = "";
      for (auto val : data) {
         result += static_cast<char>(modular_pow(val, privateKey, product));
      }
      return result;
   }
};

/*----------------------------------------------------🚀 Main Driver ----------------------------------------------------*/
int main() {
   RSA rsa;
   string msg = "Eagle";

   auto encrypted = rsa.encrypt(msg);
   cout << "\nEncrypted: ";
   for (auto val : encrypted)
      cout << val << " ";

   cout << "\nDecrypted: " << rsa.decrypt(encrypted) << endl;
}
