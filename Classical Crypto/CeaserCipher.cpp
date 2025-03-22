#include <iostream>
#include <iomanip>
#include <string>
using namespace std;

// ------------------ ENCRYPTION FUNCTION ------------------
string encrypt(int key, string text) {
    cout << "\nEncryption:\n";
    string result = "";

    for (int i = 0; i < text.size(); i++) {
        char ch = text[i];

        // Check if character is lowercase alphabet
        if(ch >= 'a' && ch <= 'z') {
            // Normalize to 0–25 range using ASCII: ('a' → 0, 'z' → 25)
            // Then apply shift using mod 26 to wrap around
            char enc = ((ch - 'a' + key) % 26) + 'a';

            // Print and append encrypted character
            cout << enc;
            result += enc;
        } else {
            // If not lowercase alphabet (e.g., space, punctuation), keep it same
            result += ch;
            cout << ch;
        }
    }
    return result;
}

// ------------------ DECRYPTION FUNCTION ------------------
string decrypt(int key, string text) {
    cout << "\nDecryption:\n";
    string result = "";

    for (int i = 0; i < text.size(); i++) {
        char ch = text[i];

        // Check if character is lowercase alphabet
        if(ch >= 'a' && ch <= 'z') {
            // Reverse the shift: (original index - key)
            // +26 ensures no negative values before applying mod 26
            char dec = ((ch - 'a' - key + 26) % 26) + 'a';

            // Print and append decrypted character
            cout << dec;
            result += dec;
        } else {
            // Keep non-alphabet characters as-is
            result += ch;
            cout << ch;
        }
    }
    return result;
}

// ------------------ MAIN FUNCTION ------------------
int main() {
    // Encrypt the text "hassanz" with a key shift of 9
    string text = encrypt(9, "hassanz");

    // Decrypt the result back to original using the same key
    decrypt(9, text);

    // Just a styled slogan at the end ✨
    string slogan = "<------------------------The Eagle------------------------>";
    cout << endl << setw(80) << slogan;
}
