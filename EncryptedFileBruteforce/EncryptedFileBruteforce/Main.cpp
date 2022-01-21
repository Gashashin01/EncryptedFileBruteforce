#include "Decrypt.h"
#include "Bruteforce.h"

int main(int argc, const char* argv[]) {
    std::cout << "Bruteforcing..." << std::endl;
    std::vector<unsigned char> cipherText;
    ReadFile("chipher_text_brute_force", cipherText);
    std::vector<unsigned char> cipherHash = HashExtraction(cipherText);
    cipherText.erase(cipherText.begin() + (cipherText.size() - 32), cipherText.end());
    Decrypt decrypt(cipherText, cipherHash);
    Bruteforce brute(decrypt);
    brute.BruteforceMain();
}