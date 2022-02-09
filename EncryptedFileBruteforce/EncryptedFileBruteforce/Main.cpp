#include <filesystem>
#include "CipherTextWrapper.h"
#include "Bruteforce.h"

int main(int argc, const char* argv[]) {
    std::string filePath;
    std::cout << "Enter file path >> ";
    std::cin >> filePath;
    
    if (!std::filesystem::exists(filePath)) {
        std::cout << "File not found";
        return -1;
    }

    std::cout << "Bruteforcing..." << std::endl;
    std::vector<unsigned char> cipherText;
    ReadFile(filePath, cipherText);
    std::vector<unsigned char> cipherHash = HashExtraction(cipherText);
    cipherText.erase(cipherText.begin() + (cipherText.size() - 32), cipherText.end());
    CipherTextWrapper decrypt(cipherText, cipherHash);
    Bruteforce brute(decrypt);
    brute.BruteforceMain();
}