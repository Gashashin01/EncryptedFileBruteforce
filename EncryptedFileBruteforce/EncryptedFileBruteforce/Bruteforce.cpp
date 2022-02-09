#include <string>
#include <vector>
#include <fstream>
#include <exception>
#include <iostream>
#include <algorithm>
#include <chrono>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include "Bruteforce.h"

Bruteforce::Bruteforce(CipherTextWrapper& decrypt) :
    m_decrypt(decrypt)
{
    SetAlphabet();
}

void Bruteforce::SetAlphabet() {
    std::string letters = "0123456789abcdefghijklmnopqrstuvwxyz";

    for (size_t i = 0; i < letters.size(); i++) {
        m_alphabet.push_back(letters[i]);
    }
}

std::string Bruteforce::BruteforcePassword(int brutforceSize) {
    std::vector<int> password(brutforceSize);
    
    std::string lastAviablePass = std::string(password.size(), m_alphabet.back());

    bool needBreakLoop = false;
    while (!needBreakLoop) {
        for (size_t letter = 0; letter < m_alphabet.size(); letter++) {
            password[0] = letter;
            std::string pass;
            for (size_t i = 0; i < password.size(); i++) {
                pass.push_back(m_alphabet[password[i]]);
            }
            if (m_decrypt.CheckPassword(pass)) {
                return pass;
            }
            else if (pass == lastAviablePass) {
                needBreakLoop = true;
            }
        }
        for (size_t i = 1; i < password.size(); i++) {
            password[i]++;
            if (password[i] == m_alphabet.size()) {
                password[i] = 0;
            }
            else {
                break;
            }
        }
    }
    return std::string();
}

int Bruteforce::BruteforceMain() {
    
    int brutedpassSize = 0;
    auto begin = std::chrono::high_resolution_clock::now();
    while (true) {
        brutedpassSize++;
        if (brutedpassSize == 5) {
            std::cout << "Password not found";
            return -1;
        }
        std::string brutedpass = BruteforcePassword(brutedpassSize);
        
        if (!brutedpass.empty()) {
            auto end = std::chrono::high_resolution_clock::now();
            std::cout << "----------------------" << std::endl;
            std::cout << "Your password: " << brutedpass << std::endl;
            std::cout << "Bruteforce took: ";
            std::cout << std::chrono::duration_cast<std::chrono::seconds>(end - begin).count() << " second(s)" << std::endl;
            return 0;
        }
    }
}


