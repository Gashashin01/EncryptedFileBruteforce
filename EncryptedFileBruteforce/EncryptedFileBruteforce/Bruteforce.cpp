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
#include "Decrypt.h"
#include "Bruteforce.h"

#define BRUT_NUMBERS       (1<<0)
#define BRUT_ENG_LOWERCASE (1<<1)

Bruteforce::Bruteforce(Decrypt& decrypt) :
    m_decrypt(decrypt)
{}

void Bruteforce::SetAlphabet(int letterSet) {
    std::string letters;
    if (letterSet & BRUT_NUMBERS) { 
        letters += "0123456789"; 
    }
    if (letterSet & BRUT_ENG_LOWERCASE) { 
        letters += "abcdefghijklmnopqrstuvwxyz"; 
    }

    for (size_t i = 0; i < letters.size(); i++) {
        m_alphabet.push_back(letters[i]);
    }
}

std::string Bruteforce::BruteforcePassword(int brutforceSize, std::vector<unsigned char>& cipherText, std::vector<unsigned char>& cipherHash) {
    std::vector<int> password(brutforceSize); 
    for (size_t i = 0; i < password.size(); i++) {
        password[i] = 0;
    }
    
    std::string lastAviablePass = std::string(password.size(), m_alphabet.back());

    bool needBreakLoop = false;
    while (!needBreakLoop) {
        for (size_t letter = 0; letter < m_alphabet.size(); letter++) {
            password[0] = letter;
            std::string pass;
            for (size_t i = 0; i < password.size(); i++) {
                pass.push_back(m_alphabet[password[i]]);
            }
            if (m_decrypt.DecryptMain(pass)) {
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
    return std::string(); //Возвращаем пустую строку, если пароль не был найден
}

int Bruteforce::BruteforceMain() {
    int alphabet = BRUT_NUMBERS | BRUT_ENG_LOWERCASE;

    alphabet = BRUT_NUMBERS | BRUT_ENG_LOWERCASE;
    SetAlphabet(alphabet);
    
    int brutedpassSize = 0;
    auto begin = std::chrono::high_resolution_clock::now();
    while (true) {
        brutedpassSize++;
        if (brutedpassSize == 5) {
            std::cout << "Password not found";
            return -1;
        }
        std::vector<unsigned char> cipherHash = m_decrypt.GetCipherHash();
        std::vector<unsigned char> cipherText = m_decrypt.GetCipherText();
        std::string brutedpass = BruteforcePassword(brutedpassSize, cipherHash, cipherText);
        
        if (!brutedpass.empty()) {
            //оп, пароль найден, выводим
            auto end = std::chrono::high_resolution_clock::now();
            std::cout << "----------------------" << std::endl;
            std::cout << "Your password: " << brutedpass << std::endl;
            std::cout << "Bruteforce took: ";
            std::cout << std::chrono::duration_cast<std::chrono::seconds>(end - begin).count() << " second(s)" << std::endl;
            return 0;
        }
    }
}


