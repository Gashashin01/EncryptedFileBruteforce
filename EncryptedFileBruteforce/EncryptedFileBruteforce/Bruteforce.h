#pragma once
#include "Decrypt.h"

#define BRUT_NUMBERS       (1<<0)
#define BRUT_ENG_LOWERCASE (1<<1)

class Bruteforce {
public:
	Bruteforce(Decrypt& decrypt);
	int BruteforceMain();
private:
	void SetAlphabet(int letterSet);
	std::string BruteforcePassword(int brutforceSize, std::vector<unsigned char>& cipherText, std::vector<unsigned char>& cipherHash);
private:
	Decrypt m_decrypt;
	std::vector<char> m_alphabet;
};