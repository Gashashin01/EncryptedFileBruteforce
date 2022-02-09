#pragma once
#include "CipherTextWrapper.h"

class Bruteforce {
public:
	Bruteforce(CipherTextWrapper& decrypt);
	int BruteforceMain();
private:
	void SetAlphabet();
	std::string BruteforcePassword(int brutforceSize);
private:
	CipherTextWrapper m_decrypt;
	std::vector<char> m_alphabet;
};