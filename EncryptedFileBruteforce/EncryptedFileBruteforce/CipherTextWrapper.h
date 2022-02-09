#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <exception>
#include <iostream>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

void ReadFile(const std::string& filePath, std::vector<unsigned char>& buf);
std::vector<unsigned char> HashExtraction(std::vector<unsigned char> cipherText);

class CipherTextWrapper {
public:
	CipherTextWrapper(const std::vector<unsigned char>& cipherText, const std::vector<unsigned char>& cipherHash);
	bool CheckPassword(std::string& passw);
	std::vector<unsigned char>& GetCipherText();
	std::vector<unsigned char>& GetCipherHash();
private:	
	void PasswordToKey(std::string& password);
	void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash);
	bool DecryptAes(std::vector<unsigned char>& plainText);
	void WriteFile(const std::string& filePath, const std::vector<unsigned char>& buf);

private:
	const EVP_MD* m_dgst;
	std::vector<unsigned char> m_cipherText;
	std::vector<unsigned char> m_cipherHash;
	unsigned char m_key[EVP_MAX_KEY_LENGTH];
	unsigned char m_iv[EVP_MAX_IV_LENGTH];
};
