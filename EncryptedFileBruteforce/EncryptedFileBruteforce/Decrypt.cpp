#include "Decrypt.h"

std::vector<unsigned char> HashExtraction(std::vector<unsigned char> cipherText) {
    const size_t hashSize = 32;
    std::vector<unsigned char> hash(cipherText);
    hash.erase(hash.begin(), hash.end() - hashSize);
    return hash;
}

void ReadFile(const std::string& filePath, std::vector<unsigned char>& buf)
{
    std::basic_fstream<unsigned char> fileStream(filePath, std::ios::binary | std::fstream::in);
    if (!fileStream.is_open())
    {
        throw std::runtime_error("Can not open file " + filePath);
    }

    buf.clear();
    buf.insert(buf.begin(), std::istreambuf_iterator<unsigned char>(fileStream), std::istreambuf_iterator<unsigned char>());
}

Decrypt::Decrypt(const std::vector<unsigned char>& cipherText, const std::vector<unsigned char>& cipherHash) :
    m_cipherText(cipherText),
    m_cipherHash(cipherHash)
{
}

std::vector<unsigned char> Decrypt::GetCipherText() {
    return m_cipherText;
}

std::vector<unsigned char> Decrypt::GetCipherHash() {
    return m_cipherHash;
}

void Decrypt::PasswordToKey(std::string& password)
{
    OpenSSL_add_all_digests();
    const EVP_MD* dgst = EVP_get_digestbyname("MD5");
    if (!dgst)
    {
        throw std::runtime_error("no such digest");
    }
    unsigned char* pass = reinterpret_cast<unsigned char*>(&password[0]);
    const unsigned char* salt = NULL;
    if (!EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), salt,
        reinterpret_cast<unsigned char*>(&password[0]),
        password.size(), 1, m_key, m_iv))
    {
        throw std::runtime_error("EVP_BytesToKey failed");
    }
}

void Decrypt::CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash)
{
    std::vector<unsigned char> hashTmp(SHA256_DIGEST_LENGTH);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, &data[0], data.size());
    SHA256_Final(&hashTmp[0], &sha256);

    hash.swap(hashTmp);
}

bool Decrypt::DecryptAes(const std::vector<unsigned char> cipherText, std::vector<unsigned char>& plainText)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, m_key, m_iv))
    {
        throw std::runtime_error("DeryptInit error");
    }

    size_t size = cipherText.size();

    std::vector<unsigned char> plainTextBuf(cipherText.size());
    int plainTextSize = 0;
    int updateStat = EVP_DecryptUpdate(ctx, &plainTextBuf[0], &plainTextSize, &cipherText[0], cipherText.size());

    int lastPartLen = 0;
    if (!EVP_DecryptFinal_ex(ctx, &plainTextBuf[0] + plainTextSize, &lastPartLen)) {
        return false;
    }
    plainTextBuf.erase(plainTextBuf.begin() + 340, plainTextBuf.end());

    plainText.swap(plainTextBuf);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

void Decrypt::WriteFile(const std::string& filePath, const std::vector<unsigned char>& buf)
{
    std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary);
    fileStream.write(&buf[0], buf.size());
    fileStream.close();
}

bool Decrypt::DecryptMain(std::string& passw)
{
    std::vector<unsigned char> hash;
    PasswordToKey(passw);
    std::vector<unsigned char> plainText;
    if (!DecryptAes(m_cipherText, plainText)) {
        return false;
    }
    CalculateHash(plainText, hash);
    if (m_cipherHash == hash) {
        WriteFile("plain_text", plainText);
        return true;
    }
    return false;
}