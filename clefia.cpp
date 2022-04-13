#include <iostream>
#include <string>
#include <vector>
#include <cstddef>
#include <bitset>
#include "clefia.h"

BLOCK_TYPE mult_Galois(BLOCK_TYPE first_polyn, BLOCK_TYPE second_polyn){
    BLOCK_TYPE res = 0;
    while(second_polyn){
        if(second_polyn & 0b1){
            res ^= first_polyn;
        }
        first_polyn <<= 1;
        
        if(first_polyn & 0x100){
            first_polyn ^= 0b11101;
        }
        second_polyn >>= 1;
    }

    return res & 0xff;
}

BLOCK_TYPE F0(BLOCK_TYPE RK, BLOCK_TYPE x){
    BLOCK_TYPE T = RK ^ x;
    BLOCK_TYPE T0 = (T & a0_8) >> 24;
    BLOCK_TYPE T1 = (T & a8_16) >> 16;
    BLOCK_TYPE T2 = (T & a16_24) >> 8;
    BLOCK_TYPE T3 = (T & a24_32);

    T0 = S0[T0];
    T1 = S1[T1];
    T2 = S0[T2];
    T3 = S1[T3];

    BLOCK_TYPE y0 = T0 ^ mult_Galois(2, T1) ^ mult_Galois(4, T2) ^ mult_Galois(6, T3);
    BLOCK_TYPE y1 = mult_Galois(2, T0) ^ T1 ^ mult_Galois(6, T2) ^ mult_Galois(4, T3);
    BLOCK_TYPE y2 = mult_Galois(4, T0) ^ mult_Galois(6, T1) ^ T2 ^ mult_Galois(2, T3);
    BLOCK_TYPE y3 = mult_Galois(6, T0) ^ mult_Galois(4, T1) ^ mult_Galois(2, T2) ^ T3;

    return WORD_FROM_BYTES(y0, y1, y2, y3);
    // std::cout << T0 << ' ' << T1 << ' ' << T2 << ' ' << T3;
}

BLOCK_TYPE F1(BLOCK_TYPE RK, BLOCK_TYPE x){
    BLOCK_TYPE T = RK ^ x;
    BLOCK_TYPE T0 = (T & a0_8) >> 24;
    BLOCK_TYPE T1 = (T & a8_16) >> 16;
    BLOCK_TYPE T2 = (T & a16_24) >> 8;
    BLOCK_TYPE T3 = (T & a24_32);

    T0 = S1[T0];
    T1 = S0[T1];
    T2 = S1[T2];
    T3 = S0[T3];

    BLOCK_TYPE y0 = T0 ^ mult_Galois(8, T1) ^ mult_Galois(2, T2) ^ mult_Galois(10, T3);
    BLOCK_TYPE y1 = mult_Galois(8, T0) ^ T1 ^ mult_Galois(10, T2) ^ mult_Galois(2, T3);
    BLOCK_TYPE y2 = mult_Galois(2, T0) ^ mult_Galois(10, T1) ^ T2 ^ mult_Galois(8, T3);
    BLOCK_TYPE y3 = mult_Galois(10, T0) ^ mult_Galois(2, T1) ^ mult_Galois(8, T2) ^ T3;

    return WORD_FROM_BYTES(y0, y1, y2, y3);
}

BLOCK_TYPE word_to_block(const std::string& word){
    unsigned int X0 = word[0];
    unsigned int X1 = word[1];
    unsigned int X2 = word[2];
    unsigned int X3 = word[3];

    return WORD_FROM_BYTES(X0, X1, X2, X3);
}

std::string block_to_word(BLOCK_TYPE block){
    char symbol0 = (block & a0_8) >> 24;
    char symbol1 = (block & a8_16) >> 16;
    char symbol2 = (block & a16_24) >> 8;
    char symbol3 = (block & a24_32);

    std::string res;
    res.push_back(symbol0);
    res.push_back(symbol1);
    res.push_back(symbol2);
    res.push_back(symbol3);

    return res;
}

std::vector<BLOCK_TYPE> GFN4(BLOCK_TYPE T0, BLOCK_TYPE T1, BLOCK_TYPE T2, BLOCK_TYPE T3){
    for(int i = 0; i < ROUNDS; ++i){
        T1 = T1 ^ F0(RoundKeys[2 * i], T0);
        T3 = T3 ^ F1(RoundKeys[2 * i + 1], T2);
        auto temp = T0;
        T0 = T1;
        T1 = T2;
        T2 = T3;
        T3 = temp;
    }

    std::vector<BLOCK_TYPE> Y{T3, T0, T1, T2};
    return Y;
}

std::vector<BLOCK_TYPE> GFN4inverse(BLOCK_TYPE T0, BLOCK_TYPE T1, BLOCK_TYPE T2, BLOCK_TYPE T3){
    for(int i = 0; i < ROUNDS; ++i){
        T1 = T1 ^ F0(RoundKeys[2 * (ROUNDS - i) - 2], T0);
        T3 = T3 ^ F1(RoundKeys[2 * (ROUNDS - i) - 1], T2);
        auto temp = T3;
        T3 = T2;
        T2 = T1;
        T1 = T0;
        T0 = temp;
    }

    std::vector<BLOCK_TYPE> Y{T1, T2, T3, T0};
    return Y;
}

std::string encrypt_block(const std::string& word){
    BLOCK_TYPE T0 = word_to_block(word.substr(0, 4));
    BLOCK_TYPE T1 = word_to_block(word.substr(4, 4)) ^ WhiteKeys[0];
    BLOCK_TYPE T2 = word_to_block(word.substr(8, 4));
    BLOCK_TYPE T3 = word_to_block(word.substr(12, 4)) ^ WhiteKeys[1];
    
    std::vector<BLOCK_TYPE> Y = GFN4(T0, T1, T2, T3);

    std::string decrypted;
    decrypted += block_to_word(Y[0]);
    decrypted += block_to_word(Y[1] ^ WhiteKeys[2]);
    decrypted += block_to_word(Y[2]);
    decrypted += block_to_word(Y[3] ^ WhiteKeys[3]);

    return decrypted;
}

std::string decrypt_block(const std::string& word){
    BLOCK_TYPE T0 = word_to_block(word.substr(0, 4));
    BLOCK_TYPE T1 = word_to_block(word.substr(4, 4)) ^ WhiteKeys[2];
    BLOCK_TYPE T2 = word_to_block(word.substr(8, 4));
    BLOCK_TYPE T3 = word_to_block(word.substr(12, 4)) ^ WhiteKeys[3];

    std::vector<BLOCK_TYPE> Y = GFN4inverse(T0, T1, T2, T3);

    std::string decrypted;
    decrypted += block_to_word(Y[0]);
    decrypted += block_to_word(Y[1] ^ WhiteKeys[0]);
    decrypted += block_to_word(Y[2]);
    decrypted += block_to_word(Y[3] ^ WhiteKeys[1]);

    return decrypted;
}

std::string encrypt(std::string& plain_text){
    std::string cypher_text;

    std::string appended(BLOCK_SIZE -  plain_text.size() % BLOCK_SIZE, ' ');
    plain_text += appended;

    for(int i = 0; i < plain_text.size(); i += BLOCK_SIZE){
        cypher_text += encrypt_block(plain_text.substr(i, BLOCK_SIZE));
    }

    return cypher_text;
}

std::string decrypt(const std::string& cypher_text){
    std::string plain_text;

    for(int i = 0; i < cypher_text.size(); i += BLOCK_SIZE){
        plain_text += decrypt_block(cypher_text.substr(i, BLOCK_SIZE));
    }

    return plain_text;
}

int main(){
    std::string plain_text;
    
    std::cout << "plain_text: " << '\n';
    std::getline(std::cin, plain_text);

    std::string cypher_text = encrypt(plain_text);
    std::cout << "cypher text: " << cypher_text << '\n';
    std::cout << "decrypted text: " << decrypt(cypher_text) << '\n';
}