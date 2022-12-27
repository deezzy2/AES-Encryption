# AES-Encryption

## How does it work?

AES encryption works by taking plaintext as input and transforming it so that it is difficult for anyone to read the data. This transformation is done through a series of steps called rounds.

In AES, there are four main parts:

1. Key Expansion: Here the key that was supplied as an input has to be expanded to multiple rounds keys which will be used in each iterations (rounds) of encryption process.
2. Initial Round: It applies some linear transformation over the plaintext before proceeding further with encryption process.
3. Rounds: In this phase, the expansion key derived from the previous step is applied one round at a time using different transformation functions like substitution and transposition till we get our desired cipher text. In every round some additional mix operations are also performed over the data before proceeding with next round's encryption/decryption process.
4. Final Round: Here any additional steps required for completion of the encryption/decryption process are done using the final round key again generated from last step (Key Expansion). Once all this is done we will have our cipher text ready for transmission or storage depending upon what was required!

In Java server-side applications, developers usually use javax crypto packages for implementing AES encryption or decryption algorithms, where support for different key sizes (128 , 192 & 256 bit ) as well as modes of operation(ECB, CBC etc) are available out of box due to extensive work put into making these APIs secure yet intuitive enough to use.

check out this note https://www.notion.so/abrshkorra/Chapter-12-3d974a1afc164054be1dcad476df6488
