# Java Implementation of Various Attribute-Based Encryption Schemes

Author:  mmsyan

Date: 2024-12-20

Currently, we have implemented the following schemes:

- BLS 
- IBE (Identity Based Encryption)
- FIBE (Fuzzy Identity Based Encryption)
- KPABE (Key Policy Attribute Based Encryption)
- CPABE (Ciphertext Policy Attribute Based Encryption)
- Partial implementation of EH-CPABE
- CPABE-Waters11 (2024-12-20 finished)

Some schemes are still under implementation:
- FH-CPABE



Below is the development log.

### 2024-12-20
We have implemented the paper "Ciphertext-Policy Attribute-Based Encryption: An Expressive, Efficient, and Provably Secure Realization." The process was very tortuous. The implementation of \(\omega\) was quite challenging and skillful. Moreover, due to a misreading of the position of an exponent term in the final decryption formula, my code was once caught in a dilemma. It took me about six hours to find this silly mistake.


