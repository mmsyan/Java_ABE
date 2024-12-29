# Java Implementation of Various Attribute-Based Encryption Schemes

Author:  mmsyan

Date: 2024-12-29

Currently, we have implemented the following schemes:

- BLS 
- IBE (Identity Based Encryption)


- FIBE [< Fuzzy Identity-Based Encryption >](https://link.springer.com/chapter/10.1007/11426639_27)
  - section4 Our Construction: FIBE.FIBEa
  - section6 Large Universe Construction: FIBE.FIBEb


- KPABE [< Attribute-based encryption for fine-grained access control of encrypted data >](https://dl.acm.org/doi/10.1145/1180405.1180418)
  - section4.2 Our Construction: KPABE.KPABEa
  - section5 Large Universe Construction: KPABE.KPABEb
  

- CPABE [< Ciphertext-Policy Attribute-Based Encryption >](https://ieeexplore.ieee.org/document/4223236)
  - section4.2 Our Construction(Setup Encrypt KeyGen Delegate Decrypt)


- Partial implementation of EH-CPABE


- CPABE-Waters11 [< Ciphertext-Policy Attribute-Based Encryption: An Expressive, Efficient, and Provably Secure Realization >](https://link.springer.com/chapter/10.1007/978-3-642-19379-8_4)
  - section3 Our Most Efficient Construction


Some schemes are still under implementation:
- FH-CPABE
- PPKE[< Forward Secure Asynchronous Messaging from Puncturable Encryption >](https://ieeexplore.ieee.org/document/7163033)


Below is the development log.

### 2024-12-25
I'm very sorry that I accidentally added an extra line "msk_y = bp.getZr().newRandomElement().getImmutable();" in the setup function while implementing the KPABE of the grand universe, which caused a very bad error. I only found and corrected it the next day.

### 2024-12-20
We have implemented the paper "Ciphertext-Policy Attribute-Based Encryption: An Expressive, Efficient, and Provably Secure Realization." The process was very tortuous. The implementation of \(\omega\) was quite challenging and skillful. Moreover, due to a misreading of the position of an exponent term in the final decryption formula, my code was once caught in a dilemma. It took me about six hours to find this silly mistake.


