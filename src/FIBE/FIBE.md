# FIBE 类文档

Author:  mmsyan

Date: 2024-12-18

## 概述

`FIBE` 类实现了模糊身份基加密（Fuzzy Identity-Based Encryption，FIBE）方案，支持初始化、公钥生成、密钥生成、加密和解密操作。加密和解密是基于用户的属性集进行的，支持容错匹配。

## 主要功能

- **初始化**：设置加密参数，生成主密钥和公钥。
- **密钥生成**：根据用户的属性生成私钥。
- **加密**：根据用户属性加密消息。
- **解密**：根据用户属性解密密文。

## 方法

### `setUp(pairingFilePath)`
初始化加密参数，生成主密钥和公钥。

- **参数**：`pairingFilePath`：双线性对参数文件路径。
- **功能**：设置双线性对参数，生成公钥和主密钥。

### `keyGeneration(userAttributes, skFilePath)`
生成用户的私钥。

- **参数**：
    - `userAttributes`：用户的属性数组。
    - `skFilePath`：私钥文件保存路径。
- **功能**：根据用户的属性生成并保存私钥。

### `encrypt(messageAttributes, message, ctFilePath)`
加密消息。

- **参数**：
    - `messageAttributes`：加密消息的属性数组。
    - `message`：要加密的消息。
    - `ctFilePath`：密文保存路径。
- **功能**：根据属性对消息进行加密。

### `decrypt(userAttributes, skFilePath, ctFilePath)`
解密消息。

- **参数**：
    - `userAttributes`：用户的属性数组。
    - `skFilePath`：私钥文件路径。
    - `ctFilePath`：密文文件路径。
- **功能**：根据用户的属性解密密文。

### `generateRandomPlainText()`
生成随机的明文。

- **返回值**：返回随机生成的消息。一个`GT`类型元素

## 类字段

- `universe`：属性宇宙的大小。
- `distance`：容错距离。
- `bp`：双线性对的对象。
- `g`：G1群的生成元。
- `msk_ti`：主密钥数组。
- `msk_y`：主密钥元素。
- `pk_Ti`：公钥数组。
- `pk_Y`：公钥元素。


## 下标问题
