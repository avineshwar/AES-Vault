# AES-Vault
This C-based tool utilizes several Linux facilities (and hence it is GNU-based) to ultimately serve as a tool for encrypting your contents (maybe, umm, from SysAdmins?) and decrypting them back. Since it has a CBC-MAC implemented as well, it has data integrity feature, i.e., if anyone tampers your encrypted data, the decryption will fail with an evident failure message.

NOTE: It is still possible to partially decrypt your data, however, there is a high possibility, there will only be a partial recovery. Hence, if the data is anything apart from text, don't expect to get it back. Well, that's how encryption was initially visioned.
