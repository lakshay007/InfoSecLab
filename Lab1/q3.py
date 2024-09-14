def makeword(word):




    message = "attack is today".replace(" ", "").upper()
    key = [['L','G','D','B','A'], ['Q','M','H','E','C'],['U','R','N','I/J','F'],['X','V','S','O','K'],['Z','Y','W','T','P']]
    encrypt = 'my name is'
    encrypted_message = additive_encrypt(message, key)
    decrypted_message = additive_decrypt(encrypted_message, key)

    print(f"Additive Cipher Encrypted: {encrypted_message}")
    print(f"Additive Cipher Decrypted: {decrypted_message}")