def str_to_bin(user_input):

    binary = ''

    for char in user_input:
        binary_char = format(ord(char), '08b')
        binary += binary_char
        binary = binary[:64]

    binary = binary[:64].ljust(64, '0')
    return binary

