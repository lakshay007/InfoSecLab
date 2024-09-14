def hash_function(s):
    h = 5381
    for char in s:
        h = (h * 33) + ord(char)
    return h & 0xffffffff


example_string = "nitant"
hash_value = hash_function(example_string)
print(f"The hash value for '{example_string}' is: {hash_value}")
