import hashlib
import itertools
import string

def hash_password(password, algorithm="md5"):
    #Hash a password using the specified algorithm
    return hashlib.new(algorithm, password.encode()).hexdigest()


def brute_force_crack(target_hash, max_length=4, algorithm="md5"):
    #Attempt to brute force a password hash
    chars = string.ascii_lowercase + string.digits #a-z, 0-9
    for length in range(1, max_length+1):
        for guess in itertools.product(chars, repeat=length):
            guess_password = "".join(guess)
            if hash_password(guess_password, algorithm) == target_hash:
                print(f"Password found: {guess_password}")
                return guess_password
    print("Password not found")
    return None

target_password = "098f6bcd4621d373cade4e832627b4f6"
target_hash = hash_password(target_password)

