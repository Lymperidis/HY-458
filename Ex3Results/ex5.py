import rsa
import hashlib

import random
import math  


class Signer:
    def __init__(self):
        (self.pub_key, self.priv_key) = rsa.newkeys(2048)
    #Return the public key 
    def get_public_key(self):
        return self.pub_key
    #Return a signature for the blinded_message
    def sign(self, blinded_message):
        return pow(blinded_message, self.priv_key.d, self.priv_key.n)
    
    
class User:
    def __init__(self, signer):
        self.signer = signer
    def get_signed_message(self):
        #Create a random message
        message = random.getrandbits(256).to_bytes(32, byteorder='big')
        hash_message = hashlib.sha256(message).digest()

        #Convert hash to integer
        m = int.from_bytes(hash_message, byteorder='big')
        N = self.signer.get_public_key().n
        #Pick random number(must be relative prime)
        r = random.randrange(1, N)
        while math.gcd(r, N) != 1: 
            r = random.randrange(1, N)


        #Create blinded message
        e = self.signer.get_public_key().e
        m_prime = (pow(r, e, N) * m) % N

        #Get blinded signature
        s_prime = self.signer.sign(m_prime)

        #Calculate unblinded signature
        r_inv = rsa.common.inverse(r, N)
        s = (s_prime * r_inv) % N

        #Convert signature to bytes
        signature = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big')

        #Return message and signature
        return message, signature
    
    
class Verifier:
    def __init__(self, signer):
        self.signer = signer

    def verify(self, message, signature):
        # Hash the message
        hash_message = hashlib.sha256(message).digest()

        #Convert signature to integer
        s_prime = int.from_bytes(signature, byteorder='big')

        #Verification process
        e = self.signer.get_public_key().e
        m = pow(s_prime, e, self.signer.get_public_key().n)

        #Convert m to bytes
        hash_calculated = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')

        #Compare hashes
        return hash_calculated == hash_message
    
def main():
    #Create a Signer object
    signer = Signer()

    #Create a User and a Verifier
    user = User(signer)
    verifier = Verifier(signer)

    #Get signed message
    message, signature = user.get_signed_message()

    #Verification tests
    print("Original message verification:", verifier.verify(message, signature)) # True

    # Damaged message or signature tests
    print("Damaged message verification:", verifier.verify(message[:-1], signature)) # False
    
    print("Damaged signature verification:", verifier.verify(message, signature[:-1])) # False

if __name__ == "__main__":
    main()
    