import sympy
import base64
import hashlib
import json
import logging
import os
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(filename='key_management.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


class RabinCryptosystem:
    def __init__(self, key_size=1024):
        self.key_size = key_size
        self.public_keys = {}
        self.private_keys = {}
        self.key_expiration = {}

    def generate_key_pair(self):
        p = sympy.randprime(2 ** (self.key_size // 2 - 1), 2 ** (self.key_size // 2))
        q = sympy.randprime(2 ** (self.key_size // 2 - 1), 2 ** (self.key_size // 2))
        n = p * q
        return (n, p, q)

    def generate_keys(self, identifier):
        n, p, q = self.generate_key_pair()
        public_key = n
        private_key = (p, q)
        self.public_keys[identifier] = public_key
        self.private_keys[identifier] = private_key
        self.key_expiration[identifier] = datetime.now() + timedelta(days=365)  # Set expiration to 1 year
        logging.info(f"Generated keys for {identifier}.")

    def get_key_pair(self, identifier):
        if identifier in self.public_keys and identifier in self.private_keys:
            return self.public_keys[identifier], self.private_keys[identifier]
        else:
            raise ValueError("Key pair not found.")

    def revoke_keys(self, identifier):
        if identifier in self.public_keys:
            del self.public_keys[identifier]
        if identifier in self.private_keys:
            del self.private_keys[identifier]
        if identifier in self.key_expiration:
            del self.key_expiration[identifier]
        logging.info(f"Revoked keys for {identifier}.")

    def renew_keys(self):
        for identifier in list(self.key_expiration.keys()):
            if datetime.now() > self.key_expiration[identifier]:
                self.revoke_keys(identifier)
                self.generate_keys(identifier)
                logging.info(f"Renewed keys for {identifier}.")

    def store_key(self, identifier, key):
        with open(f'{identifier}_key.json', 'w') as f:
            json.dump(key, f)
        logging.info(f"Stored key for {identifier}.")

    def load_key(self, identifier):
        if os.path.exists(f'{identifier}_key.json'):
            with open(f'{identifier}_key.json', 'r') as f:
                return json.load(f)
        else:
            raise ValueError("Key file not found.")

    def secure_key_distribution(self, identifier):
        if identifier in self.public_keys and identifier in self.private_keys:
            key_pair = {
                'public_key': self.public_keys[identifier],
                'private_key': self.private_keys[identifier]
            }
            self.store_key(identifier, key_pair)
            return key_pair
        else:
            raise ValueError("Key pair not found.")

    def audit_logs(self):
        with open('key_management.log', 'r') as f:
            return f.read()


# Example Usage
def main():
    key_manager = RabinCryptosystem(key_size=1024)

    # Generate keys for hospitals and clinics
    key_manager.generate_keys('HospitalA')
    key_manager.generate_keys('ClinicB')

    # Securely distribute keys
    key_manager.secure_key_distribution('HospitalA')
    key_manager.secure_key_distribution('ClinicB')

    # Perform key renewal
    key_manager.renew_keys()

    # Revoke keys
    key_manager.revoke_keys('ClinicB')

    # Display audit logs
    logs = key_manager.audit_logs()
    print(logs)


if __name__ == "__main__":
    main()
