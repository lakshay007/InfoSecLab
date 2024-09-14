import hashlib
import time
import random
import string

def rand_str(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def hash_md5(s):
    return hashlib.md5(s.encode()).hexdigest()

def hash_sha1(s):
    return hashlib.sha1(s.encode()).hexdigest()

def hash_sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()

def time_hashing(hash_func, data):
    start = time.time()
    return [hash_func(d) for d in data], time.time() - start


def find_collisions(hashes):
    seen = set()
    collisions = set()
    for h in hashes:
        if h in seen:
            collisions.add(h)
        seen.add(h)
    return collisions


def main():
    n = random.randint(50, 100)
    strs = [rand_str(10) for _ in range(n)]

    md5_hashes, md5_time = time_hashing(hash_md5, strs)
    sha1_hashes, sha1_time = time_hashing(hash_sha1, strs)
    sha256_hashes, sha256_time = time_hashing(hash_sha256, strs)

    md5_coll = find_collisions(md5_hashes)
    sha1_coll = find_collisions(sha1_hashes)
    sha256_coll = find_collisions(sha256_hashes)

    print(f"MD5 Time: {md5_time:.4f}s, Collisions: {len(md5_coll)}")
    print(f"SHA-1 Time: {sha1_time:.4f}s, Collisions: {len(sha1_coll)}")
    print(f"SHA-256 Time: {sha256_time:.4f}s, Collisions: {len(sha256_coll)}")


if __name__ == "__main__":
    main()
