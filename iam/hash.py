import hashlib


def hash_md5(local_id, salt):
    return hashlib.md5(local_id + salt).hexdigest()
