#
# import the CryptContext class, used to handle all hashing...
#
from passlib.context import CryptContext


hash_context = CryptContext(
    # replace this list with the hash(es) you wish to support.
    # this example sets pbkdf2_sha256 as the default,
    # with support for legacy des_crypt hashes.
    schemes=["pbkdf2_sha512", "bcrypt", "sha512_crypt" ],
    default="pbkdf2_sha512",

    # set the number of rounds that should be used...
    # (appropriate values may vary for different schemes,
    # and the amount of time you wish it to take)
    pbkdf2_sha256__default_rounds = 8000,
    )
