import random
import string
import hashlib
import time

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

candidates = ("Democrat", "Republican")


def generate_key_pair_rsa():
    private_key = rsa.generate_private_key(65537, 2048)
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_rsa(public_key, message):
    encrypted_message = public_key.encrypt(
        message.encode(), padding.OAEP(
            padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
    )
    return encrypted_message


def decrypt_rsa(private_key, encrypted_message):
    decrypted_message = private_key.decrypt(
        encrypted_message, padding.OAEP(
            padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
    )
    # exception for failed decryption should be here
    return decrypted_message.decode()


class Voter:
    def __init__(self):
        self.id = random.randint(311111111, 399999999)
        self.vote_preference = candidates[random.randint(0, 1)]
        key_pair = generate_key_pair_rsa()
        self.private_key = key_pair[0]
        self.public_key = key_pair[1]
        self.malicious = False

    def vote_secure(self, centers_list):
        for center in centers_list:
            encrypted_vote = encrypt_rsa(center.public_key, self.vote_preference)
            zkp_hash_signature = create_zkp_signature(self.private_key, encrypted_vote)
            signed_encrypted_vote = (encrypted_vote, zkp_hash_signature[1])
            center.collected_votes.append(signed_encrypted_vote)

class Center:
    def __init__(self):
        self.number_of_center = random.randint(100, 999)
        key_pair = generate_key_pair_rsa()
        self.private_key = key_pair[0]
        self.public_key = key_pair[1]
        self.collected_votes = []
        self.valid_votes = 0
        self.invalid_votes = 0
        self.votes_democrat = 0
        self.votes_republican = 0

    def tally_votes(self):
        for vote in self.collected_votes:
            if verify_zkp(self.public_key, vote[0], vote[1]):
                self.valid_votes += 1
                if decrypt_rsa(self.private_key, vote[0]) == candidates[0]:
                    self.votes_democrat += 1
                elif decrypt_rsa(self.private_key, vote[0]) == candidates[1]:
                    self.votes_republican += 1
                break
            else:
                self.invalid_votes += 1
        print(f"Согласно центру подсчета голосов №{self.number_of_center}:\n")
        print(f"Общее количество голосов составляет: {self.valid_votes}\n")
        print(f"Количество выявленных невалидных голосов: {self.invalid_votes}")
        print(f"Количество голосов, поданных за кандидата от Демократической партии: {self.votes_democrat}")
        print(f"Количество голосов, поданных за кандидата от Республиканской партии: {self.votes_republican}")


def generate_centers(num_centers):
    centers_list = []
    for i in range(0, num_centers):
        centers_list.append(Center())
    return centers_list


def generate_voters(num_voters):
    voters_list = []
    for i in range(0, num_voters):
        voters_list.append(Voter())
    return voters_list


def create_zkp_signature(voter_private_key, encrypted_vote):
    encrypted_vote_hashed = hashlib.sha256(encrypted_vote).digest()
    signature_zkp = voter_private_key.sign(
        encrypted_vote_hashed,
        padding.PSS(padding.MGF1(hashes.SHA256),
                    padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return encrypted_vote_hashed, signature_zkp


def verify_zkp(center_public_key, encrypted_vote, signature_zkp):
    try:
        center_public_key.verify(
            signature_zkp, encrypted_vote, padding.PSS(
                padding.MGF1(hashes.SHA256()),
                padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as exception:
        return False

# def vote_secure(voter, centers_list):
#     for center in centers_list:
#         encrypted_vote = encrypt_rsa(center.public_key, voter.vote_preference)
#         zkp_hash_signature = create_zkp_signature(voter.private_key, encrypted_vote)
#         signed_encrypted_vote = (encrypted_vote, zkp_hash_signature[1])
#         center.collected_votes.append(signed_encrypted_vote)


def verify_third_party():
    pass


def voter_registration():
    pass


def begin_elections():
    voters_list = generate_voters(20)
    centers_list = generate_centers(3)
    for voter in voters_list:
        voter.vote_secure(centers_list)
    # print(voters_list[19].private_key)
    # print(voters_list[19].public_key)
    # message = "I'm a message."
    # encrypted_message = encrypt_rsa(voters_list[19].public_key, message)
    # decrypted_message = decrypt_rsa(voters_list[19].private_key, encrypted_message)
    # print(f"{decrypted_message}")
    print(time.process_time())


begin_elections()
