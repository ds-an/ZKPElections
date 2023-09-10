import random
import string
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

candidates = ("Демократ", "Республиканец")


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
        # Голосующий подключается к защищенному интерфейсу и передает каждому центру подсчета
        # уникальный пакет с зашифрованным голосом, парой подпись/хеш этого голоса
        # и собственным публичным ключом.
        for center in centers_list:
            encrypted_vote = encrypt_rsa(center.public_key, self.vote_preference)
            zkp_hash_signature = create_zkp_signature(self.private_key, encrypted_vote)
            signed_encrypted_vote = (encrypted_vote, zkp_hash_signature, self.public_key)
            center.collected_votes.append(signed_encrypted_vote)


class Center:
    def __init__(self):
        self.number_of_center = random.randint(100, 999)
        key_pair = generate_key_pair_rsa()
        self.private_key = key_pair[0]
        self.public_key = key_pair[1]
        self.collected_votes = []
        self.collected_votes_hash = 0
        self.valid_votes = 0
        self.invalid_votes = 0
        self.votes_democrat = 0
        self.votes_republican = 0

    def tally_votes(self):
        print(f"Центр подсчета голосов №{self.number_of_center} гарантирует неприкосновенность собственной"
              f" базы собранных голосов.")
        self.collected_votes_hash = create_collected_votes_hash(self.private_key, str(self.collected_votes).encode())
        print(f"Центр подсчета №{self.number_of_center} ведет подсчет голосов...")
        for vote in self.collected_votes:
            voter_public_key = vote[2]
            encrypted_vote_hashed = vote[1][0]
            signature_zkp = vote[1][1]
            if verify_zkp(voter_public_key, encrypted_vote_hashed, signature_zkp):
                self.valid_votes += 1
                if decrypt_rsa(self.private_key, vote[0]) == candidates[0]:
                    self.votes_democrat += 1
                elif decrypt_rsa(self.private_key, vote[0]) == candidates[1]:
                    self.votes_republican += 1
            else:
                self.invalid_votes += 1
        print(f"Согласно центру подсчета голосов №{self.number_of_center}:")
        print(f"Общее количество голосов составляет: {self.valid_votes}")
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
        padding.PSS(padding.MGF1(hashes.SHA256()),
                    padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return encrypted_vote_hashed, signature_zkp


def create_collected_votes_hash(center_private_key, collected_votes):
    collected_votes_hashed = hashlib.sha256(collected_votes).digest()
    signature = center_private_key.sign(
        collected_votes_hashed,
        padding.PSS(padding.MGF1(hashes.SHA256()),
                    padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return collected_votes_hashed, signature


def verify_zkp(voter_public_key, encrypted_vote_hashed, signature_zkp):
    try:
        voter_public_key.verify(
            signature_zkp, encrypted_vote_hashed, padding.PSS(
                padding.MGF1(hashes.SHA256()),
                padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as exception:
        return False


def verify_collected_votes_hash(center_public_key, collected_votes_hashed, signature):
    try:
        center_public_key.verify(
            signature, collected_votes_hashed, padding.PSS(
                padding.MGF1(hashes.SHA256()),
                padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as exception:
        return False


def verify_third_party(centers_list, number_centers):
    valid_votes = 0
    invalid_votes = 0
    center = centers_list[random.randint(0, number_centers - 1)]
    if verify_collected_votes_hash(center.public_key, center.collected_votes_hash[0],
                                   center.collected_votes_hash[1]):
        for vote in center.collected_votes:
            voter_public_key = vote[2]
            encrypted_vote_hashed = vote[1][0]
            signature_zkp = vote[1][1]
            if verify_zkp(voter_public_key, encrypted_vote_hashed, signature_zkp):
                valid_votes += 1
            else:
                invalid_votes += 1
        if valid_votes == center.valid_votes:
            print("Голоса были верифицированы стейкхолдером и выборы признаны состоявшимися.")
        else:
            print("Стейкхолдеру не удалось верифицировать голоса и выборы признаны не состоявшимися.")
    else:
        print("Стейкхолдеру не удалось верифицировать переданный центром подсчета"
              " набор данных.")


def voter_registration(voters_list):
    registered_voters = []
    for voter in voters_list:
        if voter.id in range(311111111, 399999999):
            # Булев параметр здесь - статус проголосовал/не проголосовал
            registered_voters.append([voter.id, voter.public_key, False])
        else:
            print(f"Голосующий №{voter.id} имеет невалидный id"
                  f" и был выявлен при попытке регистрации.")
    return registered_voters


def check_voter_registration(voter, registered_voters_list):
    for voter_id_key_and_status in registered_voters_list:
        if voter.id == voter_id_key_and_status[0] and \
                voter_id_key_and_status[2] is False:
            voter_id_key_and_status[2] = True
            return True
        elif voter.id == voter_id_key_and_status[0] and \
                voter_id_key_and_status[2] is True:
            print(f"Голосующий №{voter.id} пытался проголосовать дважды и был выявлен.")
        else:
            pass
    return False


def begin_elections_scenario_1():
    number_voters = int(input("Введите количество голосущих: "))
    number_centers = int(input("Введите количество центров подсчета голосов: "))
    print("Генерируем голосующих...")
    voters_list = generate_voters(number_voters)
    print("Генерируем центры подсчета голосов...")
    centers_list = generate_centers(number_centers)
    print("Проводим регистрацию голосующих...")
    registered_voters_list = voter_registration(voters_list)
    # voters_list.append(Voter())
    print("Проводим голование...")
    for voter in voters_list:
        if check_voter_registration(voter, registered_voters_list):
            voter.vote_secure(centers_list)
        else:
            # print(f"The voter {voter.id} not on the list")
            pass
    print("Начинаем подсчет голосов.")
    for center in centers_list:
        center.tally_votes()
    print("Проводим верификацию голосования стейкхолдером...")
    verify_third_party(centers_list, number_centers)


def begin_elections_scenario_2():
    number_voters = int(input("Введите количество голосущих: "))
    number_centers = int(input("Введите количество центров подсчета голосов: "))
    print("Генерируем голосующих...")
    voters_list = generate_voters(number_voters)
    malicious_voter = voters_list[random.randint(1, number_voters)]
    malicious_voter.id = 234343434 # невалидный id
    malicious_voter.malicious = True
    print("Генерируем центры подсчета голосов...")
    centers_list = generate_centers(number_centers)
    print("Проводим регистрацию голосующих...")
    registered_voters_list = voter_registration(voters_list)
    # voters_list.append(Voter())
    print("Проводим голование...")
    for voter in voters_list:
        if check_voter_registration(voter, registered_voters_list):
            voter.vote_secure(centers_list)
        else:
            print(f"Голосующий №{voter.id} не зарегистрирован и не будет допущен к голосованию.")
    for center in centers_list:
        center.tally_votes()
    print("Проводим верификацию голосования стейкхолдером...")
    verify_third_party(centers_list, number_centers)


def begin_elections_scenario_3():
    number_voters = int(input("Введите количество голосущих: "))
    number_centers = int(input("Введите количество центров подсчета голосов: "))
    print("Генерируем голосующих...")
    voters_list = generate_voters(number_voters)
    malicious_voter = voters_list[random.randint(1, number_voters)]
    malicious_voter.malicious = True
    print("Генерируем центры подсчета голосов...")
    centers_list = generate_centers(number_centers)
    print("Проводим регистрацию голосующих...")
    registered_voters_list = voter_registration(voters_list)
    # voters_list.append(Voter())
    print("Проводим голование...")
    for voter in voters_list:
        if check_voter_registration(voter, registered_voters_list):
            voter.vote_secure(centers_list)
        else:
            print(f"Голосующий №{voter.id} не зарегистрирован и не будет допущен к голосованию.")
    if check_voter_registration(malicious_voter, registered_voters_list):
        malicious_voter.vote_secure()
    for center in centers_list:
        center.tally_votes()
    print("Проводим верификацию голосования стейкхолдером...")
    verify_third_party(centers_list, number_centers)


scenario = int(input("Выберите сценарий голосования:\n"
                     "1. Сценарий без эксцессов\n"
                     "2. Сценарий с попыткой проголосовать без валидного ID\n"
                     "3. Cценарий с попыткой проголосовать дважды\n"))
if scenario == 1:
    begin_elections_scenario_1()
elif scenario == 2:
    begin_elections_scenario_2()
elif scenario == 3:
    begin_elections_scenario_3()
else:
    print("Некорректный вариант сценация голосования: введите 1, 2 или 3.")
