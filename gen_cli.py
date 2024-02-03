import requests
import hashlib
from cassandra.cluster import Cluster, ExecutionProfile, EXEC_PROFILE_DEFAULT
from time import time
import sys

execution_profile = ExecutionProfile(request_timeout=600)
cluster = Cluster(['10.16.16.22'], execution_profiles={EXEC_PROFILE_DEFAULT: execution_profile})
session = cluster.connect('hashes')

SERVER_URL = 'http://10.16.25.100:5000'


def get_password_by_index(index, CHARACTERS, MIN_LENGTH, MAX_LENGTH):
    password = ""
    current_index = 0

    for length in range(MIN_LENGTH, MAX_LENGTH + 1):
        num_combinations = len(CHARACTERS) ** length

        if current_index + num_combinations > index:
            remaining_index = index - current_index
            for _ in range(length):
                password += CHARACTERS[remaining_index % len(CHARACTERS)]
                remaining_index //= len(CHARACTERS)
            break
        else:
            current_index += num_combinations

    return password[::-1]


def get_indices_by_index(index, CHARACTERS, MIN_LENGTH, MAX_LENGTH):
    indices = []
    current_index = 0

    for length in range(MIN_LENGTH, MAX_LENGTH + 1):
        num_combinations = len(CHARACTERS) ** length

        if current_index + num_combinations > index:
            remaining_index = index - current_index
            for _ in range(length):
                indices.append(remaining_index % len(CHARACTERS))
                remaining_index //= len(CHARACTERS)
            break
        else:
            current_index += num_combinations

    return indices[::-1]


def generator(CHARACTERS, MIN_LENGTH, MAX_LENGTH, start_index=0, end_index=0):
    def generate_combinations(CHARACTERS, MIN_LENGTH, MAX_LENGTH, start_index, end_index):
        index = start_index
        indices = []
        if start_index > 0:
            indices2 = get_indices_by_index(index, CHARACTERS, MIN_LENGTH, MAX_LENGTH)
            last_combination = get_password_by_index(index, CHARACTERS, MIN_LENGTH, MAX_LENGTH)
            if last_combination:
                length = len(last_combination)
                indices = [0] * length
                for i in range(length):
                    indices[i] = CHARACTERS.index(last_combination[i])
        else:
            indices = [0] * MIN_LENGTH

        for length in range(len(indices), MAX_LENGTH + 1):
            while end_index == 0 or index <= end_index:
                combination = ''.join(CHARACTERS[i] for i in indices)
                yield f"{index:08d}:{combination}"
                index += 1
                i = length - 1
                while i >= 0:
                    indices[i] += 1
                    if indices[i] < len(CHARACTERS):
                        break
                    indices[i] = 0
                    i -= 1
                else:
                    indices.append(0)
                    break

    return generate_combinations(CHARACTERS, MIN_LENGTH, MAX_LENGTH, start_index, end_index)


def hash_and_write_to_cassandra(strings, BATCH_SIZE):
    printed = False
    batch_index = 0
    indexes_and_hashes = []
    for string in strings:
        if not printed:
            printed = True
            print(string)
        parts = string.split(":")
        index = int(parts[0])
        password = ":".join(parts[1:])
        sha256_hash = hashlib.sha256(password.encode()).hexdigest()
        indexes_and_hashes.append((index, sha256_hash))
        if batch_index == BATCH_SIZE:
            query = format_batch_insert_hash_query(indexes_and_hashes)
            session.execute(query, timeout=60)
            batch_index = 0
            indexes_and_hashes = []
        else:
            batch_index += 1
    if len(indexes_and_hashes) > 0:
        query = format_batch_insert_hash_query(indexes_and_hashes)
        session.execute(query, timeout=60)


def format_batch_insert_hash_query(indexes_and_hashes):
    try:
        insert_hash_queries = format_insert_hash_queries(indexes_and_hashes)
        query = f"""
        BEGIN BATCH 
            {insert_hash_queries}           
        APPLY BATCH;"""
        return query
    except Exception as e:
        print(f"Ошибка при получении информации о диапазоне: {e}")


def format_insert_hash_queries(indexes_and_hashes):
    queries = ""
    for index_and_hash in indexes_and_hashes:
        queries += format_insert_hash_query(index_and_hash[0], index_and_hash[1])
    return queries


def format_insert_hash_query(index, sha256_hash):
    return f"INSERT INTO hash (partition_id, password_id, hash_text) VALUES ({get_partition_id(sha256_hash)}, {index}, '{sha256_hash}');"


def get_partition_id(sha256_hash):
    return int(sha256_hash[-4:], 16)


def client_process(CHARACTERS, MIN_LENGTH, MAX_LENGTH, BATCH_SIZE, start_index, end_index):
    strings = generator(CHARACTERS, MIN_LENGTH, MAX_LENGTH, start_index, end_index)
    hash_and_write_to_cassandra(strings, BATCH_SIZE)
    report_completion(start_index, end_index)


def get_range_info():
    try:
        response = requests.get(f'{SERVER_URL}/get_range')
        return response.json()
    except Exception as e:
        print(f"Ошибка при получении информации о диапазоне: {e}")
        return {'status': 'error'}


def run_client():
    while True:
        range_info = get_range_info()
        if range_info.get('status') == 'finished':
            print("Генерация завершена.")
            signal_last_generation_completion(end_index)
            break
        elif range_info.get('status') == 'error':
            print(range_info.get('message'))
            sys.exit()
        else:
            start_index = range_info.get('start_index')
            end_index = range_info.get('end_index')

            if start_index is not None and end_index is not None:
                CHARACTERS = range_info.get('characters')
                MIN_LENGTH = range_info.get('min_length')
                MAX_LENGTH = range_info.get('max_length')
                BATCH_SIZE = range_info.get('batch_size')

                client_process(CHARACTERS, MIN_LENGTH, MAX_LENGTH, BATCH_SIZE, start_index, end_index)
            else:
                print("Некорректные данные start_index и end_index")
                sys.exit()


def report_completion(start_index, end_index):
    try:
        finish_time = time()
        data = {'start_index': start_index, 'end_index': end_index, 'finish_time': finish_time}
        response = requests.post(f'{SERVER_URL}/report_completion', json=data)
        if response.json().get('status') == 'error':
            print(response.json().get('message'))
    except Exception as e:
        print(f"Ошибка при отправке отчета о завершении работы: {e}")


def signal_last_generation_completion(end_index):
    try:
        data = {'last_index': end_index}
        response = requests.post(f'{SERVER_URL}/check_last_record', json=data)
        if response.status_code == 200 and response.json().get('status') == 'success':
            print("Проверка последней записи успешно завершена.")
            return True
        else:
            print("Ошибка при проверке последней записи.")
    except Exception as e:
        print(f"Ошибка при отправке сигнала последней генерации: {e}")


if __name__ == "__main__":
    run_client()
