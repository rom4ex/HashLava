import requests
import hashlib
import queue
from cassandra.cluster import Cluster, ExecutionProfile, EXEC_PROFILE_DEFAULT

execution_profile = ExecutionProfile(request_timeout=600)
cluster = Cluster(['10.16.16.22'], execution_profiles={EXEC_PROFILE_DEFAULT: execution_profile})
session = cluster.connect('hashes')

SERVER_URL = 'http://10.16.16.22:5000'


def get_password_by_index(index, characters, min_length, max_length):
    password = ""
    current_index = 0

    for length in range(min_length, max_length + 1):
        num_combinations = len(characters) ** length

        if current_index + num_combinations > index:
            remaining_index = index - current_index
            for _ in range(length):
                password += characters[remaining_index % len(characters)]
                remaining_index //= len(characters)
            break
        else:
            current_index += num_combinations

    return password[::-1]


def get_indices_by_index(index, characters, min_length, max_length):
    indices = []
    current_index = 0

    for length in range(min_length, max_length + 1):
        num_combinations = len(characters) ** length

        if current_index + num_combinations > index:
            remaining_index = index - current_index
            for _ in range(length):
                indices.append(remaining_index % len(characters))
                remaining_index //= len(characters)
            break
        else:
            current_index += num_combinations

    return indices[::-1]


def generator(characters, min_length, max_length, start_index=0, end_index=0):
    def generate_combinations(characters, min_length, max_length, start_index, end_index):
        index = start_index
        indices = []
        if start_index > 0:
            indices2 = get_indices_by_index(index, characters, min_length, max_length)
            last_combination = get_password_by_index(index, characters, min_length, max_length)
            if last_combination:
                length = len(last_combination)
                indices = [0] * length
                for i in range(length):
                    indices[i] = characters.index(last_combination[i])
        else:
            indices = [0] * min_length

        for length in range(len(indices), max_length + 1):
            while end_index == 0 or index <= end_index:
                combination = ''.join(characters[i] for i in indices)
                yield f"{index:08d}:{combination}"
                index += 1
                i = length - 1
                while i >= 0:
                    indices[i] += 1
                    if indices[i] < len(characters):
                        break
                    indices[i] = 0
                    i -= 1
                else:
                    indices.append(0)
                    break

    return generate_combinations(characters, min_length, max_length, start_index, end_index)

def hash_and_write_to_cassandra(strings, batch_size):
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
        if batch_index == batch_size:
            query = format_batch_insert_hash_query(indexes_and_hashes)
            session.execute(query, timeout=60)
            batch_index = 0
            indexes_and_hashes = []
        else:
            batch_index += 1
    if len(indexes_and_hashes) > 0:
        query = format_batch_insert_hash_query(indexes_and_hashes)
        session.execute(query, timeout=60)

    print(f"Записано {index} новых записей в базу данных.")


def format_batch_insert_hash_query(indexes_and_hashes):
    try:
        insert_hash_queries = format_insert_hash_queries(indexes_and_hashes)
        query = f"""
        BEGIN BATCH 
            {insert_hash_queries}
            INSERT INTO metadata (id, hwm) VALUES (1, {indexes_and_hashes[-1][0]});
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


def get_password_by_index(index, characters, min_length, max_length):
    password = ""
    current_index = 0

    for length in range(min_length, max_length + 1):
        num_combinations = len(characters) ** length

        if current_index + num_combinations > index:
            remaining_index = index - current_index
            for _ in range(length):
                password += characters[remaining_index % len(characters)]
                remaining_index //= len(characters)
            break
        else:
            current_index += num_combinations

    return password[::-1]


def get_indices_by_index(index, characters, min_length, max_length):
    indices = []
    current_index = 0

    for length in range(min_length, max_length + 1):
        num_combinations = len(characters) ** length

        if current_index + num_combinations > index:
            remaining_index = index - current_index
            for _ in range(length):
                indices.append(remaining_index % len(characters))
                remaining_index //= len(characters)
            break
        else:
            current_index += num_combinations

    return indices[::-1]


def client_process(characters, min_length, max_length, batch_size, start_index, end_index):
    strings = generator(characters, min_length, max_length, start_index, end_index)
    hash_and_write_to_cassandra(strings, batch_size)
    requests.post(f'{SERVER_URL}/report_completion', json={'start_index': start_index, 'end_index': end_index})


def get_range_info():
    try:
        response = requests.get('http://10.16.16.22:5000/get_range')
        return response.json()
    except Exception as e:
        print(f"Ошибка при получении информации о диапазоне: {e}")
        return {'status': 'error'}


def run_client():
    while True:
        range_info = get_range_info()
        if range_info.get('status') == 'finished':
            print("Генерация завершена. Выполняем запрос на сервер для проверки последней записи.")
            signal_last_generation_completion()
            break

        characters = range_info.get('characters', '')
        min_length = range_info.get('min_length')
        max_length = range_info.get('max_length')
        batch_size = range_info.get('batch_size')
        start_index = range_info.get('start_index', 0)
        end_index = range_info.get('end_index', 0)

        client_process(characters, min_length, max_length, batch_size, start_index, end_index)
        report_completion(start_index, end_index)


def report_completion(start_index, end_index):
    try:
        data = {'start_index': start_index, 'end_index': end_index}
        response = requests.post('http://10.16.16.22:5000/report_completion', json=data)
        if response.json().get('status') == 'success':
            print(f"Отчет о завершении работы с диапазоном {start_index}-{end_index} отправлен.")
        else:
            print(f"Ошибка при отправке отчета о завершении работы с диапазоном {start_index}-{end_index}.")
    except Exception as e:
        print(f"Ошибка при отправке отчета о завершении работы: {e}")


def signal_last_generation_completion():
    try:
        response = requests.post('http://10.16.16.22:5000/check_last_record')
        if response.status_code == 200 and response.json().get('status') == 'success':
            print("Проверка последней записи успешно завершена. Сигнал серверу отправлен.")
        else:
            print("Ошибка при проверке последней записи. Сигнал серверу не отправлен.")
    except Exception as e:
        print(f"Ошибка при отправке сигнала последней генерации: {e}")


def register_client():
    response = requests.get(f'{SERVER_URL}/get_range')
    if response.status_code == 200:
        return response.json()
    elif response.json().get('status') == 'finished':
        print("Все диапазоны были обработаны.")
        return None
    else:
        return None

if __name__ == "__main__":
    run_client()
