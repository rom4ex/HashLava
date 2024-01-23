from time import time
from cassandra.cluster import Cluster, ExecutionProfile, EXEC_PROFILE_DEFAULT
import hashlib

characters = 'abcdefghijklmnopqrstuvwxyz'
min_length = 1
max_length = 4
batch_size = 2500

execution_profile = ExecutionProfile(request_timeout=600)
cluster = Cluster(['10.16.16.22'], execution_profiles={EXEC_PROFILE_DEFAULT: execution_profile})
session = cluster.connect('hashes')


def generator(characters, min_length, max_length, start_index=0):
    def generate_combinations(characters, min_length, max_length, start_index):
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
            while True:
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

    return generate_combinations(characters, min_length, max_length, start_index)



def get_max_index():
    result = session.execute("SELECT hwm FROM metadata WHERE id = 1;").one()
    return result.hwm if result else 0


def hash_and_write_to_cassandra(strings):
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

    query = format_batch_insert_hash_query(indexes_and_hashes)
    session.execute(query, timeout=60)

    print(f"Записано {index} новых записей в базу данных.")


def format_batch_insert_hash_query(indexes_and_hashes):
    insert_hash_queries = format_insert_hash_queries(indexes_and_hashes)
    query = f"""
    BEGIN BATCH 
        {insert_hash_queries}
        INSERT INTO metadata (id, hwm) VALUES (1, {indexes_and_hashes[-1][0]});
    APPLY BATCH;"""
    return query


def format_insert_hash_queries(indexes_and_hashes):
    queries = ""
    for index_and_hash in indexes_and_hashes:
        queries += format_insert_hash_query(index_and_hash[0], index_and_hash[1])
    return queries


def format_insert_hash_query(index, sha256_hash):
    return f"INSERT INTO hash (partition_id, password_id, hash_text) VALUES ({get_partition_id(sha256_hash)}, {index}, '{sha256_hash}');"


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


def check_last_record(index):
    measure_exec_time = True

    password = get_password_by_index(index, characters, min_length, max_length)
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    partition_id = get_partition_id(sha256_hash)
    print(f"password: {password}, partition_id:{partition_id}, hash:{sha256_hash}, password_id:{index}")

    db_query_exec_time_start = time()

    result = session.execute(f"SELECT * FROM hash WHERE partition_id = {partition_id} AND hash_text = '{sha256_hash}';").one()

    if measure_exec_time:
        db_query_exec_duration = time() - db_query_exec_time_start
        print(f'DB query execution took {db_query_exec_duration:.3} seconds')

    return result.password_id == index and result.hash_text == sha256_hash if result else False


def get_partition_id(sha256_hash):
    return int(sha256_hash[-4:], 16)


def main():
    start_time = time()
    count = get_max_index()
    max_records = sum(len(characters) ** length for length in range(min_length, max_length + 1)) - 1

    if count == 0:
        print("Таблица пуста. Запускаем новый генератор...")
        strings = generator(characters, min_length, max_length)
        hash_and_write_to_cassandra(strings)
    else:
        if count == max_records:
            print(f"Таблица содержит {count} записей.\n""Максимальное количество записей для данной генерации достигнуто. Измените параметры для начала новой генерации.")
            if check_last_record(count):
                print("Последняя запись успешно проверена.")
            else:
                print("Ошибка при проверке последней записи.")
        elif count > max_records:
            print(f"Таблица содержит {count} записей вместо {max_records}, порядок генерации нарушен")
        else:
            print(f"Таблица содержит {count} записей. Восстанавливаем генератор...")
            strings = generator(characters, min_length, max_length, start_index=count + 1)
            hash_and_write_to_cassandra(strings)

            if check_last_record(count):
                print("Последняя запись успешно проверена.")
            else:
                print("Ошибка при проверке последней записи.")

    end_time = time()
    result_time = end_time - start_time
    if result_time > 0.05:
        print(f"Время выполнения программы: {result_time:.3f} с")



if __name__ == "__main__":
    main()
