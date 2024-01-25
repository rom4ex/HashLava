from time import time
from cassandra.cluster import Cluster, ExecutionProfile, EXEC_PROFILE_DEFAULT
import hashlib
import pandas as pd

characters = 'abcdefghijklmnopqrstuvwxyz'
min_length = 1
max_length = 3
batch_size = 1000



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
        indexes_and_hashes.append((get_partition_id(sha256_hash), index, sha256_hash))
        if batch_index == batch_size:
            df = pd.DataFrame(data=indexes_and_hashes, columns=["partition_id", "password_id", "hash_text"])
            #print(df.shape[0])
            df.to_csv("data.csv", sep="|", index=False)
            break;
        else:
            batch_index += 1

    print(f"Записано {index} новых записей в базу данных.")



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



def get_partition_id(sha256_hash):
    return int(sha256_hash[-4:], 16)


def main():
    start_time = time()
    count = 0

    if count == 0:
        print("Таблица пуста. Запускаем новый генератор...")
        strings = generator(characters, min_length, max_length)
        hash_and_write_to_cassandra(strings)

    end_time = time()
    result_time = end_time - start_time
    print(f"Время выполнения программы: {result_time:.3f} с")


if __name__ == "__main__":
    main()
