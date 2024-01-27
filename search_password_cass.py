from cassandra.cluster import Cluster

characters = 'abcdefghijklmnopqrstuvwxyz'
min_length = 1
max_length = 4

cluster = Cluster(['10.16.16.22'])
session = cluster.connect('hashes')


def get_index_by_hash(target_hash):
    query = f"SELECT password_id FROM hash WHERE hash_text = '{target_hash}'"
    result = session.execute(query)
    row = result.one()
    return row.password_id if row else None


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


def main():
    target_hash = input('Введите хэш для поиска:')
    index = get_index_by_hash(target_hash)

    if index is not None:
        password = get_password_by_index(index, characters, min_length, max_length)
        print(f"Индекс:пароль для хэша {target_hash}: {index}:{password}")
    else:
        print(f"Хэш {target_hash} не найден в базе данных.")


if __name__ == "__main__":
    main()
