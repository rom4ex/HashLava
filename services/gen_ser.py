from flask import Flask, jsonify, request
import queue
from time import time
import hashlib
from cassandra.cluster import Cluster, ExecutionProfile, EXEC_PROFILE_DEFAULT

app = Flask(__name__)
index_queue = queue.Queue()
completed_ranges = set()
characters = 'abcdefghijklmnopqrstuvwxyz'
min_length = 1
max_length = 4
batch_size = 2500
max_records = sum(len(characters) ** length for length in range(min_length, max_length + 1)) - 1

execution_profile = ExecutionProfile(request_timeout=600)
cluster = Cluster(['10.16.16.22'], execution_profiles={EXEC_PROFILE_DEFAULT: execution_profile})
session = cluster.connect('hashes')


def get_max_index():
    result = session.execute("SELECT hwm FROM metadata WHERE id = 1;").one()
    return result.hwm if result else 0


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


def run_server():
    app.run(host='10.16.16.22', port=5000)


@app.route('/get_range', methods=['GET'])
def get_range():
    if index_queue.empty() and len(completed_ranges) == max_records // batch_size + 1:
        return jsonify({'status': 'finished'})

    if request.method == 'GET':
        if not index_queue.empty():
            start_index = index_queue.get()
        else:
            last_index = get_max_index()
            start_index = (last_index // batch_size + 1) * batch_size

        end_index = min(start_index + batch_size - 1, max_records)

        response_data = {
            'start_index': start_index,
            'end_index': end_index,
            'characters': characters,
            'min_length': min_length,
            'max_length': max_length,
            'batch_size': batch_size
        }

        return jsonify(response_data)


@app.route('/report_completion', methods=['POST'])
def report_completion():
    data = request.json
    start_index = data['start_index']
    end_index = data['end_index']
    completed_ranges.add((start_index, end_index))
    return jsonify({'status': 'success'})


@app.route('/check_last_record', methods=['POST'])
def check_last_record_route():
    data = request.json
    index_to_check = data['last_index']
    if check_last_record(index_to_check):
        count = get_max_index()
        success = check_last_record(count)
        if success:
            return jsonify({'status': 'success'})
        else:
            return jsonify({'status': 'error'})
    else:
        return jsonify({'status': 'error'})


def main():
    start_time = time()
    count = get_max_index()
    global index_queue

    if count == 0:
        print("Таблица пуста. Запускаем новый генератор...")
        index_queue = queue.Queue(maxsize=max_records // batch_size + 1)
        for i in range(0, max_records + 1, batch_size):
            index_queue.put(i)
        app.run(host='10.16.16.22', port=5000)
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
            app.run(host='10.16.16.22', port=5000)


    end_time = time()
    result_time = end_time - start_time
    if result_time > 0.05:
        print(f"Время выполнения программы: {result_time:.3f} с")


if __name__ == "__main__":
    main()
