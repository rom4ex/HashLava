from flask import Flask, jsonify, request
import queue
from time import time
import hashlib
import os
import signal
from cassandra.cluster import Cluster, ExecutionProfile, EXEC_PROFILE_DEFAULT

app = Flask(__name__)
index_queue = queue.Queue()
completed_ranges = set()
CHARACTERS = 'abcdefghijklmnopqrstuvwxyz'
MIN_LENGTH = 1
MAX_LENGTH = 4
BATCH_SIZE = 2500
MAX_RECORDS = sum(len(CHARACTERS) ** length for length in range(MIN_LENGTH, MAX_LENGTH + 1)) - 1
RECORDS_COUNT = 10000

execution_profile = ExecutionProfile(request_timeout=600)
cluster = Cluster(['10.16.16.22'], execution_profiles={EXEC_PROFILE_DEFAULT: execution_profile})
session = cluster.connect('hashes')

shutdown = False


def get_max_index():
    result = session.execute("SELECT hwm FROM metadata WHERE id = 1;").one()
    return result.hwm if result else 0


def get_partition_id(sha256_hash):
    return int(sha256_hash[-4:], 16)


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


def check_last_record(index):
    measure_exec_time = True

    password = get_password_by_index(index, CHARACTERS, MIN_LENGTH, MAX_LENGTH)
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    partition_id = get_partition_id(sha256_hash)
    print(f"password: {password}, partition_id:{partition_id}, hash:{sha256_hash}, password_id:{index}")

    db_query_exec_time_start = time()

    result = session.execute(
        f"SELECT * FROM hash WHERE partition_id = {partition_id} AND hash_text = '{sha256_hash}';").one()

    if measure_exec_time:
        db_query_exec_duration = time() - db_query_exec_time_start
        print(f'DB query execution took {db_query_exec_duration:.3} seconds')

    return result.password_id == index and result.hash_text == sha256_hash if result else False


def run_server():
    app.run(host='10.16.16.22', port=5000, use_reloader=False)


@app.route('/get_range', methods=['GET'])
def get_range():
    if index_queue.empty() and len(completed_ranges) == MAX_RECORDS // RECORDS_COUNT + 1:
        return jsonify({'status': 'finished'})

    if request.method == 'GET':
        if not index_queue.empty():
            start_index = index_queue.get()
        elif get_max_index() == MAX_RECORDS:
            print("Генерация окончена")
            return jsonify({'status': 'finished'})
        else:
            start_index = get_max_index() + 1

        end_index = min(start_index + RECORDS_COUNT - 1, MAX_RECORDS)

        response_data = {
            'start_index': start_index,
            'end_index': end_index,
            'characters': CHARACTERS,
            'min_length': MIN_LENGTH,
            'max_length': MAX_LENGTH,
            'batch_size': BATCH_SIZE
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
    if index_to_check != MAX_RECORDS:
        print("Генерация завершилась, но последний индекс не соответствует предполагаемому максимальному значению")
        return jsonify({'status': 'error'})
    else:
        if check_last_record(index_to_check):
            global shutdown
            shutdown = True
            return jsonify({'status': 'success'})
        else:
            return jsonify({'status': 'error'})


@app.teardown_request
def shutdown_server(exception=None):
    global shutdown
    if shutdown:
        print("Shutting down server...")
        os.kill(os.getpid(), signal.SIGINT)


def main():
    start_time = time()
    count = get_max_index()
    global index_queue

    if count == 0:
        print("Таблица пуста. Запускаем новый генератор...")
        index_queue = queue.Queue(maxsize=MAX_RECORDS // RECORDS_COUNT + 1)
        for i in range(0, MAX_RECORDS + 1, RECORDS_COUNT):
            index_queue.put(i)
        run_server()
    else:
        if count == MAX_RECORDS:
            print(
                f"Таблица содержит {count} записей.\n""Максимальное количество записей для данной генерации достигнуто. Измените параметры для начала новой генерации.")
            if check_last_record(count):
                print("Последняя запись успешно проверена.")
            else:
                print("Ошибка при проверке последней записи.")
        elif count > MAX_RECORDS:
            print(f"Таблица содержит {count} записей вместо {MAX_RECORDS}, порядок генерации нарушен")
        else:
            print(f"Таблица содержит {count} записей. Восстанавливаем генератор...")
            index_queue = queue.Queue(maxsize=MAX_RECORDS // RECORDS_COUNT + 1)
            for i in range(count, MAX_RECORDS + 1, RECORDS_COUNT):
                index_queue.put(i)
            run_server()

    end_time = time()
    result_time = end_time - start_time
    if result_time > 0.05:
        print(f"Время выполнения программы: {result_time:.3f} с")


if __name__ == "__main__":
    main()
