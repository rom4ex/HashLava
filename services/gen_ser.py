from flask import Flask, jsonify, request
from time import time, sleep
import hashlib
import os
import signal
from cassandra.cluster import Cluster, ExecutionProfile, EXEC_PROFILE_DEFAULT
from collections import deque
from datetime import datetime
from threading import Thread, Event

stop_thread_event = Event()
app = Flask(__name__)
index_queue = deque
completed_ranges = set()
CHARACTERS = 'abcdefghijklmnopqrstuvwxyz'
MIN_LENGTH = 1
MAX_LENGTH = 5
BATCH_SIZE = 2500
MAX_RECORDS = sum(len(CHARACTERS) ** length for length in range(MIN_LENGTH, MAX_LENGTH + 1)) - 1
RECORDS_COUNT = 100000
in_progress_tasks = []
blacklist = set()
shutdown = False
CONTROL_TIME = RECORDS_COUNT / 1000

execution_profile = ExecutionProfile(request_timeout=600)
cluster = Cluster(['10.16.16.22'], execution_profiles={EXEC_PROFILE_DEFAULT: execution_profile})
session = cluster.connect('hashes')


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


def format_insert_metadata_query(hwm_min):
    try:
        query = f"INSERT INTO metadata (id, hwm) VALUES (1, {hwm_min})"
        session.execute(query)
        return query
    except Exception as e:
        print(f"Ошибка при формировании запроса вставки в metadata: {e}")


def check_last_record(index):
    measure_exec_time = True

    password = get_password_by_index(index, CHARACTERS, MIN_LENGTH, MAX_LENGTH)
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    partition_id = get_partition_id(sha256_hash)
    print(f"password: {password}, partition_id:{partition_id}, hash:{sha256_hash}, password_id:{index}")
    analyze_task_execution(in_progress_tasks)

    db_query_exec_time_start = time()

    result = session.execute(f"SELECT * FROM hash WHERE partition_id = {partition_id} AND hash_text = '{sha256_hash}';").one()

    if measure_exec_time:
        db_query_exec_duration = time() - db_query_exec_time_start
        print(f'DB query execution took {db_query_exec_duration:.3} seconds')

    return result.password_id == index and result.hash_text == sha256_hash if result else False


def check_and_update():
    while not stop_thread_event.is_set():
        sleep(CONTROL_TIME)

        in_progress_found = False
        for task_dict in in_progress_tasks.copy():
            if task_dict['status'] == 'in_progress':
                in_progress_found = True
                elapsed_time = time() - task_dict['start_time']
                if elapsed_time > CONTROL_TIME:
                    index_queue.appendleft(task_dict['task'])
                    blacklist.add(task_dict['ip'])
                    in_progress_tasks.remove(task_dict)

        if not in_progress_found:
            stop_thread_event.set()


def analyze_task_execution(tasks):
    if not tasks:
        print("Список заданий пуст.")
        return

    total_execution_time = 0
    total_tasks = len(tasks)
    tasks_per_minute = 0

    for task in tasks:
        start_time = task.get('start_time')
        finish_time = task.get('finish_time')

        if start_time and finish_time:
            start_datetime = datetime.fromtimestamp(start_time)
            finish_datetime = datetime.fromtimestamp(finish_time)

            execution_time = (finish_datetime - start_datetime).total_seconds()
            total_execution_time += execution_time

    if total_tasks > 0:
        average_execution_time = total_execution_time / total_tasks
        tasks_per_minute = (RECORDS_COUNT / average_execution_time) * 60

        print(f"Общее время выполнения всех записей: {total_execution_time:.2f} секунд")
        print(f"Записей за минуту: {tasks_per_minute:.2f}")
        print(f"Среднее время выполнения одного задания: {average_execution_time:.2f} секунд")
    else:
        print("Нет выполненных заданий с полной информацией о времени.")


def run_server():
    app.run(host='10.16.25.100', port=5000, threaded=True)


@app.route('/get_range', methods=['GET'])
def get_range():
    # current_time = time()
    # for task_dict in in_progress_tasks.copy():
    #     if task_dict['status'] == 'in_progress' or task_dict['status'] == 'error':
    #         elapsed_time = current_time - task_dict['start_time']
    #         if elapsed_time > CONTROL_TIME:
    #             blacklist.add(task_dict['ip'])
    #             index_queue.appendleft(task_dict['task'])
    #             task_dict['status'] = 'error'

    hwm_min = 0

    if in_progress_tasks:
        in_progress_values = [task['task'] for task in in_progress_tasks if task['status'] == 'in_progress' or task['status'] == 'error']
        if in_progress_values:
            hwm_min = min(in_progress_values) - 1
        elif completed_ranges:
            max_completed_task = max(completed_ranges, key=lambda x: x[1])
            hwm_min = max_completed_task[1]

    elif not index_queue:
        hwm_min = MAX_RECORDS

    format_insert_metadata_query(hwm_min)
    print(hwm_min)

    if index_queue and len(completed_ranges) == MAX_RECORDS // RECORDS_COUNT + 1:
        return jsonify({'status': 'finished'})

    if request.method == 'GET':
        client_ip = request.remote_addr
        if client_ip in blacklist:
            return jsonify({'status': 'error', 'message': 'Your IP address is blacklisted'})

        if index_queue:
            start_index = index_queue.popleft()
        elif get_max_index() == MAX_RECORDS:
            print("Генерация окончена")
            return jsonify({'status': 'finished'})
        else:
            start_index = get_max_index()+1

        end_index = min(start_index + RECORDS_COUNT - 1, MAX_RECORDS)

        existing_task = next((task for task in in_progress_tasks if task['task'] == start_index), None)

        if existing_task:
            existing_task['ip'] = request.remote_addr
            existing_task['start_time'] = time()
            existing_task['status'] = 'in_progress'
        else:
            task_dict = {
                'task': start_index,
                'ip': request.remote_addr,
                'start_time': time(),
                'status': 'in_progress',
                'finish_time': None
            }

            in_progress_tasks.append(task_dict)

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
    finish_time = data['finish_time']
    status = 'complete'

    for task_dict in in_progress_tasks:
        if task_dict['task'] == start_index:
            task_dict['status'] = status
            task_dict['finish_time'] = finish_time
            completed_ranges.add((start_index, end_index))
            return jsonify({'status': 'success'})

    return jsonify({'status': 'error', 'message': 'Task not found'})


@app.route('/check_last_record', methods=['POST'])
def check_last_record_route():
    data = request.json
    index_to_check = data['last_index']
    if index_to_check != MAX_RECORDS:
        if get_max_index() != MAX_RECORDS:
            print("Генерация завершилась, но последний индекс не соответствует предполагаемому максимальному значению")
            return jsonify({'status': 'error'})
        else:
            if get_max_index() == MAX_RECORDS:
                if check_last_record(MAX_RECORDS):
                    return jsonify({'status': 'success'})
    else:
        if check_last_record(index_to_check):
            return jsonify({'status': 'success'})
        else:
            return jsonify({'status': 'error'})
    global shutdown
    shutdown = True



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
        index_queue = deque(maxlen=MAX_RECORDS // RECORDS_COUNT + 1)
        for i in range(0, MAX_RECORDS + 1, RECORDS_COUNT):
            index_queue.append(i)
        update_thread = Thread(target=check_and_update)
        update_thread.start()
        run_server()
    else:
        if count == MAX_RECORDS:
            print(f"Таблица содержит {count} записей.\n""Максимальное количество записей для данной генерации достигнуто. Измените параметры для начала новой генерации.")
            if check_last_record(count):
                print("Последняя запись успешно проверена.")
            else:
                print("Ошибка при проверке последней записи.")
        elif count > MAX_RECORDS:
            print(f"Таблица содержит {count} записей вместо {MAX_RECORDS}, порядок генерации нарушен")
        else:
            print(f"Таблица содержит {count} записей. Восстанавливаем генератор...")
            index_queue = deque(maxlen=MAX_RECORDS // RECORDS_COUNT + 1)
            for i in range(count, MAX_RECORDS + 1, RECORDS_COUNT):
                index_queue.append(i)
            update_thread = Thread(target=check_and_update)
            update_thread.start()
            run_server()

    end_time = time()
    result_time = end_time - start_time
    if result_time > 0.05:
        print(f"Время выполнения программы: {result_time:.3f} с")

    update_thread.join()


if __name__ == "__main__":
    main()
