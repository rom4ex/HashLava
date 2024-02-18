from flask import Flask, jsonify, request
from time import time, sleep
import hashlib
import logging
from cassandra.cluster import Cluster, ExecutionProfile, EXEC_PROFILE_DEFAULT
from collections import deque, defaultdict
from threading import Thread, Event

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

file_handler = logging.FileHandler('gen_ser.log')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)

stop_thread_event = Event()
app = Flask(__name__)
completed_ranges = set()
CHARACTERS = 'abcdefghijklmnopqrstuvwxyz'
MIN_LENGTH = 1
MAX_LENGTH = 4
BATCH_SIZE = 2500
MAX_RECORDS = sum(len(CHARACTERS) ** length for length in range(MIN_LENGTH, MAX_LENGTH + 1)) - 1
RECORDS_COUNT = 100000
in_progress_tasks = []
blacklist = defaultdict(list)
shutdown = False
CONTROL_TIME = RECORDS_COUNT / 1000
bag_queue = deque()

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
        logger.error(f"Ошибка при формировании запроса вставки в metadata: {e}")


def check_last_record(index):
    measure_exec_time = True

    password = get_password_by_index(index, CHARACTERS, MIN_LENGTH, MAX_LENGTH)
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    partition_id = get_partition_id(sha256_hash)
    logger.debug(f"password: {password}, partition_id:{partition_id}, hash:{sha256_hash}, password_id:{index}")
    analyze_task_execution(in_progress_tasks)

    db_query_exec_time_start = time()

    result = session.execute(f"SELECT * FROM hash WHERE partition_id = {partition_id} AND hash_text = '{sha256_hash}';").one()

    if measure_exec_time:
        db_query_exec_duration = time() - db_query_exec_time_start
        logger.debug(f'DB query execution took {db_query_exec_duration:.3} seconds')

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
                    blacklist[task_dict['username']].append(task_dict['pid'])
                    bag_queue.appendleft(task_dict['task'])
                    task_dict['status'] = 'error'

        if not in_progress_found:
            stop_thread_event.set()


def analyze_task_execution(tasks):
    if not tasks:
        logger.debug("Список заданий пуст.")
        return

    total_tasks = len(tasks)

    start_times = [task.get('start_time') for task in tasks if task.get('start_time')]
    finish_times = [task.get('finish_time') for task in tasks if task.get('finish_time')]

    if not start_times or not finish_times:
        logger.debug("Недостаточно данных для анализа времени выполнения заданий.")
        return

    start_time = min(start_times)
    finish_time = max(finish_times)

    total_execution_time = finish_time - start_time

    if total_tasks > 0:
        average_execution_time = total_execution_time / total_tasks
        tasks_per_minute = (RECORDS_COUNT / average_execution_time) * 60

        logger.debug(f"Общее время выполнения всех записей: {total_execution_time:.2f} секунд")
        logger.debug(f"Записей за минуту: {tasks_per_minute:.2f}")
        logger.debug(f"Среднее время выполнения одного задания: {average_execution_time:.2f} секунд")
    else:
        logger.debug("Нет выполненных заданий с полной информацией о времени.")


def run_server():
    app.run(host='10.16.25.100', port=5000)


@app.route('/get_range', methods=['GET'])
def get_range():
    hwm_min = 0
    username = request.args.get('username')
    pid = request.args.get('pid')

    if bag_queue:
        min_value = min(bag_queue)
        hwm_min = min_value - 1 if min_value > 0 else 0
    elif in_progress_tasks:
        in_progress_values = [task['task'] for task in in_progress_tasks if task['status'] == 'in_progress' or task['status'] == 'error']
        if in_progress_values:
            min_value = min(in_progress_values)
            hwm_min = min_value - 1 if min_value > 0 else 0
        elif completed_ranges:
            max_completed_task = max(completed_ranges, key=lambda x: x[1])
            hwm_min = max_completed_task[1]

    if hwm_min > 0:
        format_insert_metadata_query(hwm_min)
        logger.debug(hwm_min)

    if all(task['status'] == 'complete' for task in in_progress_tasks) and len(completed_ranges) == MAX_RECORDS // RECORDS_COUNT + 1:
        return jsonify({'status': 'finished', 'message': "Mission complete"})

    if request.method == 'GET':
        bag_pid = len(blacklist[username])
        if bag_pid > 16:
            return jsonify({'status': 'error', 'message': "Your client is blocked"})

        if bag_queue:
            start_index = bag_queue.popleft()
        elif not in_progress_tasks:
            if get_max_index() == 0:
                start_index = 0
            else:
                start_index = get_max_index() + 1
        else:
            max_start_index = max(task['task'] for task in in_progress_tasks)
            start_index = max_start_index + RECORDS_COUNT

        if start_index > MAX_RECORDS:
            return jsonify({'status': 'error', 'message': "start_index > MAX_RECORDS"})

        end_index = min(start_index + RECORDS_COUNT - 1, MAX_RECORDS)

        existing_task = next((task for task in in_progress_tasks if task['task'] == start_index), None)
        if existing_task:
            if existing_task['status'] == 'in_progress' or existing_task['status'] == 'complete':
                pass
            elif existing_task['status'] == 'error':
                existing_task['ip'] = request.remote_addr
                existing_task['username'] = username
                existing_task['pid'] = pid
                existing_task['start_time'] = time()
                existing_task['status'] = 'in_progress'
        else:
            task_dict = {
                'task': start_index,
                'ip': request.remote_addr,
                'username': username,
                'pid': pid,
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
            logger.error("Генерация завершилась, но последний индекс не соответствует предполагаемому максимальному значению")
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
    # global shutdown
    # shutdown = True



# def shutdown_server(exception=None):
#     global shutdown
#     if shutdown:
#         logger.info("Shutting down server...")
#         os.kill(os.getpid(), signal.SIGINT)


# def shutdown():
#     sys.exit()


def start():
    update_thread = Thread(target=check_and_update)
    update_thread.start()
    run_server()
    update_thread.join()


def main():
    start_time = time()
    count = get_max_index()

    if count == 0:
        logger.info("Таблица пуста. Запускаем новый генератор...")
        start()
    else:
        if count == MAX_RECORDS:
            logger.info(f"Таблица содержит {count} записей.\n""Максимальное количество записей для данной генерации достигнуто.\nИзмените параметры для начала новой генерации.")
            if check_last_record(count):
                logger.info("Последняя запись успешно проверена.")
            else:
                logger.error("Ошибка при проверке последней записи.")
        elif count > MAX_RECORDS:
            logger.error(f"Таблица содержит {count} записей вместо {MAX_RECORDS}, порядок генерации нарушен")
        else:
            logger.info(f"Таблица содержит {count} записей. Восстанавливаем генератор...")
            start()

    end_time = time()
    result_time = end_time - start_time
    if result_time > 0.05:
        logger.info(f"Время выполнения программы: {result_time:.3f} с")


if __name__ == "__main__":
    main()
