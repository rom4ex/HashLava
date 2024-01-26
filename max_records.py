characters = 'abcdefghijklmnopqrstuvwxyz'
min_length = 1
max_length = 4
max_records = sum(len(characters) ** length for length in range(min_length, max_length + 1)) - 1
print(max_records)