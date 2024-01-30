# This data processor will only take .txt files.
# Headers will not be removed, remove them manually

DATA_FOLDER = 'data/'
# TODO: Change the file_name field below with the file you want to process
FILE_NAME = 'transmitter_basic_protocol_rsa_3072_aes_24.txt'
FULL_PATH_TO_FILE = DATA_FOLDER + FILE_NAME

# Open the text file for reading
with open(FULL_PATH_TO_FILE, 'r') as file:
    data = file.read()

# Remove values starting with a comma until an ending square bracket and all other square brackets
def trim(data):
    result = ''
    skip = False

    for char in data:
        if char == ',':
            skip = True
        elif char == '[':
            pass
        elif char == ']' and skip:
            skip = False
        elif char == ']':
            pass
        elif not skip:
            result += char

    return result

# Process the data and remove values as per the criteria
processed_data = trim(data)

# Write the processed data to a new file or perform any desired operation
processed_file_name = 'processed/processed_' + FILE_NAME
with open(processed_file_name, 'w') as file:
    file.write(processed_data)
