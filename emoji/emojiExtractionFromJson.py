import json

# Specify the input and output file names
input_filename = 'emojis2.json'
output_filename = 'emojis.txt'

# Read the JSON data from the file
with open(input_filename, 'r', encoding='utf-8') as file:
    emoji_json = json.load(file)

# Extract the emojis from the 'code' field
emojis = [emoji['code'] for emoji in emoji_json]

# Write the emojis to the text file, each on a separate line
with open(output_filename, 'w', encoding='utf-8') as file:
    for emoji in emojis:
        file.write(emoji + '\n')

print(f"Emojis have been extracted and saved to {output_filename}")
