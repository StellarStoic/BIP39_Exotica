# To successfully change characters in one wordlist, you need to include the map of all characters (From -> to) 
import os

# Step 1: Define the lettersMap
lettersMap = {
# From -> To
    'a': '🅐',
    'b': '🅑',
    'c': '🅒',
    'd': '🅓',
    'e': '🅔',
    'f': '🅕',
    'g': '🅖',
    'h': '🅗',
    'i': '🅘',
    'j': '🅙',
    'k': '🅚',
    'l': '🅛',
    'm': '🅜',
    'n': '🅝',
    'o': '🅞',
    'p': '🅟',
    'q': '🅠',
    'r': '🅡',
    's': '🅢',
    't': '🅣',
    'u': '🅤',
    'v': '🅥',
    'w': '🅦',
    'x': '🅧',
    'y': '🅨',
    'z': '🅩'
}

# Step 2: Define the function to translate the word list
def translate_wordlist(input_file_path):
    # Check if the file exists
    if not os.path.exists(input_file_path):
        print(f"The file {input_file_path} does not exist.")
        return

    # Open the input file and create an output file
    with open(input_file_path, 'r', encoding='utf-8') as infile, \
         open('enclosedLettersWRDL.txt', 'w', encoding='utf-8') as outfile:
        
        # Step 3: Read each line (word) from the input file
        for line in infile:
            # Remove any surrounding whitespace (like newline characters)
            word = line.strip()

            # Translate the word using the lettersMap
            translated_word = ''.join(lettersMap.get(char, char) for char in word)

            # Step 4: Write the translated word to the output file
            outfile.write(translated_word + '\n')

    print(f"Translation complete. Output written to enclosedLettersWRDL.txt")

# Example usage:
# Specify the path to your word list file here
input_file_path = 'WRDL/standard/english.txt'
translate_wordlist(input_file_path)
