# Universal script to convert text to Braille Unicode

# Function to convert a single character to Braille
def char_to_braille(char, punctuation_map):
    # Normalize the character (lowercase, etc.)
    normalized_char = char.lower()

    # Return the corresponding Braille character or '?' if not found
    return punctuation_map.get(normalized_char, '?')

# Function to convert an entire text to Braille
def text_to_braille(text, punctuation_map):
    braille_text = ''.join(char_to_braille(char, punctuation_map) for char in text)
    return braille_text


english_punctuation_map = {
    'a': '⠁',  # Braille dots-1
    'b': '⠃',  # Braille dots-1-2
    'c': '⠉',  # Braille dots-1-4
    'd': '⠙',  # Braille dots-1-4-5
    'e': '⠑',  # Braille dots-1-5
    'f': '⠋',  # Braille dots-1-2-4
    'g': '⠛',  # Braille dots-1-2-4-5
    'h': '⠓',  # Braille dots-1-2-5
    'i': '⠊',  # Braille dots-2-4
    'j': '⠚',  # Braille dots-2-4-5
    'k': '⠅',  # Braille dots-1-3
    'l': '⠇',  # Braille dots-1-2-3
    'm': '⠍',  # Braille dots-1-3-4
    'n': '⠝',  # Braille dots-1-3-4-5
    'o': '⠕',  # Braille dots-1-3-5
    'p': '⠏',  # Braille dots-1-2-3-4
    'q': '⠟',  # Braille dots-1-2-3-4-5
    'r': '⠗',  # Braille dots-1-2-3-5
    's': '⠎',  # Braille dots-2-3-4
    't': '⠞',  # Braille dots-2-3-4-5
    'u': '⠥',  # Braille dots-1-3-6
    'v': '⠧',  # Braille dots-1-2-3-6
    'w': '⠺',  # Braille dots-2-4-5-6
    'x': '⠭',  # Braille dots-1-3-4-6
    'y': '⠽',  # Braille dots-1-3-4-5-6
    'z': '⠵',  # Braille dots-1-3-5-6
}

slovenian_punctuation_map = {
    'a': '⠁',  # Braille dots-1
    'b': '⠃',  # Braille dots-1-2
    'c': '⠉',  # Braille dots-1-4
    'č': '⠡',  # Braille dots-1-6
    'd': '⠙',  # Braille dots-1-4-5
    'e': '⠑',  # Braille dots-1-5
    'f': '⠋',  # Braille dots-1-2-4
    'g': '⠛',  # Braille dots-1-2-4-5
    'h': '⠓',  # Braille dots-1-2-5
    'i': '⠊',  # Braille dots-2-4
    'j': '⠚',  # Braille dots-2-4-5
    'k': '⠅',  # Braille dots-1-3
    'l': '⠇',  # Braille dots-1-2-3
    'm': '⠍',  # Braille dots-1-3-4
    'n': '⠝',  # Braille dots-1-3-4-5
    'o': '⠕',  # Braille dots-1-3-5
    'p': '⠏',  # Braille dots-1-2-3-4
    'q': '⠟',  # Braille dots-1-2-3-4-5
    'r': '⠗',  # Braille dots-1-2-3-5
    's': '⠎',  # Braille dots-2-3-4
    'š': '⠱',  # Braille dots-1-5-6
    't': '⠞',  # Braille dots-2-3-4-5
    'u': '⠥',  # Braille dots-1-3-6
    'v': '⠧',  # Braille dots-1-2-3-6
    'w': '⠺',  # Braille dots-2-4-5-6
    'x': '⠭',  # Braille dots-1-3-4-6
    'y': '⠽',  # Braille dots-1-3-4-5-6
    'z': '⠵',  # Braille dots-1-3-5-6
    'ž': '⠮',  # Braille dots-2-3-4-6
}

# Mapping of languages to their respective Braille maps
language_maps = {
    1: ('English', english_punctuation_map),
    2: ('Slovenian', slovenian_punctuation_map),
}

# Ask the user to select a language
print("Select a language for Braille translation:")
for index, (language, _) in language_maps.items():
    print(f"{index}: {language}")

selected_language = int(input("Enter the number corresponding to the language: "))
if selected_language in language_maps:
    language_name, selected_map = language_maps[selected_language]
    print(f"Selected language: {language_name}")
else:
    print("Invalid selection. Defaulting to English.")
    selected_map = english_punctuation_map

# Input and output filenames
input_filename = "slovenian.txt"
output_filename = "braille.txt"

# Read wordlist from file
with open(input_filename, 'r', encoding='utf-8') as infile:
    wordlist = infile.readlines()

# Convert each line in the wordlist to Braille
braille_translations = []
for word in wordlist:
    word = word.strip()  # Remove any leading/trailing whitespace
    braille_word = text_to_braille(word, selected_map)
    braille_translations.append(braille_word)

# Write the Braille translations to the output file
with open(output_filename, 'w', encoding='utf-8') as outfile:
    for braille_word in braille_translations:
        outfile.write(braille_word + '\n')

print(f"Braille translation completed. Check the file {output_filename} for the output.")