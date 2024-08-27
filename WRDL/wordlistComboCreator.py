import numpy as np
import itertools
import os
import random

# Flag to control whether to create a wordlist text file
CREATE_WORDLIST_TXT = True

# Minimum and maximum length of combinations
MIN_COMBINATION_LENGTH = 3  # Example: minimum of 3 characters in a combination
MAX_COMBINATION_LENGTH = 4  # Example: maximum of 6 characters in a combination

# Flag to enforce uniqueness in the first {n} characters
ENFORCE_UNIQUENESS_IN_FIRST_N = True
N_UNIQUE_CHARACTERS = 4  # Define how many initial characters should be unique

# Number of combinations to write to the text file
COMBINATIONS_TO_WRITE = 2048  # Number of combinations to save to the file

# Flag to allow or disallow repeating characters in combinations
ALLOW_REPEATING_CHARACTERS = True  # Set to False to disallow repeating characters

def calculate_max_combinations(characters):
    # Calculate the number of unique characters
    n = len(characters)
    
    if n < 2:
        print("Provide at least two unique characters.")
        return 0
    
    # Calculate the max number of unique combinations
    max_combinations = sum(n ** i for i in range(MIN_COMBINATION_LENGTH, MAX_COMBINATION_LENGTH + 1))
    
    print(f"Max combination from selected characters {' '.join(characters)} is {max_combinations}")
    return max_combinations

def create_wordlist(characters):
    # Convert characters into a NumPy array for processing
    characters_array = np.array(list(characters))

    # We will create all possible combinations within the specified length range
    wordlist = set()  # Use a set to avoid duplicates when enforcing uniqueness
    
    for length in range(MIN_COMBINATION_LENGTH, MAX_COMBINATION_LENGTH + 1):
        # Generate all combinations for the given length
        for combination in itertools.product(characters_array, repeat=length):
            word = ''.join(combination)
            
            if not ALLOW_REPEATING_CHARACTERS and len(set(word)) != length:
                continue  # Skip this combination if repeating characters are not allowed
            
            if ENFORCE_UNIQUENESS_IN_FIRST_N:
                # Enforce uniqueness in the first {N_UNIQUE_CHARACTERS} characters
                prefix = word[:N_UNIQUE_CHARACTERS]
                if prefix not in wordlist:
                    wordlist.add(word)
            else:
                wordlist.add(word)
    
    # Shuffle the wordlist
    wordlist = list(wordlist)
    print("Shuffling 🤹 shuffling 🤹 ...")
    random.shuffle(wordlist)

    # Select only the specified number of combinations to write
    combinations_to_write = min(COMBINATIONS_TO_WRITE, len(wordlist))
    wordlist = wordlist[:combinations_to_write]
    
    # Ensure the file exists or create it
    if not os.path.exists("WRDL/comboCreatedWordlist.txt"):
        open("comboCreatedWordlist.txt", "w").close()  # This creates an empty file if it doesn't exist

    # Write the wordlist to a text file
    with open("WRDL/comboCreatedWordlist.txt", "w") as f:
        for word in sorted(wordlist):
            f.write(word + "\n")
    
    if combinations_to_write < COMBINATIONS_TO_WRITE:
        print(f"Expected to write {COMBINATIONS_TO_WRITE} combinations, but only {combinations_to_write} were available and written to 'comboCreatedWordlist.txt'.\n Tryto set ALLOW_REPEATING_CHARACTERS = True to give you more combinations or add more characters to your selection")
    else:
        print(f"{combinations_to_write} combinations have been written to 'comboCreatedWordlist.txt'")

def main():
    # Define the set of characters directly in the script
    characters = "♡♢♣♤♥♦♧"  # You can change this to any set of unique characters you want
    
    # Calculate the maximum number of combinations (for informational purposes)
    max_combinations = calculate_max_combinations(characters)
    
    # Create the wordlist
    if CREATE_WORDLIST_TXT:
        create_wordlist(characters)

if __name__ == "__main__":
    main()
