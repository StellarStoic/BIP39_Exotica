import random
from itertools import permutations

# File names
input_filename = 'emoji/emojis.txt'
output_filename = 'emojiComboWordlist.txt'

# Step 1: Read the emojis from the file
with open(input_filename, 'r', encoding='utf-8') as file:
    emojis = [line.strip() for line in file.readlines()]

# Step 2: Generate all possible unique 2-emoji combinations
emoji_combinations = set()

# Function to add combination and its permutations to the set
def add_permutations(combo):
    for p in permutations(combo):
        emoji_combinations.add(p)

# Continue generating combinations until we reach the required number
while len(emoji_combinations) < 2048:
    # Randomly select 2 unique emojis
    selected_emojis = random.sample(emojis, 2)
    
    # Create a tuple of the selected emojis
    combination = tuple(selected_emojis)
    
    # Ensure that no permutation of this combination has been used
    if not any(permutation in emoji_combinations for permutation in permutations(combination)):
        add_permutations(combination)

# Convert the set of combinations into a list and shuffle it
# Here, we are only interested in one representative combination
emoji_combinations_list = list({combo for combo in emoji_combinations if sorted(combo) == sorted(combo)})
random.shuffle(emoji_combinations_list)

# Write exactly 2048 combinations to the output file
with open(output_filename, 'w', encoding='utf-8') as file:
    for combo in emoji_combinations_list[:2048]:
        file.write(''.join(combo) + '\n')

print(f"Emoji combinations have been saved to {output_filename}")
