# Open a file in write mode. If the file does not exist, it will be created.
# The 'with' statement ensures that the file is properly closed after writing.
with open("justNumbers.txt", "w") as file:
    # Use a for loop to iterate over the range of numbers from 1 to 2048 (inclusive).
    for number in range(1, 2049):
        # Convert the number to a string and write it to the file.
        # Add a newline character '\n' after each number to place each number on a new line.
        file.write(str(number) + "\n")

# The file is automatically closed after the 'with' block is done.
# After running this script, you will find a file named 'justNumbers.txt' in the same directory as your script.
# The file will contain numbers from 1 to 2048, each on a new line.
