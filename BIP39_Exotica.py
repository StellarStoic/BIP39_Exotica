import subprocess
import hashlib
import os
import time
import datetime
import binascii
import base58
from ecdsa import SigningKey, SECP256k1
from mnemonic import Mnemonic
import bech32
from bech32 import bech32_encode, convertbits
import qrcode
import io
from bip_utils import (
    Bip39SeedGenerator, Bip32Slip10Secp256k1, Bip44, Bip49, Bip84, Bip86,
    Bip44Coins, Bip49Coins, Bip84Coins, Bip86Coins
)
from coincurve import PrivateKey  # Use coincurve to handle public key generation
from coincurve import PrivateKey as CoincurvePrivateKey


# ******* WALLET SETTINGS ************
# Default derivation path suffix (can be changed by user if needed)
DERIVATION_PATH_SUFFIX = "/0/21"

# User-defined password for mnemonic (can be empty or None)
PASSWORD = "A Super Strong Password 7"  # Replace with the desired password or leave empty


# ******* WORDLIST SETTINGS **********

# Specify the paths and options
wordlist_path = 'WRDL/nonStandard/slovenian.txt'
# wordlist_path = 'WRDL/standard/english.txt'
# wordlist_path = 'WRDL/exotic/english_braille_WRDL.txt'
# wordlist_path = 'WRDL/exotic/dominoesWRDL.txt'

#For custom mnemonics recovery we need coresponding custom wordlists which should also be set to True.
CUSTOM_MNEMONIC = False # If GENERATE_BY_COLOR = True, the custom_mnemonic_text will be ignored
CUSTOM_WORDLIST = True  # Set to True if using a custom wordlistabandon abandon

custom_mnemonic_text = "abeceda abeceda abeceda abeceda abeceda abeceda abeceda abeceda abeceda abeceda abeceda ajda" if CUSTOM_MNEMONIC else None

# ********* COLORS SETTINGS ************
GENERATE_BY_COLOR = False # Colors will always overide custom_mnemonic_text if CUSTOM_MNEMONIC=True

#
# Chose 8 or 16 HEX color values like #9EB70E #6A5E9A #7A8EA3...
# The same mnemonic will be produced no matter the colors value order

create_wallet_from_colors = "#022544 #2AB9C1 #3D0FC3 #5FFCBE #7B45DF #A4834C #B7546D #D704A8"
# *****************************

timestamp = datetime.datetime.now().strftime("%d_%m_%Y_%H-%M-%S")

# ANSI escape sequences for colors and styles
class Style:
    ITALIC = '\033[3m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

class Fore:
    RED = '\033[31m'
    GREEN = '\033[32m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    YELLOW = '\033[33m'
    ORANGE = '\033[38;5;214m'
    LIGHTYELLOW_EX = '\033[93m'
    PINK = '\033[95m'
    RESET = '\033[39m'

# ****************CALLING QR CODE GENERATION TOOL **********************(https://github.com/Jojodicus/qr2eascii)************************************

import subprocess
import time

def generate_ascii_qr_code(data, description, color='', include_color=True):
    """
    Generates an ASCII QR code using convert.py script for the given data.
    
    Parameters:
        data (str): The data to encode in the QR code.
        description (str): Description to be displayed before the QR code.
        color (str): ANSI color code to colorize the QR code output.
        include_color (bool): Whether to include color in the output.
    
    Returns:
        str: The ASCII QR code along with the description.
    """
    # Command to generate QR code
    cmd = [
        'python', 'qr.py',  # Use the correct path to your qr.py script
        '-i', data,
        '--white', '██', 
        '--black', '  ', 
        '--border', '1'
    ]
    
    # # Print the command for debugging
    # print(f"Generating QR code for: {description} with data: {data}")
    # print(f"Command: {' '.join(cmd)}")

    try:
        # Execute the command and capture the output
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode == 0:
            qr_code = result.stdout
            if include_color and color:
                # Apply the color to the QR code if needed
                colored_qr_code = f"{color}{qr_code}{Fore.RESET}"
                # Display the description and the colored QR code
                print(f"\n{description}")
                print(colored_qr_code)
                # Return the description and colored QR code for writing to the TXT file
                return f"{description}\n{colored_qr_code}"
            else:
                # Return the QR code without color for TXT file
                return f"{description}\n{qr_code}"
        else:
            error_message = f"Error generating QR code: {result.stderr}"
            print(error_message)
            return f"{description}\n{error_message}\n"

    except Exception as e:
        exception_message = f"Exception occurred while generating QR code: {str(e)}"
        print(exception_message)
        return f"{description}\n{exception_message}\n"

    # Add a short delay to ensure QR codes are generated correctly
    time.sleep(0.3)


# ********** BIP39 COLORS code is from (https://github.com/enteropositivo/bip39colors/tree/main) ***********
class BIP39Colors:
    words = []
    errors = [  'no error',
                'Invalid mnemonic. Length must be 12/24 words or decimals between [1-2048]', 
                'Some of the words do not belong to the BIP39 word list',
                'Enter 8 or 16 colors in hex format: #ABCDEF ',
                'Colors provided are not valid BIP39 colors']
    error = 0
    colors = []
    wordPositions = []
    seed = ""

    @staticmethod
    def fromSeed(seed):
        BIP39Colors.error = 0
        BIP39Colors.colors = []
        BIP39Colors.wordPositions = []
        BIP39Colors.seed = ""

        aSeed = [p.lower() for p in seed.strip().split()]

        if len(aSeed) not in [12, 24]:
            BIP39Colors.error = 1
            return False

        if all(w.isdigit() and 1 <= int(w) <= 2048 for w in aSeed):
            BIP39Colors.wordPositions = [int(idx) for idx in aSeed]
            BIP39Colors.seed = ' '.join(BIP39Colors.words[idx - 1] for idx in BIP39Colors.wordPositions)
            BIP39Colors.seedToColors()
            return True

        onlyWords = all(w in BIP39Colors.words for w in aSeed)

        if onlyWords:
            BIP39Colors.wordPositions = [BIP39Colors.words.index(w) + 1 for w in aSeed]
            BIP39Colors.seed = ' '.join(aSeed)
            BIP39Colors.seedToColors()
            return True

        BIP39Colors.error = 2
        return False

    @staticmethod
    def seedToColors():
        BIP39Colors.colors = []
        text = ''.join(str(valor).zfill(4) for valor in BIP39Colors.wordPositions)
        pieces = [text[i:i + 6] for i in range(0, len(text), 6)]

        BIP39Colors.colors = [
            '#{0:06X}'.format(int(str( (val % 8) * 2 + (val // 8) if len(BIP39Colors.wordPositions)==12  else val  )+str(position))).upper()
            for val, i in enumerate(pieces)
            for position in [i]
        ]   
    
    @staticmethod
    def toSeed(colors):
        BIP39Colors.error = 0
        BIP39Colors.colors = []
        BIP39Colors.wordPositions = []
        BIP39Colors.seed = ""

        aColors = colors.strip().split()

        if len(aColors) != 8 and len(aColors) != 16:
            BIP39Colors.error = 3
            return False

        if not all(color.startswith('#') and len(color) == 7 and all(c.isalnum() for c in color[1:]) for color in aColors):
            BIP39Colors.error = 3
            return False

        BIP39Colors.colors = aColors

        decArray = sorted([str(int(color[1:], 16)).zfill(8) for color in BIP39Colors.colors])

        if not BIP39Colors.isSequentialArray(decArray):
            BIP39Colors.colors = []
            BIP39Colors.error = 4
            return False

        text = ''.join(color[-6:] for color in decArray)
        bip39Positions = [text[i:i+4] for i in range(0, len(text), 4)]

        if not all(w.isdigit() and 1 <= int(w) <= 2048 for w in bip39Positions):
            BIP39Colors.colors = []
            BIP39Colors.error = 4
            return False

        BIP39Colors.wordPositions = bip39Positions
        
        # # Debugging - Output the reconstructed word positions and entropy
        # print(f"Reconstructed Word Positions: {bip39Positions}")
        
        # Convert word positions back to entropy
        # reconstructed_entropy, _ = generate_entropy_from_mnemonic_or_seed(' '.join(BIP39Colors.words[int(idx) - 1] for idx in bip39Positions), BIP39Colors.words)
        # print(f"Reconstructed Entropy: {reconstructed_entropy.hex()}")

        BIP39Colors.seed = ' '.join(BIP39Colors.words[int(idx) - 1] for idx in bip39Positions)

        return True

    @staticmethod
    def getError():
        return BIP39Colors.errors[BIP39Colors.error]

    @staticmethod
    def isSequentialArray(array):
        expectedDiff = 2 if len(array) == 8 else 1

        for i in range(1, len(array)):
            current = int(array[i][:2])
            previous = int(array[i - 1][:2])

            if current - previous != expectedDiff:
                return False

        return True
    
    @staticmethod
    def hex_to_rgb(hex):
        return [int(hex[1:3], 16), int(hex[3:5], 16), int(hex[5:7], 16)]

    @staticmethod
    def rgb_to_hex(rgb):
        return f"#{((1 << 24) + (rgb[0] << 16) + (rgb[1] << 8) + rgb[2]):06X}"

    @staticmethod
    def rgb_to_hsv(rgb):
        r, g, b = rgb
        maximum = max(r, g, b)
        minimum = min(r, g, b)
        delta = maximum - minimum

        h, s, v = 0, 0, 0

        if delta == 0:
            h = 0
        elif maximum == r:
            h = ((g - b) / delta) % 6
        elif maximum == g:
            h = (b - r) / delta + 2
        else:
            h = (r - g) / delta + 4

        h = round(h * 60)
        if h < 0:
            h += 360

        s = 0 if maximum == 0 else delta / maximum
        s = round(s * 100)

        v = round((maximum / 255) * 100)

        return [h, s, v]

    @staticmethod
    def colorPalette():
        colors = BIP39Colors.colors

        rgb_arr = [BIP39Colors.hex_to_rgb(color) for color in colors]

        color_hsv = []

        for rgb in rgb_arr:
            hsv = BIP39Colors.rgb_to_hsv(rgb)
            color_hsv.append({"rgb": rgb, "hsv": hsv})

        color_hsv.sort(key=lambda color: color["hsv"][0])

        sorted_colors = [color["rgb"] for color in color_hsv]

        return [BIP39Colors.rgb_to_hex(rgb) for rgb in sorted_colors]

def load_wordlist(wordlist_path):
    # Load custom Slovenian wordlist
    with open(wordlist_path, 'r', encoding='utf-8') as file:
        slovenian_wordlist = [line.strip() for line in file.readlines()]

    # Ensure the wordlist has exactly 2048 words
    if len(slovenian_wordlist) != 2048:
        raise ValueError("Wordlist must contain exactly 2048 words.")

    return slovenian_wordlist

def calculate_file_hash(file_path):
    """
    Calculates the SHA-256 hash of the given file.

    Parameters:
        file_path (str): The path to the file.

    Returns:
        str: The SHA-256 hash of the file.
    """
    hash_sha256 = hashlib.sha256()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def create_mnemonic_from_entropy(language, entropy, custom_wordlist=None):
    if custom_wordlist:
        # Convert the entropy to binary
        entropy_bits = bin(int.from_bytes(entropy, byteorder='big'))[2:].zfill(len(entropy) * 8)
        checksum_bits = bin(int(hashlib.sha256(entropy).digest()[0]))[2:].zfill(8)[:len(entropy) * 8 // 32]
        full_bits = entropy_bits + checksum_bits

        # Break into 11-bit segments and map to custom wordlist
        words = []
        for i in range(len(full_bits) // 11):
            index = int(full_bits[i * 11:(i + 1) * 11], 2)
            words.append(custom_wordlist[index])

        mnemonic_phrase = ' '.join(words)
    else:
        # Fallback to default behavior for other languages
        mnemonic = Mnemonic(language=language)
        mnemonic_phrase = mnemonic.to_mnemonic(entropy)

    return mnemonic_phrase

def generate_entropy_for_word_count(word_count):
    if word_count == 12:
        return os.urandom(128 // 8)  # 128 bits
    # elif word_count == 15:
    #     return os.urandom(160 // 8)  # 160 bits
    # elif word_count == 18:
    #     return os.urandom(192 // 8)  # 192 bits
    elif word_count == 24:
        return os.urandom(256 // 8)  # 256 bits
    else:
        raise ValueError("Invalid word count. Choose 12 or 24.")
    
def mnemonic_to_seed(mnemonic_phrase, passphrase=PASSWORD, custom_wordlist=None):
    if not passphrase:  # Treat empty password as None
        passphrase = ""

    if custom_wordlist:
        # Custom wordlist is used, so we need to handle seed generation manually
        mnemonic = Mnemonic
        mnemonic.wordlist = custom_wordlist
        seed = hashlib.pbkdf2_hmac("sha512", mnemonic_phrase.encode("utf-8"), ("mnemonic" + passphrase).encode("utf-8"), 2048)
    else:
        seed = Bip39SeedGenerator(mnemonic_phrase).Generate(passphrase)
    return seed

def validate_custom_mnemonic(custom_mnemonic, custom_wordlist):
    words = custom_mnemonic.split()

    # Step 1: Check if all words are in the custom wordlist and get their zero-based index
    word_indexes = []
    for word in words:
        if word not in custom_wordlist:
            raise ValueError(f"{Fore.RED}Error: Word '{word}' not found in the custom wordlist. Check if you chosen the right Wordlist or set CUSTOM_MNEMONIC = False if you'd like to generate random.{Fore.RESET}")
        word_indexes.append(custom_wordlist.index(word))  # Zero-based index for internal use

    # Step 2: Convert word indexes back to entropy
    entropy_bits = ''.join([bin(index)[2:].zfill(11) for index in word_indexes])  # Convert to 11-bit binary

    # Calculate the length of the entropy (128 bits for 12 words, 256 bits for 24 words, etc.)
    entropy_length = (len(words) * 11) - (len(words) * 11 // 33)  # Calculate expected entropy length in bits
    entropy_bits_only = entropy_bits[:entropy_length]  # Extract only the entropy part

    # Convert back to entropy bytes
    entropy = int(entropy_bits_only, 2).to_bytes(len(entropy_bits_only) // 8, byteorder='big')

    # Step 3: Calculate the checksum from the entropy
    checksum_length = len(entropy) * 8 // 32  # Length of checksum in bits
    calculated_checksum_bits = bin(int(hashlib.sha256(entropy).digest()[0]))[2:].zfill(8)[:checksum_length]

    # Extract the checksum bits from the original entropy_bits string
    mnemonic_checksum_bits = entropy_bits[entropy_length:entropy_length + checksum_length]

    # # Debugging: Print all the calculated values for verification
    # print(f"Entropy (Hex): {entropy.hex()}")
    # print(f"Entropy (Binary): {entropy_bits_only}")
    # print(f"Expected Checksum Length (Bits): {checksum_length}")
    # print(f"Calculated Checksum Bits: {calculated_checksum_bits}")
    # print(f"Mnemonic Checksum Bits: {mnemonic_checksum_bits}")

    # Step 4: Validate the checksum
    if calculated_checksum_bits != mnemonic_checksum_bits:
        raise ValueError(f"{Fore.RED}Error: Invalid mnemonic checksum.{Fore.RESET}")

    # Adjust word indexes back to 1-based indexing for external use
    adjusted_word_indexes = [index + 1 for index in word_indexes]

    return adjusted_word_indexes
    
#     return entropy, word_indexes
def generate_entropy_from_mnemonic_or_seed(mnemonic_or_seed, custom_wordlist):
    """
    Generates entropy from a given mnemonic or custom seed, ensuring consistency across both processes.
    """
    # Validate that all words exist in the custom wordlist and get their indexes
    word_indexes = validate_custom_mnemonic(mnemonic_or_seed, custom_wordlist)
    
    # Convert each index back to an 11-bit binary string
    entropy_bits = ''.join([bin(index - 1)[2:].zfill(11) for index in word_indexes])  # Subtract 1 to revert to 0-based index
    
    # Calculate the entropy length in bits (11 bits * number of words - checksum length in bits)
    entropy_length_bits = len(word_indexes) * 11 - (len(word_indexes) // 3)
    
    # Calculate the checksum length
    checksum_length_bits = len(word_indexes) // 3  # 1 bit for every 3 words

    # Extract the actual entropy bits
    actual_entropy_bits = entropy_bits[:entropy_length_bits]

    # Convert the entropy bits back to bytes
    entropy = int(actual_entropy_bits, 2).to_bytes(len(actual_entropy_bits) // 8, byteorder='big')

    return entropy, word_indexes

def generate_seed_from_entropy(entropy, passphrase=PASSWORD):
    """
    Generates a seed from the given entropy using PBKDF2.
    """
    # Manually generate the seed from the entropy using PBKDF2
    seed = hashlib.pbkdf2_hmac("sha512", entropy, ("mnemonic" + passphrase).encode('utf-8'), 2048)
    return seed

# # This function should be used instead of the undefined generate_seed_from_custom_mnemonic
def generate_seed_and_entropy(mnemonic_or_seed, custom_wordlist=None, passphrase=PASSWORD, language=None):
    """
    Handles both custom seed and custom mnemonic cases uniformly.
    """
    if not passphrase:  # Treat empty password as None
        passphrase = ""

    if custom_wordlist:
        # Generate entropy from the provided custom seed or mnemonic and get word indexes
        entropy, word_indexes = generate_entropy_from_mnemonic_or_seed(mnemonic_or_seed, custom_wordlist)
        # Generate the mnemonic from the entropy to ensure consistency in the seed
        mnemonic_phrase = create_mnemonic_from_entropy(language, entropy, custom_wordlist)
        # Re-calculate word indexes after generating the mnemonic
        word_indexes = [custom_wordlist.index(word) for word in mnemonic_phrase.split()]
        # Generate the BIP39 seed from this mnemonic phrase
        seed = mnemonic_to_seed(mnemonic_phrase, passphrase, custom_wordlist)
    else:
        # Fallback for non-custom wordlists (standard method)
        if language:
            mnemonic_instance = Mnemonic(language)
            if mnemonic_instance.check(mnemonic_or_seed):
                entropy = mnemonic_instance.to_entropy(mnemonic_or_seed)
            else:
                raise ValueError("Provided seed is not a valid mnemonic for the given language.")
            seed = Bip39SeedGenerator(mnemonic_or_seed).Generate(passphrase)
        else:
            # Custom seed without a specific language or wordlist
            entropy = hashlib.sha512(mnemonic_or_seed.encode('utf-8')).digest()[:16]  # Use 128 bits for entropy
            seed = generate_seed_from_entropy(entropy, passphrase)
        word_indexes = None

    # print(f"{Style.ITALIC}Custom seed/mnemonic used{Style.RESET}: {Style.BOLD}{mnemonic_or_seed}{Style.RESET}")
    # print(f"{Style.ITALIC}Generated entropy from custom seed/mnemonic{Style.RESET}: {entropy.hex()}")
    # if word_indexes:
    #     print(f"{Style.ITALIC}Word indexes used for entropy{Style.RESET}: {word_indexes}")
    return seed, entropy, word_indexes


def private_key_to_wif(private_key_hex):
    private_key = binascii.unhexlify(private_key_hex)
    extended_key = b'\x80' + private_key + b'\x01'  # Append 0x01 for compressed keys
    first_sha256 = hashlib.sha256(extended_key).digest()
    second_sha256 = hashlib.sha256(first_sha256).digest()
    checksum = second_sha256[:4]
    wif = base58.b58encode(extended_key + checksum)
    return wif.decode('utf-8')

def hash160(data):
    sha = hashlib.sha256(data).digest()
    ripemd = hashlib.new('ripemd160', sha).digest()
    return ripemd

def bech32_address(hrp, witver, witprog):
    witprog = [x for x in witprog]
    return bech32.encode(hrp, witver, witprog)

def generate_addresses(bip32, path_suffix):
    addresses = {}
    derivation_paths = {
        "P2PKH": f"m/44'/0'/0'{path_suffix}",
        "P2SH": f"m/49'/0'/0'{path_suffix}",
        "P2WPKH": f"m/84'/0'/0'{path_suffix}",
        "P2TR": f"m/86'/0'/0'{path_suffix}"
    }

    for addr_type, derivation_path in derivation_paths.items():
        derived_key = bip32.DerivePath(derivation_path)
        private_key = derived_key.PrivateKey().Raw().ToHex()
        
        # Generate the public key using coincurve
        private_key_obj = PrivateKey(binascii.unhexlify(private_key))
        pub_key = private_key_obj.public_key.format(compressed=True).hex()

        if addr_type == "P2PKH":
            bip44_ctx = Bip44.FromPrivateKey(binascii.unhexlify(private_key), Bip44Coins.BITCOIN)
            address = bip44_ctx.PublicKey().ToAddress()
        elif addr_type == "P2SH":
            bip49_ctx = Bip49.FromPrivateKey(binascii.unhexlify(private_key), Bip49Coins.BITCOIN)
            address = bip49_ctx.PublicKey().ToAddress()
        elif addr_type == "P2WPKH":
            bip84_ctx = Bip84.FromPrivateKey(binascii.unhexlify(private_key), Bip84Coins.BITCOIN)
            address = bip84_ctx.PublicKey().ToAddress()
        elif addr_type == "P2TR":
            bip86_ctx = Bip86.FromPrivateKey(binascii.unhexlify(private_key), Bip86Coins.BITCOIN)
            address = bip86_ctx.PublicKey().ToAddress()

        addresses[addr_type] = {
            "derivation_path": derivation_path,
            "address": address,
            "private_key": private_key,
            "wif": private_key_to_wif(private_key),
            "public_key": pub_key
        }

    return addresses

# Generate Nostr keys from a seed
def generate_nostr_keys_from_mnemonic(mnemonic_or_seed, passphrase="", is_custom_mnemonic=False, custom_wordlist=None):
    if is_custom_mnemonic and custom_wordlist:
        # Handle custom mnemonic with custom wordlist
        seed = mnemonic_to_seed(mnemonic_or_seed, passphrase, custom_wordlist)
    elif not is_custom_mnemonic:
        # For standard BIP39 mnemonics without a custom wordlist
        seed = Bip39SeedGenerator(mnemonic_or_seed).Generate(passphrase)
    else:
        # If a custom wordlist is provided without the custom mnemonic flag, it's a misuse, so raise an error
        raise ValueError("Custom wordlist provided without setting CUSTOM_WORDLIST=True. Software does't allow random mnemonics without wordlists")

    # Derive the private key using the path m/44'/1237'/0'/0/0
    bip32_master_key = Bip32Slip10Secp256k1.FromSeed(seed)
    bip32_nostr_key = bip32_master_key.DerivePath("m/44'/1237'/0'/0/0")

    # Extract the private key in raw bytes (32 bytes)
    nostr_private_key = bip32_nostr_key.PrivateKey().Raw().ToBytes()

    # Generate the corresponding public key using ecdsa and SECP256k1
    signing_key = SigningKey.from_string(nostr_private_key, curve=SECP256k1)
    verifying_key = signing_key.verifying_key
    nostr_public_key = verifying_key.to_string("compressed")[1:]  # Get the 32-byte uncompressed form

    # Convert keys to Bech32 encoding (npub for public key and nsec for private key)
    public_key_converted_bits = convertbits(nostr_public_key, 8, 5)
    private_key_converted_bits = convertbits(nostr_private_key, 8, 5)

    npub = bech32_encode("npub", public_key_converted_bits)
    nsec = bech32_encode("nsec", private_key_converted_bits)

    return nostr_private_key.hex(), nostr_public_key.hex(), nsec, npub



def display_wallet_info(mnemonic_phrase, seed, bip32, entropy, path_suffix, wordlist=None, language=None, password="", nostr_keys=None, custom_mnemonic=False, wordlist_filename=None, word_indexes=None):
    
    # Initialize BIP39Colors with the wordlist (custom or standard)
    BIP39Colors.words = wordlist if wordlist else Mnemonic(language).wordlist
    
    seed_hex = seed.hex()

    addresses = generate_addresses(bip32, path_suffix)
    
    print(f"\n... . -.-. .-. . - / -.. .- - .- / - --- / -.-- --- ..- .-. / - .-. ..- . / ..-. .-. . . -.. --- --\n")
    print(f"\n{Style.BOLD}{Fore.BLUE}BIP39_Exotica data created ->{Fore.RESET} {timestamp}{Style.RESET}\n")
    print(f"{Style.ITALIC}{Fore.GREEN}You can get a decent explanation of what this project is, on my Github -> https://github.com/StellarStoic/BIP39_Exotica{Fore.RESET}{Style.RESET}")

    
    # Generate colors from the mnemonic phrase
    if BIP39Colors.fromSeed(mnemonic_phrase):
        colors = BIP39Colors.colors  # Directly use the colors from seedToColors
    
    # Extract Nostr keys if provided
    nostr_private_key_hex, nostr_public_key_hex, nsec, npub = nostr_keys if nostr_keys else (None, None, None, None)

    # Calculate raw binary and checksum
    entropy_bits = bin(int(entropy.hex(), 16))[2:].zfill(len(entropy) * 8)
    checksum_bits = bin(int(hashlib.sha256(entropy).hexdigest(), 16))[2:].zfill(256)[:len(entropy) * 8 // 32]
    full_bits = entropy_bits + checksum_bits
    
    # Display mnemonic phrase
    if mnemonic_phrase:
        print(f"\n{Style.ITALIC}Mnemonic Phrase{Style.RESET}: {Style.BOLD}{mnemonic_phrase}{Style.RESET}\n")
        print(f"{Style.ITALIC}Colors (Hex){Style.RESET}: {' '.join(colors)}\n")
        
        # Display the password or a warning if none is set
        if password:
            print(f"{Style.ITALIC}Password{Style.RESET}: {Style.BOLD}{Fore.GREEN}{password}{Fore.RESET}{Style.RESET}")
        else:
            print(f"{Fore.RED}DANGER! No password has been set.{Fore.RESET}")

        # Display word indexes if available
        if custom_mnemonic and word_indexes:
            print(f"\n{Style.ITALIC}Word Indexes Used (Using Custom Wordlist: {wordlist_filename}){Style.RESET}: {Fore.MAGENTA}{word_indexes}{Fore.RESET}\n")
            print(f"{Style.ITALIC}{Fore.YELLOW}Remember that when going trough the list of words, word index starts with 0 not 1. We always count first word with 0. That's how computers count numbers. Just a note to avoid any further confusion.{Style.RESET}{Fore.RESET}\n\n")
            
            # Calculate and display the hash of the wordlist file if it's a custom wordlist
            if wordlist_filename:  # Ensure the wordlist filename is not None
                wordlist_file_hash = calculate_file_hash(wordlist_filename)
                print(f"{Style.ITALIC}Hash of the wordlist file{Style.RESET}: {Fore.YELLOW}{wordlist_file_hash}{Fore.RESET}")
        
        elif custom_mnemonic:
            print(f"\n{Style.ITALIC}!!! Word indexes not available, custom mnemonic seed was used but not processed properly !!!{Style.RESET}")
        else:
            if wordlist:
                word_indexes = [wordlist.index(word) for word in mnemonic_phrase.split()]
                print(f"\n{Style.ITALIC}Word Indexes (Using Custom Wordlist: {wordlist_filename}){Style.RESET}: {Fore.MAGENTA}{word_indexes}{Fore.RESET}\n")
                print(f"{Style.ITALIC}{Fore.YELLOW}Remember that when going trough the list of words, word index starts with 0 not 1. We always count first word with 0. That's how computers count numbers. Just a note to avoid any further confusion.{Style.RESET}{Fore.RESET}\n\n")

                # Calculate and display the hash of the wordlist file if it's a custom wordlist
                if wordlist_filename:  # Ensure the wordlist filename is not None
                    wordlist_file_hash = calculate_file_hash(wordlist_filename)
                    print(f"{Style.ITALIC}Hash of the wordlist file{Style.RESET}: {Fore.YELLOW}{wordlist_file_hash}{Fore.RESET}")
            else:
                # For standard BIP39 wordlist
                mnemonic_instance = Mnemonic(language)
                word_indexes = [mnemonic_instance.wordlist.index(word) for word in mnemonic_phrase.split()]
                print(f"\n{Style.ITALIC}Word Indexes (Standard Wordlist: {language}){Style.RESET}: {Fore.MAGENTA}{word_indexes}{Fore.RESET}\n")
                print(f"{Style.ITALIC}{Fore.YELLOW}Remember that when going trough the list of words, word index starts with 0 not 1. We always count first word with 0. That's how computers count numbers. Just a note to avoid any further confusion.{Style.RESET}{Fore.RESET}\n\n")
            
        # Display word details using the raw binary
        words = mnemonic_phrase.split()
        print(f"\n{Style.ITALIC}{Fore.PINK}Word Details (Index, Binary, Word):{Fore.RESET}{Style.RESET}")
        for i, (word, binary) in enumerate(zip(words, [entropy_bits[j:j+11] for j in range(0, len(entropy_bits), 11)]), start=1):
            if i == len(words):  # Last word (potential checksum)
                # Properly concatenate the binary and checksum bits
                main_binary = binary + checksum_bits  # Append the checksum bits to the last binary section
                main_binary_full = main_binary.zfill(11)  # Ensure it's a full 11-bit binary
                main_binary = main_binary_full[:-len(checksum_bits)]
                checksum_part = main_binary_full[-len(checksum_bits):]
                print(f"{i}. {main_binary} [{Fore.RED}{checksum_part}{Fore.RESET}] = {word_indexes[i-1]} = {Style.BOLD}{Fore.RED}{word}{Fore.RESET}{Style.RESET} {Style.ITALIC}<-(This word is a checksum){Style.RESET}")
            else:
                print(f"{i}. {binary} = {word_indexes[i-1]} = {Style.BOLD}{word}{Style.RESET}")                    
    # Display seed
    print(f"\n{Style.ITALIC}BIP39 Seed{Style.RESET}: {Fore.MAGENTA}{seed_hex}{Fore.RESET}")

    # Display entropy and checksum details
    print(f"\n{Style.ITALIC}Entropy{Style.RESET}: {Fore.CYAN}{entropy.hex()}{Fore.RESET}")
    print(f"{Style.ITALIC}Raw Binary{Style.RESET}: {' '.join(entropy_bits[i:i+11] for i in range(0, len(entropy_bits), 11))}")
    print(f"{Style.ITALIC}Binary Checksum{Style.RESET}: {checksum_bits}")
    
    # Define titles and colors for each address type
    titles = {
        "P2PKH": ("Legacy Wallet", Fore.ORANGE),
        "P2SH": ("Nested Segwit Wallet", Fore.CYAN),
        "P2WPKH": ("Native Segwit Wallet", Fore.LIGHTYELLOW_EX),
        "P2TR": ("Taproot Wallet", Fore.GREEN)
    }

    # Print wallet information with titles
    for addr_type, info in addresses.items():
        title, color = titles.get(addr_type, ("Unknown Wallet", Fore.RESET))
        print(f"\n{color}{Style.BOLD}{title}{Style.RESET}")
        print(f"\n{info['derivation_path']} {addr_type} Address: {color}{info['address']}{Fore.RESET}")
        print(f"{info['derivation_path']} {addr_type} Private Key: {color}{info['private_key']}{Fore.RESET}")
        print(f"{info['derivation_path']} {addr_type} Public Key: {color}{info['public_key']}{Fore.RESET}")
        print(f"{info['derivation_path']} {addr_type} WIF: {color}{info['wif']}{Fore.RESET}")
        
        # Generate QR codes for Public Key and WIF Private Key with the specified color for console
        generate_ascii_qr_code(info['address'], "ADDRESS (For importing watch only wallet)", color, include_color=True)
        generate_ascii_qr_code(info['wif'], "WIF PRIVATE KEY (anyone scanning this key can move your funds)", color, include_color=True)

    # Display Nostr keys if available
    if nostr_private_key_hex and nostr_public_key_hex and nsec and npub:
        
        print(f"\n{Fore.MAGENTA}{Style.BOLD}Nostr Keys{Style.RESET}{Fore.RESET}")
        print(f"\n{Style.ITALIC}Nostr Private Key (Hex){Style.RESET}: {Fore.MAGENTA}{nostr_private_key_hex}{Fore.RESET}")
        print(f"{Style.ITALIC}Nostr Public Key (Hex){Style.RESET}: {Fore.MAGENTA}{nostr_public_key_hex}{Fore.RESET}")
        print(f"{Style.ITALIC}Nostr Private Key (nsec){Style.RESET}: {Fore.MAGENTA}{nsec}{Fore.RESET}")
        print(f"{Style.ITALIC}Nostr Public Key (npub){Style.RESET}: {Fore.MAGENTA}{npub}{Fore.RESET}\n")
        
        # Define Magenta color for Nostr QR codes
        nostr_qr_color = Fore.MAGENTA
        
        # Generate QR codes for Nostr Public Key and Private Key with Magenta color for console
        generate_ascii_qr_code(npub, "npub (For importing watch only nostr id)", nostr_qr_color, include_color=True)
        generate_ascii_qr_code(nsec, "nsec NOSTR PRIVATE KEY (anyone scanning this key can sign notes on your behalf)", nostr_qr_color, include_color=True)
        
        print(f"{Style.BOLD}WTF is {Style.RESET}{Fore.MAGENTA}{Style.ITALIC}Nostr{Style.RESET}{Fore.RESET}?")
        print(f"\n{Fore.MAGENTA}{Style.ITALIC}Nostr is a open protocol. anyone can build on top of it{Style.RESET}{Fore.RESET}")
        print(f"\n{Fore.MAGENTA}{Style.ITALIC}because is open and permissionless{Style.RESET}{Fore.RESET}")
        print(f"\n{Fore.MAGENTA}{Style.ITALIC}Nostr is decentralized and censorship resistant{Style.RESET}{Fore.RESET}")
        print(f"\n{Fore.MAGENTA}{Style.ITALIC}Nostr gives you a portable digital social identity that you control{Style.RESET}{Fore.RESET}")
        print(f"\n{Fore.YELLOW}{Style.ITALIC}Find me on Nosr - one@satoshi.si{Style.RESET}{Fore.RESET}")


def generate_txt(mnemonic_phrase, seed, bip32, entropy, path_suffix, wordlist=None, language=None, password="", nostr_keys=None, custom_mnemonic=False, wordlist_filename=None, word_indexes=None):
    filename = f"exotic_wallet__{timestamp}.txt"

    # Calculate raw binary and checksum
    entropy_bits = bin(int(entropy.hex(), 16))[2:].zfill(len(entropy) * 8)
    checksum_bits = bin(int(hashlib.sha256(entropy).hexdigest(), 16))[2:].zfill(256)[:len(entropy) * 8 // 32]
    
    max_line_width = 80  # Set the maximum width of each line to fit within A4 width, approximately 80 characters

    with open(filename, 'w', encoding='utf-8') as file:
        file.write("₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ ₿ \n\n")
        file.write(f"\nBIP39_Exotica data created -> {timestamp}\n\n")

        file.write("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
        file.write("Treat this information as highly classified for yours eyes only!\n")
        file.write("If you are planning to use some of these keys, please store them somewhere super safe like in your password manager for example\n")
        file.write("The creator of the software this keys were created with, doesn't take any responsibility if someone lose the funds!\n")
        file.write("You can get a decent explanation of what this software does in the BIP39_Exotica Github repository (https://github.com/StellarStoic/BIP39_Exotica)\n")
        file.write("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n")
        # Display the mnemonic phrase
        if mnemonic_phrase:
            file.write(".............................................................................................................................................................................................\n")
            file.write(f"\nMnemonic Phrase: {mnemonic_phrase}\n")
            file.write("\n.............................................................................................................................................................................................\n\n")
            
            # Generate colors from the mnemonic phrase
            if BIP39Colors.fromSeed(mnemonic_phrase):
                colors = BIP39Colors.colors  # Directly use the colors from seedToColors
                # No need to adjust the colors here
                # print(f"Colors (Hex): {', '.join(colors)}")
                file.write("# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # \n\n")
                file.write(f"BIP39Colors: {' '.join(colors)}\n\n")
                
                file.write("These sets of colors can restore your mnemonic phrase no matter how colors are sorted.\n")
                file.write("To retrieve the wallet with these set of colors, you need to know which word list was used. (A filename of the wordlist and it's hash should be written in word index in this txt file)\n")
                file.write("If you used standard BIP39 wordlist like English, Italian etc., you can use standard wordlist included in WRDL/standard as a custom wordlist.\n\n")
                file.write("# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # \n\n")
            if password:
                file.write("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n")
                file.write(f"Password: {password}\n")
                file.write("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n\n")
            else:
                file.write("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n")
                file.write("This wallet is not password-protected.\n")
                file.write("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n\n")
            
            # Ensure word_indexes are generated if not already provided
            if word_indexes is None and wordlist:
                word_indexes = [wordlist.index(word) for word in mnemonic_phrase.split()]

            file.write("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n\n")
            # Display Word Indexes if applicable
            if custom_mnemonic and word_indexes:
                file.write(f"Word Indexes: (Using Custom Wordlist: {wordlist_filename} was used to generate this mnemonic phrase):\n{word_indexes}\n")
                file.write(f"Remember that when going trough the list of words, word index starts with 0 not 1. We always count first word with 0. That's how computers count numbers. Just a note to avoid any further confusion.\n")

                
                # Calculate the hash of the wordlist file if it's a custom wordlist
                if wordlist_filename:  # Ensure the wordlist filename is not None
                    wordlist_file_hash = calculate_file_hash(wordlist_filename)
                    file.write(f"\nHash of the wordlist file: {wordlist_file_hash}\n\n")
                
            elif custom_mnemonic:
                file.write("Word index not available because custom mnemonic seed was used.\n")

                # Calculate the hash of the wordlist file
                file.write(f"Hash of the wordlist file used: {wordlist_file_hash}\n\n")
                
            elif wordlist:
                word_indexes = [wordlist.index(word) for word in mnemonic_phrase.split()]
                file.write(f"Word Indexes (Using Custom Wordlist: {wordlist_filename} was used to generate this mnemonic phrase):\n{word_indexes}\n")
                file.write(f"Remember that when going trough the list of words, word index starts with 0 not 1. We always count first word with 0. That's how computers count numbers. Just a note to avoid any further confusion.\n\n")
                
                # Calculate the hash of the wordlist file if it's a custom wordlist
                if wordlist_filename:  # Ensure the wordlist filename is not None
                    wordlist_file_hash = calculate_file_hash(wordlist_filename)
                    file.write(f"Hash of the wordlist file: {wordlist_file_hash}\n\n")

            else:
                try:
                    word_indexes = [Mnemonic(language).wordlist.index(word) for word in mnemonic_phrase.split()]
                    file.write(f"Word Indexes (Standard Wordlist: {language} was used to generate this mnemonic phrase):\n{word_indexes}\n\n")
                except ValueError:
                    file.write("Words are not part of the standard BIP39 wordlist - Skipping Word Index Calculation\n\n")
                    
            # Display Word Indexes and corresponding binary representation
            file.write("Word Details (Index, Binary, Word):\n")
            words = mnemonic_phrase.split()
            for i, (word, binary) in enumerate(zip(words, [entropy_bits[j:j+11] for j in range(0, len(entropy_bits), 11)]), start=1):
                if i == len(words):  # Last word (potential checksum)
                    main_binary = binary + checksum_bits  # Append the checksum bits to the last binary section
                    main_binary_full = main_binary.zfill(11)  # Ensure it's a full 11-bit binary
                    main_binary = main_binary_full[:-len(checksum_bits)]
                    checksum_part = main_binary_full[-len(checksum_bits):]
                    file.write(f"{i}. {main_binary} [{checksum_part}] = {word_indexes[i-1]} = {word}\n")
                else:
                    file.write(f"{i}. {binary} = {word_indexes[i-1]} = {word}\n")
                    
            file.write("\n")
        file.write("--------------------------------------------------------------------------------------------------------------------------------------------\n")
        # Display the Seed in Hex format
        file.write(f"BIP39 Seed: {seed.hex()}\n")
        file.write("-------------------------------------------------------------------------------------------------------------------------------------------\n\n")
        # Additional Information
        file.write("---------------------------------------------------------------------------\n\n")
        file.write(f"Entropy: {entropy.hex()}\n\n")
        file.write("---------------------------------------------------------------------------\n\n")

        entropy_bits = bin(int(entropy.hex(), 16))[2:].zfill(len(entropy) * 8)
        checksum_bits = bin(int(hashlib.sha256(entropy).hexdigest(), 16))[2:].zfill(256)[:len(entropy) * 8 // 32]
        
        file.write("---------------------------------------------------------------------------------------------------------------------------------------------------------\n\n")
        file.write(f"Raw Binary: {' '.join(entropy_bits[i:i+11] for i in range(0, len(entropy_bits), 11))}\n")
        file.write(f"Binary Checksum: {checksum_bits}\n\n")
        file.write("---------------------------------------------------------------------------------------------------------------------------------------------------------\n\n")

        # Define titles and colors for each address type
        titles = {
            "P2PKH": "Legacy Wallet",
            "P2SH": "Nested Segwit Wallet",
            "P2WPKH": "Native Segwit Wallet",
            "P2TR": "Taproot Wallet"
        }

        # Addresses and Keys
        addresses = generate_addresses(bip32, path_suffix)
        for addr_type, info in addresses.items():
            title = titles.get(addr_type, "Unknown Wallet")
            file.write(f"{title}\n")
            file.write(f"  {info['derivation_path']} {addr_type} Address: {info['address']}\n")
            file.write(f"  {info['derivation_path']} {addr_type} Private Key: {info['private_key']}\n")
            file.write(f"  {info['derivation_path']} {addr_type} Public Key: {info['public_key']}\n")
            file.write(f"  {info['derivation_path']} {addr_type} WIF: {info['wif']}\n\n")
            
            # Generate QR codes for Public Key and WIF Private Key without color for TXT
            address_qr = generate_ascii_qr_code(info['address'], (f" {addr_type} ADDRESS (For importing watch only wallet)\n{info['address']}\n{info['derivation_path']}"), '', include_color=False)
            wif_qr = generate_ascii_qr_code(info['wif'], (f" {addr_type} WIF PRIVATE KEY (anyone scanning this key can move your funds)\n{info['wif']}\n{info['derivation_path']}"), '', include_color=False)

            # Write QR codes to the file
            file.write(address_qr)
            file.write("\n")
            file.write(wif_qr)
            file.write("\n")            
            
        # Add Nostr keys to the TXT
        if nostr_keys:
            nostr_private_key_hex, nostr_public_key_hex, nsec, npub = nostr_keys
            file.write("...........................................................................................................\n\n")
            file.write("Nostr Keys\n")
            file.write(f"  Nostr Private Key (Hex): {nostr_private_key_hex}\n")
            file.write(f"  Nostr Public Key (Hex): {nostr_public_key_hex}\n")
            file.write(f"  Nostr Private Key (nsec): {nsec}\n")
            file.write(f"  Nostr Public Key (npub): {npub}\n\n")
            
            # Generate QR codes for Public Key and WIF Private Key without color for TXT
            nostr_npub_qr = generate_ascii_qr_code(npub, (f" {npub }npub (For importing watch only nostr id)"), '', include_color=False)
            nostr_nsec_qr = generate_ascii_qr_code(nsec, (f" {nsec} nsec NOSTR PRIVATE KEY (anyone scanning this key can sign notes on your behalf)"), '', include_color=False)

            # Write QR codes to the file
            file.write(nostr_npub_qr)
            file.write("\n")
            file.write(nostr_nsec_qr)
            file.write("\n")       

            
        file.write("WTF is Nostr?\n")
        file.write("Nostr is a open protocol.\n")
        file.write("Because it is open and permissionless, anyone can build on top of it.\n")
        file.write("Nostr is decentralized and censorship resistant.\n")
        file.write("Nostr gives you a portable digital social identity that you control.\n")
        file.write("If you need help with Nostr,\n")
        file.write("just find me by NIP05 one@satoshi.si or my npub npub1qqqqqqz7nhdqz3uuwmzlflxt46lyu7zkuqhcapddhgz66c4ddynswreecw \n")
        file.write(" I'd be happy to help.\n")


    return filename

def main():
    global CUSTOM_MNEMONIC

    # Default language for Mnemonic library
    language = 'english'  
    
    # Display the script configuration options
    print(f"{Fore.BLUE}{Style.BOLD}\n\nThe script is configured with the following options:{Style.RESET}{Fore.RESET}")
    
    print(f"🗝 {Fore.GREEN}User-defined Password for Mnemonic{Fore.RESET} = {'SET 🔒' if PASSWORD else 'NOT SET 🔓'} ")
    print(f"⛐ {Fore.GREEN}Derivation Path Suffix{Fore.RESET} = {DERIVATION_PATH_SUFFIX}")

    # Custom Wordlist Option
    print(f"🗈 {Fore.GREEN}Custom Wordlist{Fore.RESET} = {'ON' if CUSTOM_WORDLIST else 'OFF'}")
    if CUSTOM_WORDLIST:
        print(f"  - Wordlist File Path: {wordlist_path}")
        
        # Calculate the hash of the custom wordlist file
        wordlist_file_hash = calculate_file_hash(wordlist_path)
        print(f"  - Hash of the wordlist file: {wordlist_file_hash}")
    
    # Custom Seed Option
    print(f"⟿ {Fore.GREEN}Custom Mnemonic{Fore.RESET} = {'ON' if CUSTOM_MNEMONIC else 'OFF'}")
    if CUSTOM_MNEMONIC:
        print(f"  - Custom Seed: {custom_mnemonic_text}")
    
    # Create Mnemonic Phrase by Colors Option
    print(f"🖌 {Fore.GREEN}Create Mnemonic Phrase by COLORS{Fore.RESET} = {'ON' if GENERATE_BY_COLOR else 'OFF'}")
    if GENERATE_BY_COLOR:
        print(f"🖌  - Defined Colors: {create_wallet_from_colors}\n")
        
        # Red warning if GENERATE_BY_COLOR is True but CUSTOM_MNEMONIC is False
        if not CUSTOM_MNEMONIC:
            # Print warning message
            print(f"{Fore.RED}{Style.BOLD}WARNING: To recover or generate a wallet by color from a known wordlist, CUSTOM_MNEMONIC should be set to True.{Style.RESET}{Fore.RESET}")
            
            # Prompt the user for action
            while True:
                user_input = input(f"{Fore.YELLOW}Do you want to automatically set CUSTOM_MNEMONIC to True? (y/n): {Fore.RESET}").lower()
                if user_input == 'y':
                    CUSTOM_MNEMONIC = True
                    print(f"{Fore.GREEN}CUSTOM_MNEMONIC has been set to True.{Fore.RESET}")
                    break
                elif user_input == 'n':
                    print(f"{Fore.RED}Exiting script. Please set CUSTOM_MNEMONIC = True manually and restart the script.{Fore.RESET}")
                    return
                else:
                    print(f"{Fore.RED}Invalid input. Please enter 'y' (yes) or 'n' (no).{Fore.RESET}")
            
    if CUSTOM_WORDLIST:
        with open(wordlist_path, 'r', encoding='utf-8') as file:
            wordlist = [line.strip() for line in file.readlines()]
            if len(wordlist) != 2048:
                raise ValueError("Wordlist must contain exactly 2048 words.")
        language = None  # Set language to None if using custom wordlist
        wordlist_filename = wordlist_path  # Use the filename for custom wordlist
        
    else:
        wordlist = None
        wordlist_filename = None
        
    # Initialize BIP39Colors with the selected wordlist
    BIP39Colors.words = wordlist if wordlist else Mnemonic(language).wordlist
    
    # Initialize BIP39Colors with the selected wordlist
    BIP39Colors.words = wordlist if wordlist else Mnemonic(language).wordlist
    
    if GENERATE_BY_COLOR and create_wallet_from_colors:
        # Disallow recovery by color if not using a custom wordlist
        if not CUSTOM_WORDLIST:
            print(f"\n{Fore.RED}Recovery by color is only allowed when using a wordlist locally. Set CUSTOM_WORDLIST = True{Fore.RESET}")
            print(f"\n{Fore.RED}If you used any standard languages, just choose their wordlist as a custom wordlist.{Fore.RESET}")
            print(f"{Fore.RED}Colors can be in any order. No matter what the order of 8 or 16 colors are, it will always retreive the same wallet{Fore.RESET}")
            return
        
        # Recover wallet from provided hex colors
        if BIP39Colors.toSeed(create_wallet_from_colors):
            mnemonic_phrase = BIP39Colors.seed
            # print(f"{Style.ITALIC}Recovered Mnemonic Phrase{Style.RESET}: {Style.BOLD}{mnemonic_phrase}{Style.RESET}")

            # Continue with the recovered mnemonic phrase
            seed, entropy, word_indexes = generate_seed_and_entropy(mnemonic_phrase, custom_wordlist=wordlist, passphrase=PASSWORD)
            bip32 = Bip32Slip10Secp256k1.FromSeed(seed)
            nostr_keys = generate_nostr_keys_from_mnemonic(mnemonic_phrase, PASSWORD, is_custom_mnemonic=CUSTOM_MNEMONIC, custom_wordlist=wordlist)
            
            display_wallet_info(mnemonic_phrase, seed, bip32, entropy, DERIVATION_PATH_SUFFIX, wordlist, language, PASSWORD, nostr_keys, custom_mnemonic=CUSTOM_MNEMONIC, wordlist_filename=wordlist_filename, word_indexes=word_indexes)

            # Ask user to print to TXT or exit
            while True:
                user_input = input(f"\nPress {Fore.RED}'x'{Fore.RESET} to exit, {Fore.BLUE}'p'{Fore.RESET} to print to TXT file: ").lower()
                if user_input == 'x':
                    print("Exiting script.")
                    return
                elif user_input == 'p':
                    filename = generate_txt(mnemonic_phrase, seed, bip32, entropy, DERIVATION_PATH_SUFFIX, wordlist, language, PASSWORD, nostr_keys, custom_mnemonic=CUSTOM_MNEMONIC, wordlist_filename=wordlist_filename)
                    print(f"Wallet information has been saved to {filename}.")
                    return
                else:
                    print(f"{Fore.RED}Invalid input. Please enter 'x' to exit or 'p' to print to TXT file.{Fore.RESET}")        
    if CUSTOM_MNEMONIC:
        try:
            # Process custom seed with the custom wordlist
            seed, entropy, word_indexes = generate_seed_and_entropy(custom_mnemonic_text, custom_wordlist=wordlist, passphrase=PASSWORD)
            
            bip32 = Bip32Slip10Secp256k1.FromSeed(seed)
            nostr_keys = generate_nostr_keys_from_mnemonic(custom_mnemonic_text, PASSWORD, is_custom_mnemonic=True, custom_wordlist=wordlist)
            display_wallet_info(custom_mnemonic_text, seed, bip32, entropy, DERIVATION_PATH_SUFFIX, wordlist, language, PASSWORD, nostr_keys, custom_mnemonic=True, wordlist_filename=wordlist_filename, word_indexes=word_indexes)

            # Generate colors from the mnemonic phrase
            if BIP39Colors.fromSeed(custom_mnemonic_text):
                colors = BIP39Colors.colors  # Directly use the colors from seedToColors
                # print(f"Colors (Hex): {', '.join(colors)}")
                
            # Ask user to generate a TXT file of the wallet information
            while True:
                user_input = input(f"\nPress {Fore.RED}'x'{Fore.RESET} to exit, {Fore.BLUE}'p'{Fore.RESET} to print to TXT file: ").lower()
                if user_input == 'x':
                    print("Exiting script.")
                    return
                elif user_input == 'p':
                    filename = generate_txt(custom_mnemonic_text, seed, bip32, entropy, DERIVATION_PATH_SUFFIX, wordlist, language, PASSWORD, nostr_keys, custom_mnemonic=CUSTOM_MNEMONIC, wordlist_filename=wordlist_filename)
                    print(f"Wallet information has been saved to {filename}.")
                    return
                else:
                    print(f"{Fore.RED}Invalid input. Please enter 'x' to exit or 'p' to print to TXT file.{Fore.RESET}")
        except ValueError as e:
            # Catch and print the error in red
            print(f"{Fore.RED}{e}{Fore.RESET}")
            return
    else:
        if not CUSTOM_WORDLIST:
            available_languages = ['english', 'spanish', 'chinese_simplified', 'chinese_traditional', 'french', 'italian', 'korean', 'czech', 'portuguese']
            print("\n\nSelect a language for the mnemonic phrase:\n")
            print(f"{Fore.YELLOW}I did not include Japanese wordlist. Sorry Japan 🤍{Fore.RESET}")
            for i, lang in enumerate(available_languages):
                print(f"{i + 1}. {lang}")
            selected_language_index = int(input("Enter the number corresponding to your language choice: ")) - 1
            language = available_languages[selected_language_index]

        while True:
            try:
                word_count = int(input("Enter the number of words for the mnemonic phrase (12, 24): "))
                if word_count not in [12, 24]:
                    raise ValueError("Invalid word count.")
                break  # Exit the loop if the input is valid
            except ValueError as e:
                print(f"{Fore.RED}{e} Please enter either 12 or 24.{Fore.RESET}")

        while True:
            random_entropy = generate_entropy_for_word_count(word_count)
            mnemonic_phrase = create_mnemonic_from_entropy(language, random_entropy, custom_wordlist=wordlist)
            
            if CUSTOM_WORDLIST:
                seed = mnemonic_to_seed(mnemonic_phrase, custom_wordlist=wordlist)
                nostr_keys = generate_nostr_keys_from_mnemonic(mnemonic_phrase, PASSWORD, is_custom_mnemonic=True, custom_wordlist=wordlist)
            else:
                seed = mnemonic_to_seed(mnemonic_phrase)
                nostr_keys = generate_nostr_keys_from_mnemonic(mnemonic_phrase, PASSWORD)

            bip32 = Bip32Slip10Secp256k1.FromSeed(seed)
            addresses = generate_addresses(bip32, path_suffix=DERIVATION_PATH_SUFFIX)
            
            # Generate colors from the mnemonic phrase
            if BIP39Colors.fromSeed(mnemonic_phrase):
                colors = BIP39Colors.colors  # Directly use the colors from seedToColors
                # print(f"{Style.ITALIC}Colors (Hex){Style.RESET}: {', '.join(colors)}")

            display_wallet_info(mnemonic_phrase, seed, bip32, random_entropy, DERIVATION_PATH_SUFFIX, wordlist, language, PASSWORD, nostr_keys, custom_mnemonic=CUSTOM_MNEMONIC, wordlist_filename=wordlist_filename)

            while True:
                user_input = input(f"\nPress {Fore.RED}'x'{Fore.RESET} to exit, {Fore.GREEN}'r'{Fore.RESET} to create another random valid mnemonic, or {Fore.BLUE}'p'{Fore.RESET} to print to TXT file: ").lower()
                if user_input == 'x':
                    print("Exiting script.")
                    return
                elif user_input == 'r':
                    break  # This will break the inner loop and continue with the outer loop to generate a new wallet
                elif user_input == 'p':
                    filename = generate_txt(mnemonic_phrase, seed, bip32, random_entropy, DERIVATION_PATH_SUFFIX, wordlist, language, PASSWORD, nostr_keys, custom_mnemonic=CUSTOM_MNEMONIC, wordlist_filename=wordlist_filename)
                    print(f"Wallet information has been saved to {filename}.")
                    return
                else:
                    print(f"{Fore.RED}Invalid input. Please enter 'x' (EXIT), 'r' (REPEAT), or 'p' (PRINT).{Fore.RESET}")

if __name__ == '__main__':
    main()
