# Custom Bitcoin Wallet and Nostr Keys Generator BIP39_Exotica

## Overview

This script is designed to generate Bitcoin wallets using both standard BIP39 mnemonic phrases and a custom wordlist. A custom Slovenian wordlist was created for this project (more about wordlist creation for Slovenian language check this separate repository [Slovenian BIP39 wordlist](https://github.com/StellarStoic/Slovenian-BIP39-wordlist)). Firstly, the goal was to provide a way for Slovenian speakers who may not be comfortable with other languages to create secure Bitcoin wallets. But after I dig into the code I keep digging and that what's came out of it. 

**Important Note:** While the script allows you to create valid Bitcoin wallets, it also uses custom mnemonic wordlists that are **not** compatible with most wallets supported by the BIP39 standard. This means that mnemonics created using the custom wordlist cannot be restored using other Bitcoin wallet software like BlueWallet, Electrum, etc. with just these 12 or 24 words, unless this script is used. However, you can restore individual keys by copying text or scanning the QR code for public and private keys with your apps like [Electrum](https://electrum.org/)


## Features

- **Custom Wordlist:** Generate mnemonic phrases using a custom wordlist. Despite using a custom wordlist, the wallets generated by this script are cryptographically sound and produce valid Bitcoin private and public keys. Additionally, the script generates Nostr keys as a cherry on top.

- **Wordlist File Hash:** When using a custom wordlist, it's crucial to ensure you have the correct one. To help with this, a simple authenticity checker is included. The script provides the name of the wordlist used to generate the keys, and the hash serves as a quick way to verify if you are restoring keys from the correct wordlist.

- **Standard BIP39 Compatibility:** You can generate mnemonic phrases using standard BIP39 wordlists for languages such as English, Spanish, Italian, etc. However, implementing the Japanese language proved challenging, so it is currently not supported. If you're brave enough to dive into this spaghetti code, contributions are welcome and appreciated.
I included standard wordlist in the WRDL/standard folder if you want to use this tool completely offline. Just use them as custom wordlists.

- **Mnemonic by Colors:** A tool called [Bip39colors](https://github.com/enteropositivo/bip39colors/tree/main) is used to convert mnemonics into colors and vice versa. You can also play with colors on this website [enteropositivo...](https://enteropositivo.github.io/bip39colors/#biptocolors) 

- **Secure mnemonic with password:** The script allows you to set a password for the mnemonic phrase. If no password is set, a warning will be displayed in both the console and the generated TXT file.

- **derivation Path** You can manually set the derivation path of your addresses to hide funds far away from first keys.

- **TXT Export:** Save wallet information, including the mnemonic phrase, seed, private/public keys, and addresses with QR codes, to a TXT file for safekeeping and future restoration.

- **Nostr Key Generation:** Generate Nostr keys (private and public) along with a QR code for easy import into your clients.

- **QR Codes:** Each public and private key is also presented with a QR code using the tool [qr2eascii](https://github.com/Jojodicus/qr2eascii). Included file ```qr.py``` is main component for QR code creation. Scanning the codes while using a light theme may cause some issues. The best option is to use a dark theme with white codes, which you'll find in the generated TXT file with a dark background of course.


### Usage

1. Install requirements ```pip install -r requirements.txt```

2. Before running the script, set the flags, paths, and settings, which can be found right above after the imports. Several wordlists are included, along with tools that were generated for testing purposes. Standard wordlists are also included to allow for offline use of the tool if desired.

3. Once the settings are configured and requirements installed, simply run: ```python BIP39_Exotica.py```

4. After the wallet generates all the data in the console, you can save it to a TXT file by pressing the p key. If you plan to use these keys, it is essential to save the TXT file as securely as possible. I recommend using Bitwarden for secure storage.

**Disclaimer**
This script is provided "as-is" without any warranties or guarantees. I, the creator of the original code, do not take any responsibility, and the user assumes all risks associated with using the script, including the potential loss of funds. It is recommended to use standard BIP39 wordlists unless you fully understand the implications of using a custom wordlist with BIP39_Exotica.

### Visuals

Yes you can import these walets just by scanning them.

[![A sample video of a console output](https://image.nostr.build/f026be932bde43c4745c6b4bbb46be3d280f4c6741784097dda928ba6857dd20.png)](https://youtu.be/J_VgPKExNhk)