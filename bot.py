#!/usr/bin/env python
import logging
import base64
import codecs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

# Enable logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# Funciones de codificación y cifrado
def aes_encrypt(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(data, 16))
    return cipher.iv + encrypted_data

def aes_decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    iv = encrypted_data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), 16)
    return decrypted_data

def encode_base64_rot13_aes(text: str, key: str) -> str:
    rot13_text = codecs.encode(text, 'rot_13')
    encrypted_data = aes_encrypt(rot13_text.encode(), key.encode())
    return base64.b64encode(encrypted_data).decode()

# Función de descifrado
def decode_base64_rot13_aes(encoded_text: str, key: str) -> str:
    encrypted_data = base64.b64decode(encoded_text)
    decrypted_data = aes_decrypt(encrypted_data, key.encode()).decode()
    return codecs.decode(decrypted_data, 'rot_13')


# Comando del bot para cifrar
async def cipher_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if len(context.args) < 2:
        await update.message.reply_text("Please provide a key and the text to be encrypted.")
        return

    key = context.args[0]
    text = ' '.join(context.args[1:])
    
    if len(key) != 16:
        await update.message.reply_text("The key must be 16 bytes long.")
        return

    encrypted_text = encode_base64_rot13_aes(text, key)
    await update.message.reply_text(f"{encrypted_text}")
        
# Comando del bot para descifrar
async def decipher_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if len(context.args) < 2:
        await update.message.reply_text("Please provide a key and the text to decrypt.")
        return

    key = context.args[0]
    encoded_text = ' '.join(context.args[1:])

    if len(key) != 16:
        await update.message.reply_text("The key must be 16 bytes long.")
        return

    decrypted_text = decode_base64_rot13_aes(encoded_text, key)
    await update.message.reply_text(f"{decrypted_text}")

        
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("Hi, can i help you? You can ask me whatever :)")

async def encode_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    original_text = ' '.join(context.args)
    encoded_text = encode_base64_rot13(original_text)
    await update.message.reply_text(f"{encoded_text}")

async def decode_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    encoded_text = ' '.join(context.args)
    decoded_text = decode_base64_rot13(encoded_text)
    await update.message.reply_text(f"{decoded_text}")
    
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    help_text = """
    Commands:
    /start - Starts the bot
    /help - Show this help
    /encode [text] - Encodes text using ROT13 and then Base64
    /decode [encoded text] - Decodes text from Base64 to ROT13
    /cipher [key] [text] - Encrypt text using ROT13, Base64 and AES CBC
    /decipher [key] [encoded text] - decode Base64, AES CBC text to ROT13
    /mastodon - provides an interesting url 
    /github - provides an interesting url 
     
    """
    await update.message.reply_text(help_text)



async def mastodon(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("https://mastodon.social/@codebreaker1337/with_replies") 

async def github(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("https://github.com/Codebreaker1337")

async def echo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("You said " + str(update.message.text))

def main() -> None:
    application = Application.builder().token("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX").build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("encode", encode_command))
    application.add_handler(CommandHandler("decode", decode_command))
    application.add_handler(CommandHandler("cipher", cipher_command))
    application.add_handler(CommandHandler("decipher", decipher_command))
    application.add_handler(CommandHandler("mastodon", mastodon))
    application.add_handler(CommandHandler("github", github))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, echo))

    application.run_polling()

if __name__ == "__main__":
    main()
