import mysql.connector
import secrets
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Database connection
mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="sake"
)
mycursor = mydb.cursor()


def prepare_key(secret):
    if isinstance(secret, int):
        secret_bytes = secret.to_bytes((secret.bit_length() + 7) // 8, 'big')
    else:
        secret_bytes = secret
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(secret_bytes)
    return digest.finalize()[:16]

# AES-GCM decryption
def decrypt_data(key,d_enc_iv, d_enc_records, d_enc_tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(d_enc_iv, d_enc_tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(d_enc_records) + decryptor.finalize()

# AES-GCM encryption
def encrypt_data(key,d_enc_iv, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.GCM(d_enc_iv), backend=default_backend())
    encryptor = cipher.encryptor()
    d_enc_records = encryptor.update(plaintext) + encryptor.finalize()
    return d_enc_records, encryptor.tag

# Fetch encrypted records from the table
mycursor.execute("SELECT id, d_enc_records, d_enc_iv, d_enc_tag FROM sakeprotocol")  
records = mycursor.fetchall()


# Load constants from json file
with open('server_keys.json', 'r') as file:
    server_keys = json.load(file)


# Define old and new secrets
old_kappa = server_keys['kappa']
new_kappa = secrets.randbelow(2**128)

old_key = prepare_key(old_kappa)
new_key = prepare_key(new_kappa)

# Batch operation: decrypt with old_key, re-encrypt with new_key (using samed_enc_iv/tag)
for row in records:
    drone_id, d_enc_records,d_enc_iv, d_enc_tag = row
    iv_bytes = bytes.fromhex(d_enc_iv)
    encrypted_data_bytes = bytes.fromhex(d_enc_records)
    tag_bytes = bytes.fromhex(d_enc_tag)	
	
    try:
        # Decrypt with old key
        plaintext = decrypt_data(old_key,iv_bytes, encrypted_data_bytes, tag_bytes)

        # Re-encrypt with new key (keeping the samed_enc_iv)
        new_d_enc_records, new_tag = encrypt_data(new_key,iv_bytes, plaintext)
        new_d_enc_records_hex = new_d_enc_records.hex()
        new_tag_hex = new_tag.hex()
        # Update database with new d_enc_records and d_enc_tag
        sql = "UPDATE sakeprotocol SET d_enc_records = %s, d_enc_tag = %s WHERE id = %s"
        val = (new_d_enc_records_hex, new_tag_hex, drone_id)
        mycursor.execute(sql, val)
        mydb.commit()
        print(f"[+] Updated user {drone_id}")
				
		
    except Exception as e:
        print(f"[!] Error processing user {drone_id}: {str(e)}")

# Update kappa in server_keys.json
server_keys["kappa"] = new_kappa
		
# Convert the data to JSON
json_storage_data = json.dumps(server_keys, indent=2)

# Save the updated server_keys.json back to file
with open("server_keys.json", "w") as file:
    file.write(json_storage_data)
print(f"[+] kappa updated to: {new_kappa}")	

# Close connection
mycursor.close()
mydb.close()