import mysql.connector
import json
import secrets
import hashlib
import sys
import base64
import socket
import struct
import cv2
import numpy as np
import socket
import webbrowser
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import time

mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="sake"
)
mycursor = mydb.cursor()

def generate_random_identity():
    return secrets.token_hex(16)

def generate_random_number():
    return secrets.randbelow(2**128)

def hash_data(*args):
    concatenated_data = ''.join(map(str, args)).encode()
    return hashlib.sha256(concatenated_data).hexdigest()

# Function to prepare the AES key from the secret
def prepare_key(secret):
    secret_bytes = secret.to_bytes((secret.bit_length() + 7) // 8, 'big')
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(secret_bytes)
    return digest.finalize()[:16]

# Function to encrypt data using AES-GCM
def encrypt_data(key, data):
    iv = os.urandom(12)  # AES-GCM standard 12-byte IV
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return iv, encrypted_data, encryptor.tag

# Function to decrypt data using AES-GCM
def decrypt_data(key, iv, encrypted_data, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

# Function to split the concatenated values
def split_values(data):
    decoded_data = data.decode()
    identity, omega_i_hex = decoded_data.split(':')
    omega_i = bytes.fromhex(omega_i_hex)
    return identity, omega_i

# Function to concatenate identity and omega_i
def concatenate_values(identity, omega_i):
    return f"{identity}:{omega_i.hex()}".encode()
	
#Calculating GPS coordinates and opening in determined location in browser
def open_google_maps(latitude, longitude):
    # Format the coordinates
    coordinates = ""

    if longitude < 0:
        if latitude > 0:
            coordinates = f"{latitude} N, {abs(longitude)} W"
        elif latitude < 0:
            coordinates = f"{abs(latitude)} S, {abs(longitude)} W"
        else:
            coordinates = f"{latitude} N, {abs(longitude)} W"
    elif longitude > 0:
        if latitude > 0:
            coordinates = f"{latitude} N, {longitude} E"
        elif latitude < 0:
            coordinates = f"{abs(latitude)} S, {longitude} E"
        else:
            coordinates = f"{latitude} N, {longitude} E"
    else:
        print("Failed in calculating precise location")        	

    # Generate the Google Maps URL
    google_maps_url = f"https://www.google.com/maps/place/{coordinates}"

    # Open the URL in the default web browser
    webbrowser.open(google_maps_url)

def extract_records(tidi_value):
# Check if TIDi matches d_otid_new
    sql_new = "SELECT d_otid_new, d_enc_records, d_enc_iv, d_enc_tag, id  FROM sakeprotocol WHERE d_otid_new = %s AND d_rev_status = 0"
    mycursor.execute(sql_new, (tidi_value,))
    records_new = mycursor.fetchall()

# Check if TIDi matches d_otid_old
    sql_old =  "SELECT d_otid_old, d_enc_records, d_enc_iv, d_enc_tag, id FROM sakeprotocol WHERE d_otid_old = %s AND d_rev_status = 0"
    mycursor.execute(sql_old, (tidi_value,))
    records_old = mycursor.fetchall()

    extracted_values = None

# Extract and compare the values from the tuples
    for record in records_new:
        if tidi_value == record[0]:
            extracted_values = record[1:]


    for record in records_old:
        if tidi_value == record[0]:
            extracted_values = record[1:]

    return extracted_values


def compute_Ethi(identity, tauj):
    concatenated_data = identity + str(tauj)
    mid_hash = hashlib.sha256(concatenated_data.encode()).hexdigest()
    return int(mid_hash, 16)  # Convert hexadecimal string to integer
	
def split_GPS_values(data):
    decoded_data = data.decode()
    longitude, latitude, timestamp = decoded_data.split(":")
    return float(longitude), float(latitude), int(timestamp)	
def main():
    cpu_start_time1 = 0
    cpu_end_time1 = 0
    cpu_start_time2 = 0
    cpu_end_time2 = 0
    total_data_size = 0
    e2e_start_time = 0
    e2e_end_time = 0
    end_to_end_delay = 0

# Set the hostname and port
    # host = socket.gethostname()
    host = ''
    port = 11111
    tauj = 214140748028615609671106732878009013565
	
# Create a socket object and bind it to the host and port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))  # Corrected the missing closing parenthesis
        s.listen()
        print(f"Listening on {host}:{port}")

# Accept a connection when a client connects
        conn, addr = s.accept()

        with conn:
            print(f"Connected to {addr}")

################################# Receive M1 ######################################			
# Receive data from the Drone
            data = conn.recv(1024)
            data = data.decode('utf-8')
            # print('Received:', data)

# Convert the received JSON string to a Python dictionary
            received_data = json.loads(data)

# Extract and print tidi, varphii, chii, and psii
            tidi = received_data.get('tidi')
            varphii = received_data.get('varphii')
            chii = received_data.get('chii')
            psii_rec = received_data.get('psii')
			
            print("Waiting for Login message from Drone")
            print("\n")
            print("Received login message <Tidi, Varphii, Chii, Ppsi> from Drone")
            print("Received Tidi: ", tidi)
            print("Received Varphii: ", varphii)
            print("Received Chii: ", chii)
            print("Received Pppsi: ", psii_rec)
            print("\n")
################################# End of M1 ######################################
            
################################# Database ######################################
            cpu_start_time1 = time.process_time()
            extracted_values = extract_records(tidi)
            if extracted_values:
                d_enc_records = extracted_values[0]  #Extracts d_enc_records from queried data
                d_enc_iv = extracted_values[1]  #Extracts d_enc_iv from queried data
                d_enc_tag = extracted_values[2]  #Extracts d_enc_tag from queried data
                row_primary_key = extracted_values[3]   #Extracts primay key from queried data

            aes_key = prepare_key(tauj)
# Convert hex values back to bytes
            iv_bytes = bytes.fromhex(d_enc_iv)
            encrypted_data_bytes = bytes.fromhex(d_enc_records)
            tag_bytes = bytes.fromhex(d_enc_tag)

            decrypted_data = decrypt_data(aes_key, iv_bytes, encrypted_data_bytes, tag_bytes)
            db_id, omegai = split_values(decrypted_data)



################################# End of AES-GCM ######################################	
   
# Compute ethi
            ethi = compute_Ethi(db_id, tauj)
            print("Ethi", ethi)
# Compute Ni
            ni = varphii ^ ethi

# Compute LIi
            lii = ni ^ int(db_id, 16) ^ chii
            print("Received lii", lii)			
#retreiving gps values from lii

            retrieved_combined_data = lii.to_bytes((lii.bit_length() + 7) // 8, byteorder='big')
    
            try:
                longitude, latitude, timestamp = split_GPS_values(retrieved_combined_data)

            except Exception as e:
                print(f"Error splitting GPS values: {e}")
# Compute psii
            psii_data = db_id + str(ni) + str(lii) + str(ethi) + str(omegai)
            psii = hashlib.sha256(psii_data.encode()).hexdigest()
            if(psii == psii_rec):
                print("Successful Drone Auhtentication")
                print("Now Calculating Challenge Message for Drone")

# Generates Mj
                Mj = generate_random_number()
	
# Computes: Mprj = Mj Xor Ni
                Mprj = Mj ^ ni

# Generates a random identity: tidinew
                tidinew = generate_random_identity()

# Computes: TIDstar = MJ XOR TIDnew
                TIDstar = Mj ^ int(tidinew, 16)

	
# Computes: ppsi = hash(tidi concatenation Mj concatenation omegai)

                ppsi = hash_data(tidinew, Mj, omegai)

# Computes: SKik = hash(identity concatenation Mj concatenation Ni concatenation Pppsi)
                SKik = hash_data(db_id, Mj, ni, ppsi)
                cpu_end_time1 = time.process_time()
                print("\nSession key has been generated")
		
		

            else:
                print("UnSuccessful Drone Auhtentication. Session has been terminated")
                sys.exit()

            # Create a dictionary to send back to the client
            response_data = {
            'Mprj': Mprj,
            'Tidstar': TIDstar,
            'ppsi': ppsi}


            total_data_size += len(response_data)			
			
# Convert the response data to a JSON string
            response_json = json.dumps(response_data)
            
            e2e_start_time = time.time()
# Send the response to the client
            conn.send(response_json.encode('utf-8'))
            print("Sent Challenge Message <Mprj, Tidstar, Ppsi> to Drone")
            print("Sent Mprj: ", Mprj )
            print("Sent Tidstar: ", TIDstar)
            print("Sent ppsi: ", ppsi)
            
            print("Waiting for Response Message")
            print("\n")
			

# Receive data from the server
            data2 = conn.recv(1024)
            e2e_end_time = time.time()
            data2 = data2.decode('utf-8')
            total_data_size += len(data2)
            # print('Received:', data2)
			
            received_data2 = json.loads(data2)
# Extract and print Mprj, Tidstar, and ppsi
            
            upsiloni_rec = received_data2.get('upsiloni')
			
            
            print("Received Response Message <upsiloni> from Drone")
            
            print("Received upsiloni: ", upsiloni_rec)
            print("\n")
			
                


#calcualtion of authentication check
            cpu_start_time2 = time.process_time()	
            upsiloni = hash_data(omegai, SKik)
	
#verficaiton check of authentication check	
            if(upsiloni == upsiloni_rec):
                print("Successful Sesson-key Authentication")
        
     
				

# Concatenate values
                combined_data = concatenate_values(db_id, omegai)

# Encrypt the combined data
                new_iv, new_encrypted_data, new_tag = encrypt_data(aes_key, combined_data)
       
                sql_2 = "UPDATE `sakeprotocol` SET `d_otid_old`= %s,`d_otid_new`=%s,`d_enc_records` = %s, `d_enc_iv` = %s, `d_enc_tag` = %s  WHERE id = %s"
                val = (tidi, tidinew, new_encrypted_data.hex(), new_iv.hex(), new_tag.hex(), row_primary_key)

                mycursor.execute(sql_2, val)
                mydb.commit()
                cpu_end_time2 = time.process_time() 
                print("Updated Tidi in DB")

                print("\n")
                print("Established Session Key with Drone: ", SKik)
                data3 = "1"
                data3 = data3.encode("utf-8")
                conn.send(data3)

				
# Total CPU Process Time (GSS-Side)
                total_cpu_process_time = (cpu_end_time1 - cpu_start_time1) + (cpu_end_time2 - cpu_start_time2) 
#print(f"Total GSS's CPU Process Time: {total_cpu_process_time} seconds")
                print("GSS's CPU Process Time: {:.4f} seconds".format(total_cpu_process_time))

# Total E2E delay (GSS-Side)
                end_to_end_delay = e2e_end_time - e2e_start_time
                print(f"GSS's End-to-End Delay: {end_to_end_delay:.4f} seconds")

# Throughput (GSS-Side)
                throughput = total_data_size / (e2e_end_time - e2e_start_time)
                print(f"GSS's Throughput: {throughput:.4f} bytes/second")	
				
#openning GPS coordinates in google map
                open_google_maps(latitude, longitude)
                key = base64.urlsafe_b64encode(bytes.fromhex(SKik))
                cipher_suite = Fernet(key)
                try:
                    while True:
# Receive the frame length
                        frame_length_data = conn.recv(4)  # 4 bytes for frame length
                        if not frame_length_data:
                            print("End of frames")
                            break

                        frame_length = int.from_bytes(frame_length_data, byteorder='big')

# Receive the encrypted frame
                        frame_data = b""
                        while len(frame_data) < frame_length:
                            frame_chunk = conn.recv(frame_length - len(frame_data))
                            if not frame_chunk:
                                print("Frame data incomplete. Exiting.")
                                break
                            frame_data += frame_chunk

# Decrypt the frame using cipher_suite
                        decrypted_frame = cipher_suite.decrypt(frame_data)

#reconstruction of frames converting them in numpy array
                        frame_np = np.frombuffer(decrypted_frame, np.uint8)
                        frame_decrypted = cv2.imdecode(frame_np, cv2.IMREAD_COLOR)

                        if frame_decrypted is not None:
 #Display the decrypted frame
                            cv2.imshow("Decrypted Video of Drone: ", frame_decrypted)

                        if cv2.waitKey(1) & 0xFF == ord('q'):
                            break
                except Exception as e:
                    print(f"Error: {e}")
                finally:
                    conn.close()
                    cv2.destroyAllWindows()
       
            else:
                print("Session Key Auhtentication is failed. Session has been terminated")
                sys.exit()

if __name__ == "__main__":
    main()