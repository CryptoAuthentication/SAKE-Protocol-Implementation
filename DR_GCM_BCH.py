import secrets
import hashlib
import json
import os
import base64
import sys
import socket
import cv2
import struct
import socket
import gpsd
import random
import numpy
import serial
import binascii
import bchlib
from pynmea2 import parse
import numpy as np
from datetime import datetime
import time
from cryptography.fernet import Fernet
from pypuf.simulation import XORArbiterPUF
from pypuf.io import random_inputs
import sys
import numpy
from fuzzy_extractor import FuzzyExtractor
from pymavlink import mavutil



#Determines PUF output from FPGA
def read_uart(port, baudrate, timeout):
    try:
        ser = serial.Serial(port, baudrate, timeout=timeout)
        
        # Send 0xEB in hex format through RX
        ser.write(b'\xEB')  # Sending 0xEB to the UART RX
        #print("Waiting for UART data...")
        while True:
            data = ser.readline()
            if data:
                #print("Received:", data)
                hex_data = ''.join([hex(byte)[2:].zfill(2) for byte in data])
                #print("Received (hex):", hex_data)
                received_string = len(hex_data)

												
				#For A7-35T with 10 MHz CLK and 9600 baud
				#Assuming 1-hexa character = 4 bits, 26-hexa characters = 104 bits
                if len(hex_data) == 26:
                # Extract the first 18 characters and ignore the first two characters "00"
                    first_18_chars = hex_data[:18]
                    final_64_hex_string = first_18_chars[2:]
    
                    return final_64_hex_string
                    ser.close()  # Close the serial port when done
                    break




    except serial.SerialException as e:
        print("Error:", e)
    finally:
        if ser.is_open:
            ser.close()  # Ensure the serial port is closed

#To read GPS values from pixhawk's GPS sensor
def get_gps_data(master):
    #print("Waiting for GPS data...")
    while True:
        msg = master.recv_match(type=['GPS_RAW_INT', 'GLOBAL_POSITION_INT'], blocking=True)
        if msg:
            if msg.get_type() == 'GPS_RAW_INT':
                lat = msg.lat / 1e7
                lon = msg.lon / 1e7
                alt = msg.alt / 1e3
                timestamp = int(datetime.utcnow().strftime('%Y%m%d%H%M%S'))
            elif msg.get_type() == 'GLOBAL_POSITION_INT':
                lat = msg.lat / 1e7
                lon = msg.lon / 1e7
                alt = msg.alt / 1e3
                timestamp = int(datetime.utcnow().strftime('%Y%m%d%H%M%S'))
            #print(f"Latitude: {lat}, Longitude: {lon}, Altitude: {alt} meters")
            return lon, lat, timestamp
            break
        else:
            print("No GPS data received. Retrying...")


def hash_data(*args):
    concatenated_data = ''.join(map(str, args)).encode()
    return hashlib.sha256(concatenated_data).hexdigest()

def concatenate_GPS_values(longitude, latitude, timestamp):
    return f"{longitude}:{latitude}:{timestamp}".encode()

def main(): 



# Performance metrics variables
    cpu_start_time1 = 0
    cpu_end_time1 = 0
    cpu_start_time2 = 0
    cpu_end_time2 = 0
    total_data_size = 0
    e2e_start_time = 0
    e2e_end_time = 0



    alpha_i = 251651615086772420151324980956018336315
    beta_i = 60655810436627964120536452882792016979195424042144700479859464589726403653704

    #Determines PUF output
    puf_output = read_uart("/dev/ttyUSB1", 9600, 0.1)
	

# %%%%%%%%% Start of BCH-ECC %%%%%%%%%%%%%
    with open('drone_jason_data.json', 'r') as json_file:
        stored_values = json.load(json_file)
        tidi = stored_values["tidi"]
        stored_ecc = bytearray(binascii.unhexlify(stored_values["ecc"]))
        stored_key_hash = binascii.unhexlify(stored_values["key_hash"])
    cpu_start_time1 = time.process_time()    
    noisy_puf_output = bytearray(binascii.unhexlify(puf_output))

# Decode the new noisy PUF output with BCH using the stored ECC
    packet = noisy_puf_output + stored_ecc
    data, ecc = packet[:-bch.ecc_bytes], packet[-bch.ecc_bytes:]

# Decode
    nerr = bch.decode(data, ecc)

# Correct
    bch.correct(data, ecc)

# Verify the corrected PUF output
    reproduced_omegai = bytes(data)  # Convert bytearray to bytes for printing

# %%%%%%%%% End of BCH-ECC %%%%%%%%%%%%%

    
    master = mavutil.mavlink_connection('/dev/ttyACM0', baud=9600)    
    master.wait_heartbeat()    
    print("Drone's Heartbeat received:", master.target_system)
    longitude, latitude, timestamp = get_gps_data(master)

#Retrieving Identity and ethi from stored values    
   
    retrieve_identity = int.from_bytes(reproduced_omegai,byteorder = 'big') ^ alpha_i
    Ethi = retrieve_identity ^ int.from_bytes(reproduced_omegai,byteorder = 'big') ^ beta_i
    identity = hex(retrieve_identity)[2:]   

# Concatenate values

    combined_data = concatenate_GPS_values(longitude, latitude, timestamp)


    
    
    # Convert combined_data to an integer
    lii = int.from_bytes(combined_data, byteorder='big')

    
    
    
    #lii = secrets.randbelow(2**128)
    ni = secrets.randbelow(2**128)
    varphii = ni ^ Ethi
    #chii = ni ^ int(identity, 16) ^ lii  # Convert hexadecimal string to integer
    chii = ni ^ int(identity, 16) ^ lii
    #print("Chii", chii)
    psii = hashlib.sha256((identity + str(ni) + str(lii) + str(Ethi) + str(reproduced_omegai)).encode()).hexdigest()

    cpu_end_time1 = time.process_time()
# Create a dictionary with the values to send
    data = {
        "tidi": tidi,
        "varphii": varphii,
        "chii": chii,
        "psii": psii,

    }


    host = "192.168.1.105"
    port = 11111

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        json_data = json.dumps(data).encode('utf-8')


        e2e_start_time = time.time()       
        s.sendall(json_data)
        total_data_size += len(json_data)

		
# Receive data from the server
        response = s.recv(1024)
        e2e_end_time = time.time() 
        response_data = json.loads(response.decode("utf-8"))
        total_data_size += len(response_data)		
        print("\n")
        print("Sent Login Request Message <Tidi, Varphii, Chii, Psii> to GCS")
        print("Sent Tidi:", tidi)
        print("Sent Varphii:", varphii)
        print("Sent Chii:", chii)
        print("Sent Psii:", psii)
        print("\n")
        print("Waiting for Challeneg Message from GCS:")
        print("\n")

# Extract and print Mprj, Tidstar, and ppsi
        rec_mprj = response_data.get('Mprj')
        rec_tidistar = response_data.get('Tidstar')
        rec_ppsi = response_data.get('ppsi')

        print("Received Challenge Message <Mprj, Tidstar, ppsi> from GCS:")

        print("Received Mprj:", rec_mprj)
        print("Received Tidstar:", rec_tidistar)
        print("Received ppsi:", rec_ppsi)
        print("\n")
		
        cpu_start_time2 = time.process_time()				
#Regenerate Mj: Mj = Mprj Xor Ni
        Mj_regenerated = rec_mprj ^ ni 
	
# Regenerate tidinew: tidinew = Mj Xor tidistar
        tidinew_retrival = Mj_regenerated ^ rec_tidistar
        tidinew_regenerated = hex(tidinew_retrival)[2:]
	
# The expected length of the Tidinew value
        expected_length = 32  

# Check the length of the retrieved_tidinew
# Add leading zeros to make it 32 characters long
        if len(tidinew_regenerated) < expected_length:
            tidinew_regenerated = "0" * (expected_length - len(tidinew_regenerated)) + tidinew_regenerated
            
            

    
#computes ppsi from retrieved values
        ppsi = hash_data(tidinew_regenerated, Mj_regenerated, reproduced_omegai)
        if(ppsi == rec_ppsi):
            print("GCS Authentication is sucessful")
		
#Establishes Skik 
            SKik = hash_data(identity, Mj_regenerated, ni, ppsi)
            print("\n")
            print("Session Key has been generated")
            print("\n")


# Perform the XOR operation
#            cpsi = int_omegainew ^ int_omegaiold             #removed in latest
            upsiloni = hash_data(reproduced_omegai, SKik)

            cpu_end_time2 = time.process_time()			
# After successful authentication or at the end of the script, update and save new values
            stored_values["tidi"]= tidinew_regenerated 
#******Write updated values back to the file

			
# Convert the data to JSON
            json_storage_data = json.dumps(stored_values, indent=2)



# Save the JSON data to a file
            with open('drone_jason_data.json', 'w') as json_file:
                json_file.write(json_storage_data)
            print("values are updated in Drone's memory")
            print("\n")
	
            
#creating response message			
            
            data2 = {

            "upsiloni": upsiloni}
            json_data2 = json.dumps(data2).encode('utf-8')

			
            s.sendall(json_data2)
			


            #print("Sent Response Message <cpsi, upsiloni> to GCS
            print("Sent Response Message <upsiloni> to GCS:")

            #print("Sent cpsi: ", cpsi)
            print("Sent upsiloni: ", upsiloni)
            print("\n")
            print("Successfully Established Session Key with GCS")
            print("Established Session Key with GCS: ", SKik)
			
# Total CPU Process Time (Drone-Side)
            total_cpu_process_time = (cpu_end_time1 - cpu_start_time1) + (cpu_end_time2 - cpu_start_time2) 
#print(f"Total Droen's CPU Process Time: {total_cpu_process_time} seconds")
            print("Droen's CPU Process Time: {:.4f} seconds".format(total_cpu_process_time))

# Total RTT delay (Drone-Side)
            end_to_end_delay = e2e_end_time - e2e_start_time
            print(f"Round Trip Time: {end_to_end_delay:.4f} seconds")

# Throughput (Drone-Side)
            throughput = total_data_size / (e2e_end_time - e2e_start_time)
            print(f"Drone's Throughput: {throughput:.4f} bytes/second")			
            key = base64.urlsafe_b64encode(bytes.fromhex(SKik))
            cipher_suite = Fernet(key)
            data3 = s.recv(1024)
            data3 = data3.decode("utf-8")



	

            if int(data3) == 1:
                try:
                    cap = cv2.VideoCapture(0)

                    while True:
                        ret, frame = cap.read()

                        if not ret:
                            break

# Convert the frame to a byte array
                        _, frame_bytes = cv2.imencode('.jpg', frame)

# Encrypt the frame data
                        encrypted_frame = cipher_suite.encrypt(frame_bytes.tobytes())
                        frame_length = len(encrypted_frame).to_bytes(4, byteorder='big')  # 4 bytes for frame length

# Send the frame length
                        s.send(frame_length)

# Send the encrypted frame
                        s.send(encrypted_frame)

                except Exception as e:
                    print(f"Error: {e}")

                finally:
                    cap.release()
                    s.close()

            
        else:
            print("UnSucessful GCS Authentication. Session has been terminated")
            print("reproduced_omegai",reproduced_omegai)
            sys.exit()

	
	
 
	
	

if __name__ == "__main__":
    main()
	

