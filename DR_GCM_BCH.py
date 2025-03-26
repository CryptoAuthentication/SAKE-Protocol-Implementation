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


def read_uart(port, baudrate, timeout):
    try:
        ser = serial.Serial(port, baudrate, timeout=timeout)
        ser.write(b'\xEB') 
        while True:
            data = ser.readline()
            if data:
                hex_data = ''.join([hex(byte)[2:].zfill(2) for byte in data])
                received_string = len(hex_data)


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
       
def check_assertion(T_j):
# Define threshold value T_delta (1 second)
    T_delta = 5

    # Get the current server time (T_j_star)
    T_i_star = time.time()

    # Calculate the time difference
    time_diff = T_i_star - T_j

    # Check the assertion: T_delta <= T_i_star - T_j
    if T_delta >= time_diff:
        return True, time_diff
    else:
        return False, time_diff

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
				

def concatenate_ni_DPi_values(ni, DPi):
    return f"{ni}:{DPi}".encode()		

def estimate_energy_consumption(exectuion_time):
    average_power_consumption = 3.5 
    energy_consumed = exectuion_time * average_power_consumption
    print(f"Estimated Energy Consmued during the protocol run: {energy_consumed:.4f}, Joules")  

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
    overall_start_time1 = 0 
    overall_end_time1 = 0    
    overall_start_time2 = 0 
    overall_end_time2 = 0   

#Determines PUF output
    puf_output = read_uart("/dev/ttyUSB1", 9600, 0.1)
	
	
# %%%%%%%%% Start of BCH-ECC %%%%%%%%%%%%%
    with open('DR_Reg_Parameters.json', 'r') as json_file:
        stored_values = json.load(json_file)
        tidi = stored_values["tidi"]
        stored_ecc = bytearray(binascii.unhexlify(stored_values["ecc"]))
        stored_key_hash = binascii.unhexlify(stored_values["key_hash"])
        alpha_i = stored_values["alpha_i"]
        beta_i = stored_values["beta_i"]
        DPi = stored_values["DPi"]
        

    overall_start_time1 = time.time()    
    cpu_start_time1 = time.process_time()    
    noisy_puf_output = bytearray(binascii.unhexlify(puf_output))

# Decode the new noisy PUF output with BCH using the stored ECC
    packet = noisy_puf_output + stored_ecc
    BCH_T = 6
    BCH_PRIM_POLY = 487
    bch = bchlib.BCH(BCH_T,BCH_PRIM_POLY)    
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
    print("================================================================================================")    
    print(f"Drone's Heartbeat received: {master.target_system}")
    print("================================================================================================")
    longitude, latitude, timestamp = get_gps_data(master)


#Retrieving Identity and ethi from stored values    
    retrieve_identity = int.from_bytes(reproduced_omegai,byteorder = 'big') ^ alpha_i
    Ethi = retrieve_identity ^ int.from_bytes(reproduced_omegai,byteorder = 'big') ^ beta_i
    identity = hex(retrieve_identity)[2:]   
    
# Concatenate values

    combined_data = concatenate_GPS_values(longitude, latitude, timestamp)
    
# Get current time (T_i - Drone time)
    T_i = time.time()      
    
# Convert combined_data to an integer
    lii = int.from_bytes(combined_data, byteorder='big')
    
  
    
    ni = secrets.randbelow(2**128)
	
	
#Concatenate ni with DPi	
    ni_DPi = concatenate_ni_DPi_values(ni, DPi)
	

# Converts msg_i from bytes to integer
    ni_DPi_int = int.from_bytes(ni_DPi, byteorder='big')
    print(f"ni_DPi_int:{ni_DPi_int}")	
	
	
    varphii = ni_DPi_int ^ Ethi
    chii = ni ^ int(identity, 16) ^ lii
    psii = hashlib.sha256((identity + str(ni) + str(lii) + str(Ethi) + str(reproduced_omegai) + str(T_i)).encode()).hexdigest()

    cpu_end_time1 = time.process_time()
    overall_end_time1 = time.time()
# Create a dictionary with the values to send
    data = {
        "tidi": tidi,
        "varphii": varphii,
        "chii": chii,
        "psii": psii,
        "T_i":T_i
    }
    
    host = "192.168.1.58"
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
        print("================================================================================================")		 
        print("----------------- Preparing Login Message -----------------")
        print("================================================================================================")
        print("/////// Sent Login Request Message <Tidi, Varphii, Chii, Psii, Ti> to GCS ///////")
        print("================================================================================================")
        print("----------------- Login Message Parameters -----------------")
        print("Sent Tidi:", tidi)
        print("Sent Varphii:", varphii)
        print("Sent Chii:", chii)
        print("Sent Psii:", psii)
        print("Sent Ti:", T_i)        
        print("================================================================================================")
        print("----------------- Waiting for Challeneg Message from GCS -----------------")
        print("================================================================================================")
        
# Extract and print Mprj, Tidstar, and ppsi
        rec_mprj = response_data.get('Mprj')
        rec_tidistar = response_data.get('Tidstar')
        rec_ppsi = response_data.get('ppsi')
        rec_T_j = response_data.get('T_j')
        
        print("================================================================================================")
        print("/////// Received Challenge Message <Mprj, Tidstar, ppsi, Tj> from GCS ///////")
        print("================================================================================================")
        print("----------------- Received Challenge Message Parameters -----------------")
        print("Received Mprj:", rec_mprj)
        print("Received Tidstar:", rec_tidistar)
        print("Received ppsi:", rec_ppsi)
        print("Received T_j:", rec_T_j)
        print("================================================================================================")
        
# Check the assertion
        assertion_result, time_diff = check_assertion(rec_T_j)  
        
# Display result
        if assertion_result:
            print(f"----------------- Timestamp Assertion Passed -----------------")
        else:
            print(f"----------------- Timestamp Assertion Failed -----------------")
            sys.exit()
		      
        
        overall_start_time2 = time.time()	
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
        ppsi = hash_data(tidinew_regenerated, Mj_regenerated, reproduced_omegai, rec_T_j)
        if(ppsi == rec_ppsi):
            print("----------------- GCS Authentication is Sucessful -----------------")
		
#Establishes Skik 
            SKik = hash_data(identity, Mj_regenerated, ni, ppsi)
            print("================================================================================================")
            print("----------------- Session key has been Generated -----------------")
            print("================================================================================================")
            
# Get current time (T_i - Drone time)
            T_i2 = time.time()             
            

# Perform the XOR operation
            upsiloni = hash_data(reproduced_omegai, SKik, T_i2)

            cpu_end_time2 = time.process_time()	
            overall_end_time2 = time.time()		
# After successful authentication or at the end of the script, update and save new values
            stored_values["tidi"]= tidinew_regenerated 

# Convert the data to JSON
            json_storage_data = json.dumps(stored_values, indent=2)

# Save the JSON data to a file
            with open('DR_Reg_Parameters.json', 'w') as json_file:
                json_file.write(json_storage_data)
            print("================================================================================================")
            print("----------------- Values are Updated in Drone's Memory -----------------")
            print("================================================================================================")
	 
#creating response message			         
            data2 = {

            "upsiloni": upsiloni,
            "T_i2": T_i2	
            }
            json_data2 = json.dumps(data2).encode('utf-8')			
            s.sendall(json_data2)
			
            print("================================================================================================")
            print("/////// Sent Response Message <upsiloni,Ti2> to GCS ///////")
            print("================================================================================================")
            print("----------------- Response Message Parameters -----------------")
            print("Sent upsiloni: ", upsiloni)
            print("Sent T_i2: ", T_i2)	            
            print("================================================================================================")            
            print(" ----------------- Successfully Established Session Key with GCS  ----------------- ")
            print("================================================================================================")            
            print(f"Established Session Key with GCS: {SKik}")
            print("================================================================================================")
			
# Total CPU Process Time (Drone-Side)
            total_cpu_process_time = (cpu_end_time1 - cpu_start_time1) + (cpu_end_time2 - cpu_start_time2) 

            print("Droen's CPU Process Time: {:.4f} seconds".format(total_cpu_process_time))

# Total E2E delay (Drone-Side)
            end_to_end_delay = e2e_end_time - e2e_start_time
            print(f"Drone End-to-End Delay: {end_to_end_delay:.4f} seconds")
# Total Energy Consumed
            total_execution_time = (overall_end_time1 - overall_start_time1) + (overall_end_time2 - overall_start_time2)
            estimate_energy_consumption(total_execution_time)

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
	
	
