# Securing the Skies: A Cutting-Edge Authenticated Key Establishment Protocol for the Internet of Drones

## 📡 Project Overview

This repository contains the **authentication protocol** real-world implementation source code for secure **Unmanned Aerial Vehicles-to-Ground Station Servers (UAV-to-GSS) communication** in an **Internet of Drones (IoD)** environment. The goal of this project is to provide a robust and secure communication framework to ensure the integrity and confidentiality of data transmitted between **Unmanned Aerial Vehicles (UAVs)** and **Ground Station Servers (GSS)**.

The protocol leverages state-of-the-art cryptographic techniques to establish mutual authentication and protect the IoD environment against various attack vectors. The system is designed to be implemented on a real-world testbed using actual devices, ensuring practical applicability in real-world scenarios.

## 🛠️ Features

- **Mutual Authentication:** Securely verifies both UAV and GSS identity before communication.
- **Encrypted Communication:** Ensures confidentiality of data transmitted between UAVs and GSS.
- **Low Latency:** Optimized for real-time communication in IoD environments.
- **Cross-Platform Compatibility:** Designed for use with different devices such as Raspberry Pi and laptops.

## 📋 Specifications

### **🛸 UAV Side:**

- **OS:** Ubuntu 22.04
- **RAM:** 4GB LPDDR4
- **Software:** MayProxy
- **Companion Computer:** Raspberry Pi 4B
- **Microcontroller:** Pix32 v6
- **Processor:** Cortex-A7
- **GPS Module:** MBN GPS
- **Telem. Module:** 433 MHz, 100 mW
- **PUF Module:** A7-100T FPGA
- **Camera:** Sony IMX219
- **Programming Language:** Python

### **🖥️ GSS Side:**

- **OS:** Windows 11
- **RAM:** 32GB DDR4
- **Software:** QGroundControl
- **Companion Computer:** Laptop
- **Processor:** Intel Core i7
- **Telem. Module:** 433 MHz, 100 mW
- **Programming Language:** Python

## ⚙️ Installation

To get started, clone the repository and follow the installation steps to set up both the UAV and GSS systems.

```bash
git clone https://github.com/your-repository-url.git
```

## 📝 Requirements:

```bash
Python 3.x
```

Required libraries: pynmea2, hashlib, time, etc.

## 📚 Usage
Once you have set up the environment, run the script to initialize the authentication process. Both sides (UAV and GSS) will exchange keys and perform mutual authentication.

```bash
python3 GSS_GCM_BCH.py
python3 DR_GCM_BCH.py
```

## 🚀 Real-World Testbed
The protocol has been successfully tested on a real-world testbed using actual UAVs and GSS devices. The testbed setup includes the following specifications:

UAV Side: Raspberry Pi 4B running Ubuntu 22.04, communicating with Pix32 v6 and a GPS module.

GSS Side: A laptop running Windows 11 with QGroundControl software, utilizing an Intel Core i7 processor.
