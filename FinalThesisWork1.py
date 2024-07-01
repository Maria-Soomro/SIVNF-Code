# -*- coding: utf-8 -*-
"""
Created on Sun Apr 28 12:07:51 2024
@author: Maria Soomro
"""

import multichain
import pandas as pd
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from solcx import compile_standard, install_solc
from solcx import compile_source
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
import hashlib

# Define global variables for connection parameters
rpcuser_hospital = "multichainrpc"
rpcpassword_hospital = "AHKpPRqn93C2anz7q2uyoYDSFpV2rVJ99LWxYYYqziYY"
rpchost_hospital = "127.0.0.1"
rpcport_hospital = "4264"

rpcuser_pharmacy = "multichainrpc"
rpcpassword_pharmacy = "AiLg3t7oaLu3qPS6YvL2BVmm44jp61BC3cV6N4fZmHUL"
rpchost_pharmacy = "127.0.0.1"
rpcport_pharmacy = "8372"

rpcuser_interop = "multichainrpc"
rpcpassword_interop = "BMprAtvpvogAUssdmCLH6EP6Je3akKTrGiPVZEhg8wcm"
rpchost_interop = "127.0.0.1"
rpcport_interop = "9572"

total_proof_verification_time = 0
proof_verification_count = 0
total_publish_time = 0
publish_count = 0
total_delay_between_publish = 0
start_time = None
    
def is_hospital_registered(hospital_address):
    # Load registered hospital contract addresses from a file
    registered_hospital_addresses = []
    with open('pharmacy_contract_addresses.txt', 'r') as file:
        registered_hospital_addresses = [line.strip() for line in file.readlines()]

    # Check if the provided hospital contract address is in the list of registered addresses
    return hospital_address in registered_hospital_addresses

def register_hospital_if_not_registered(hospital_contract_address, registration_key, public_key):
    # Check if hospital is already registered
    if is_hospital_registered(hospital_contract_address):
        print("Hospital is already registered with this address.")
    else:
        # Create an instance of the HospitalIdentityFactory contract
        factory_contract = w3.eth.contract(address=contract_addressHospital, abi=contract_abi)

         # Check if the combination of registration_key and public_key has been used
        combination_used = factory_contract.functions.verifyIdentity(registration_key, public_key).call()
        if combination_used:
            print("Combination of registration key and public key already used.")
            print("Hospital already registered with this combination, allowing communication.")
            return False
        else:
            # Register a hospital
            tx_hash = factory_contract.functions.registerHospital(hospital_contract_address, registration_key, public_key).transact({'from': account_address})

            # Wait for transaction receipt
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            print("Hospital registered to continue communication!")
            
            # Store the transaction hash as a record
            with open('pharmacy_contract_hashes.txt', 'a') as file:
                file.write(tx_receipt['transactionHash'].hex() + '\n')

            # Store the hospital contract address in the list of registered addresses
            with open('pharmacy_contract_addresses.txt', 'a') as file:
                file.write(hospital_contract_address + '\n')
            return True

def pharmacy_interaction_with_hospital(hospital_contract_address):
    if is_hospital_registered(hospital_contract_address):
        # Proceed with interactions (e.g., requesting data, processing requests)
        print("Hospital identity verified, Pharmacy interaction with hospital allowed.")
        # Implement your logic here
    else:
        # Abort interaction if hospital identity verification fails
        print("Pharmacy interaction denied due to identity verification failure.")
        raise RuntimeError("Pharmacy interaction denied due to identity verification failure.")


# Connect to local Ganache node
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))

#Deploying Contract
contract_file_path = 'C:/Users/MariaS/Documents/HospitalIdentityFactory.sol'
with open(contract_file_path, 'r') as file:
    contract_source_code = file.read()


install_solc("0.7.0")

compiled_sol = compile_standard({
    "language": "Solidity",
    "sources": {
        "HospitalIdentityFactory.sol": {
            "content": contract_source_code
        }
    },
    "settings": {
        "outputSelection": {
            "*": {
                "*": ["abi", "evm.bytecode"]
            }
        }
    }
})
install_solc("0.7.0")
contract_name = "HospitalIdentityFactory"
contract_abi = compiled_sol["contracts"]["HospitalIdentityFactory.sol"][contract_name]["abi"]
contract_bytecode = compiled_sol["contracts"]["HospitalIdentityFactory.sol"][contract_name]["evm"]["bytecode"]["object"]

# Account to deploy the contract (use Ganache account address and private key)
account_address = w3.eth.accounts[1]
private_key = '0x089edfbf71cc1d865ff75330c0438b31545629a4f72b832f2425da5a02771583'

# Deploy the contract
contract = w3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)

# Build transaction data
nonce = w3.eth.get_transaction_count(account_address)
gas_limit = 1728712


transaction = {
    'from': account_address,
    'nonce': nonce,
    'gas': gas_limit,
    'gasPrice': w3.eth.gas_price,
    'data': contract.bytecode
}

# Sign and send the transaction
signed_txn = w3.eth.account.sign_transaction(transaction, private_key=private_key)
tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
contract_addressHospital = tx_receipt['contractAddress']
print("HospitalIdentityFactory deployed at:", contract_addressHospital)

# Register a hospital
registration_key = 'MariaSoomroThesis'
public_key = '0x12345678901234567890123456789012345678901'

hospital_contract_address = contract_addressHospital

# Register hospital if not already registered
if register_hospital_if_not_registered(hospital_contract_address, registration_key, public_key):
    # Proceed with further interactions if registration is successful
    pharmacy_interaction_with_hospital(hospital_contract_address)
else:
    print("Registration failed due to verification issues")

#signature verification
def sign_message_hospital(message, private_key_hospital):
    message_str = str(message)
    signature = private_key_hospital.sign(
        message_str.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature.hex()

def verify_signature(data, signature, public_key):
    try:
        public_key.verify(
            bytes.fromhex(signature),
            data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False
    
def hash_patient_medicine(medicine_id, medicine_name):
    concat_str = f"{medicine_id}{medicine_name}"
    return int(hashlib.sha256(concat_str.encode()).hexdigest(), 16)

# Function to generate proof based on the hash of MedicineName and Availability
def generate_proof(medicine_name, availability):
    concat_str = f"{medicine_name}{availability}"
    proof_value = int(hashlib.sha256(concat_str.encode()).hexdigest(), 16)
    return [proof_value, 0]

def check_availability(medicine_name,medicine_availability_contract,pharmacy_data):
    if medicine_name in pharmacy_data['MedicineName'].values:
        return True
    else:
        return False


# Subscribe to the blockchain stream to receive messages from the hospital
stream_name = 'PatientRequestData'

#Deploying Contract
contract_file_path = 'C:/Users/MariaS/Documents/MedicineFinal.sol'
with open(contract_file_path, 'r') as file:
    contract_source_code = file.read()

install_solc("0.7.0")

compiled_sol = compile_standard({
    "language": "Solidity",
    "sources": {
        "MedicineAvailability.sol": {
            "content": contract_source_code
        }
    },
    "settings": {
        "outputSelection": {
            "*": {
                "*": ["abi", "evm.bytecode"]
            }
        }
    }
})

contract_name = "MedicineAvailability"
contract_abi = compiled_sol["contracts"]["MedicineAvailability.sol"][contract_name]["abi"]
contract_bytecode = compiled_sol["contracts"]["MedicineAvailability.sol"][contract_name]["evm"]["bytecode"]["object"]

# Initialize Web3 and connect to the local Ethereum node Ganache
w3 = Web3(Web3.HTTPProvider('http://localhost:7545'))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)

# Set account from which to deploy the contract
account = w3.eth.accounts[0]
print("Deploying contract from account:", account)

#my_address = "0x3c29B7353842c52a68070613f6DCD383cea31f10"
private_key = "0xe10989279670e0b283549021f8fc5ba15b790e0f72da918e199b6cf1508bb120"

# Generate RSA private key
private_key_hospital = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Serialize the private key to PEM format
private_key_pem = private_key_hospital.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Extract raw private key bytes from PEM format
private_key_bytes = private_key_hospital.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Use the first 32 bytes as Ethereum private key (raw bytes)
ethereum_private_key_bytes = private_key_bytes[:32]

# Deploy the contract
contract = w3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)

nonce = w3.eth.get_transaction_count(account)

new_gas_limit = 3000000

# Submit the transaction that deploys the contract
transaction = contract.constructor().build_transaction({
    "chainId": 1337,
    'gasPrice':w3.eth.gas_price,
    'from': account,
    'nonce': nonce,
    'gas': new_gas_limit,   
})

# Sign the transaction
signed_transaction = w3.eth.account.sign_transaction(transaction, private_key=private_key)
# Send it!
tx_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
print("Transaction hash:", tx_hash.hex())

print("Waiting for the transaction to be mined...")
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print("Contract deployed at address:",{tx_receipt.contractAddress})

contract_address = tx_receipt.contractAddress
# Retrieve gas used in deployment transaction
gas_used = tx_receipt.gasUsed
print("Gas used in deployment:", gas_used)
# Calculate new gas limit for subsequent transactions
gas_limit_reduction_percentage = 1  # 1% reduction
new_gas_limit = int(new_gas_limit - (new_gas_limit * gas_limit_reduction_percentage / 100))  # Reduce gas limit by 1%

# Update the nonce for the next transaction
nonce = w3.eth.get_transaction_count(account)

# Store contract address
with open('medicine_availability_contract_address.txt', 'w') as file:
    file.write(tx_receipt.contractAddress)

def return_availability_to_hospital(mc, patient_id, medicine_name, availability, signature):
    # Publish medicine availability to hospital
    mc.publish("PatientRequestData", patient_id, {'json': {'PatientID': patient_id, 'MedicineName': medicine_name, 'Availability': availability, 'Signature': signature}})
    
    
# Track transaction counts
transaction_count = {
    'proof_generation': 0,
    'hash_publication': 0,
    'zkp_verification': 0
}

# Track execution time
start_time = None

def publish_patient_request_data(patient_id, medicine_name, availability_status, medicine_availability_contract, w3, account_address, private_key):
   try:
    # Store proof hash for medicine availability
    availability_value = 1 if availability_status else 0

    # Prepare the transaction data
    tx_hash = medicine_availability_contract.functions.storeProof(medicine_name, availability_value).transact({'from': account})

    # Wait for transaction receipt
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    # Check transaction receipt status
    if tx_receipt.status == 1:
        print(f"Proof stored successfully for {medicine_name} availability status: {availability_status}")
    else:
        print(f"Transaction failed for {medicine_name} availability status: {availability_status}")

    # Emit event to indicate patient request data (outside of transaction execution)
    event_data = {
        "patientId": patient_id,
        "medicineName": medicine_name,
        "availabilityStatus": availability_status
    }
    print("Emitting patient request data event:", event_data)

   except Exception as e:
    print(f"Error publishing patient request data: {str(e)}")


# Hospital Environment
def hospital_environment(hospital_df, pharmacy_df):
    global start_time
    start_time = time.time()  # Record start time

    for index, row in hospital_df.iterrows():
        medicine_id = row['MedicineID']
        medicine_name = row['MedicinePrescribed']

        # Generate proof (for example, concatenating MedicineID and MedicineName)
        proof_value = hash_patient_medicine(medicine_id, medicine_name)

        # Append proof to a file or data structure for later use
        with open('proofs.txt', 'a') as file:
            file.write(f"{medicine_id},{medicine_name},{proof_value}\n")

        # Increment proof generation transaction count
        transaction_count['proof_generation'] += 1

    print("Hospital environment processing complete.")

# Pharmacy Environment
def pharmacy_environment(mc_pharmacy,hospital_df, pharmacy_df):
    
    for index, row in pharmacy_df.iterrows():
        medicine_id = row['MedicineID']
        medicine_name = row['MedicineName']

        # Generate hash using MedicineID and MedicineName
        pharmacy_hash = hash_patient_medicine(medicine_id, medicine_name)

          # Append proof to a file or data structure for later use
        with open('proofPharmacy.txt', 'a') as file:
             file.write(f"{medicine_id},{medicine_name},{pharmacy_hash}\n")
             
        # Publish hash to a pharmacy-created stream
        #publish_to_pharmacy_stream(mc_pharmacy,medicine_name,pharmacy_hash)

        # Increment hash publication transaction count
        transaction_count['hash_publication'] += 1

    print("Pharmacy environment processing complete.")
    


def interoperability_layer(medicine_availability_contract, mc_hospital, pharmacy_df):
    global total_proof_verification_time
    global proof_verification_count
    global total_publish_time
    global publish_count
    global total_delay_between_publish
    global start_time
    # Track the count of data published on the stream
    data_published_count = 0
    last_publish_time = time.time()
    # Read the proofs from the file and store them in a dictionary
    proofs = {}
    with open('proofs.txt', 'r') as file:
        for line in file:
            parts = line.strip().split(',')
            medicine_id = parts[0]
            medicine_name = parts[1]
            # Simulate proof verification time calculation
            start_time = time.time()
            proof_value = int(parts[2])
            if medicine_name not in proofs:
                proofs[medicine_name] = []
            proofs[medicine_name].append(proof_value)

    # Retrieve all hashes from the pharmacy dataset for comparison
    pharmacy_hashes = {}
    with open('C:/Users/MariaS/Documents/Thesis work 1/PharmacyData.csv', 'r') as file:
        next(file)  # Skip header
        for line in file:
            parts = line.strip().split(',')
            medicine_id = parts[1]
            medicine_name = parts[5]
            pharmacy_hash = hash_patient_medicine(medicine_id, medicine_name)
            if medicine_name not in pharmacy_hashes:
                pharmacy_hashes[medicine_name] = []
            pharmacy_hashes[medicine_name].append(pharmacy_hash)

    # Iterate over hospital proofs and compare against all pharmacy hashes
    for medicine_name, proof_values in proofs.items():
        if medicine_name in pharmacy_hashes:
            found_available = False
            for proof_value in proof_values:
                for pharmacy_hash in pharmacy_hashes[medicine_name]:
                    # Compare each hospital proof value with all pharmacy hashes
                    if proof_value == pharmacy_hash:
                        # Proof found in pharmacy dataset, proceed with availability check
                        print(f"Proof for MedicineName: {medicine_name} verified.")
                        found_available = True
                        break
                if found_available:
                    break

            if found_available:
                # Verify proof against pharmacy hash using zk-SNARKs contract
                verified = medicine_availability_contract.functions.verifyProof(proof_value, pharmacy_hash).call()

                if verified:
                    print(f"Proof for MedicineName: {medicine_name} successfully verified.")
                    transaction_count['zkp_verification'] += 1
                    end_time = time.time()
                    proof_verification_time = end_time - start_time
                    print(f"proof verification time {proof_verification_time}")
                    # Accumulate proof verification time
                    total_proof_verification_time += proof_verification_time
                    proof_verification_count += 1
                    # Retrieve availability status from pharmacy database (simulated by checking if medicine_name exists)
                    availability = check_availability(medicine_name, medicine_availability_contract, pharmacy_df)
                    if availability:
                        print(f"{medicine_name} is available. Publishing availability to smart contract...")
                        start_publish_time = time.time()  # Start timing publish process
                        medicine_availability_contract.functions.publishAvailability(medicine_name, availability)
                        publish_patient_request_data(patient_id, medicine_name, availability, medicine_availability_contract,w3,account_address,private_key)
                        return_availability_to_hospital(mc_hospital, patient_id, medicine_name, availability, signature)
                        time.sleep(0.1)  # Example sleep to simulate processing time
                        end_time = time.time()
                        publish_time = end_time - start_publish_time
                        print(f"publish time {publish_time}")
       
                        # Accumulate publish time
                        total_publish_time += publish_time
                        publish_count += 1
                        current_time = time.time()
                        # Calculate delay between publishing each record
                        if data_published_count > 0:
                            delay = current_time - start_time
                            total_delay_between_publish += delay
                            delay_between_publish = (time.time() - last_publish_time) / data_published_count
                            print(f"Average delay between publish: {delay_between_publish:.2f} seconds")
                        # Update last publish time
                        last_publish_time = time.time()
                        data_published_count += 1
                        print("Total data published on stream:", data_published_count)
                    else:
                        print(f"MedicineName: {medicine_name} not available in the pharmacy database.")
                else:
                    print(f"Proof for MedicineName: {medicine_name} failed verification.")
            else:
                print(f"No matching pharmacy hash found for MedicineName: {medicine_name}")
        else:
            print(f"MedicineName: {medicine_name} not found in pharmacy hashes.")

    print("Interoperability layer processing complete.")



if __name__ == "__main__":
    # Load hospital and pharmacy datasets
    hospital_df = pd.read_csv('C:/Users/MariaS/Documents/Thesis work 1/HospitalData.csv')
    pharmacy_df = pd.read_csv('C:/Users/MariaS/Documents/Thesis work 1/PharmacyData.csv')

    # Instantiate multichain clients
    mc_hospital = multichain.MultiChainClient(rpchost_hospital, rpcport_hospital, rpcuser_hospital, rpcpassword_hospital)
    mc_pharmacy = multichain.MultiChainClient(rpchost_pharmacy, rpcport_pharmacy, rpcuser_pharmacy, rpcpassword_pharmacy)
    mc_interop = multichain.MultiChainClient(rpchost_interop, rpcport_interop, rpcuser_interop, rpcpassword_interop)

    hospital_address_to_verify = hospital_contract_address
    pharmacy_interaction_with_hospital(hospital_address_to_verify)

    # Generate hospital's RSA key pair
    private_key_hospital = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Get hospital's public key
    public_key_hospital = private_key_hospital.public_key()

    # Hospital Environment
    result_hospital = mc_hospital.getaddresses()
    print(result_hospital[0])

    # Publish chunk of data
    for index, row in hospital_df.iterrows():
        patient_id = row['PatientID']
        medicine_name = row['MedicinePrescribed']

        # Check if patient ID is present in the pharmacy dataset
        if patient_id not in pharmacy_df['PatientID'].values:
            print("Patient ID", patient_id, "not present in the pharmacy dataset. Signature verification failed. Communication halted.")
            time.sleep(5)
            continue

        # Sign and publish individual records to the blockchain
        message = patient_id + medicine_name  # Include the patient ID and medicine name
        signature = sign_message_hospital(message, private_key_hospital)

        # Determine availability of the medicine based on medicine name
        availability = medicine_name in pharmacy_df['MedicineName'].values
        
        # Determine availability of the medicine based on patient ID and medicine name
        availability = True
        
    #Removed code from here 
    
# Create an instance of the MedicineAvailability contract
medicine_availability_contract = w3.eth.contract(address=contract_address, abi=contract_abi)

# Pharmacy environment processing
pharmacy_environment(mc_pharmacy,hospital_df, pharmacy_df)
 
# Hospital environment processing
hospital_environment(hospital_df, pharmacy_df)

# Interoperability layer processing
interoperability_layer(medicine_availability_contract,mc_hospital,pharmacy_df)

# Publish availability to the stream
return_availability_to_hospital(mc_hospital, patient_id, medicine_name, availability, signature)
print("Waiting for 30 seconds...")
time.sleep(30)


# Calculate throughput for each type of transaction
total_time = time.time() - start_time
total_transactions = sum(transaction_count.values())

print("\nTransaction Counts:")
for key, value in transaction_count.items():
    print(f"{key}: {value}")

print("\nTotal Execution Time:", total_time)
print("Total Transactions:", total_transactions)
print("Average Throughput (transactions per second):", total_transactions / total_time)
# Calculate and display averages
average_proof_verification_time = total_proof_verification_time / proof_verification_count
average_publish_time = total_publish_time / publish_count
print(f"\nAverage proof verification time: {average_proof_verification_time} seconds")
print(f"Average publish time: {average_publish_time} seconds")

# Calculate average delay between publishes
if publish_count > 1:
    average_delay = total_delay_between_publish / (publish_count - 1)
    print(f"Average delay between publishes: {average_delay:.2f} seconds")
else:
    print("Insufficient data to calculate average delay.")



