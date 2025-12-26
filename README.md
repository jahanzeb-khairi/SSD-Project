# The VAULT - Secure Password Manager

## 📌 Project Overview


**The VAULT** is an offline, **desktop-based secure password manager** built using **C++/CLI** and **.NET Framework.** It was developed as a final project for the **Secure Software Design** course at **FAST-NU**.



The application moves beyond simple text storage by implementing a **cryptographically secure model** using industry-standard algorithms to mitigate threats such as brute-force and rainbow table attacks.

---

## 🚀 Key Features

**Secure User Authentication:** Login and Sign-up functionality using hashed credentials.


**Encrypted Vault:** Securely Add, View, Update, and Delete passwords.



**Password Strength Checker:** Real-time analysis of password complexity (Length, Case, Digits, Symbols).


**Session Timeout:** Automatic session expiration after 5 minutes (300 seconds) of inactivity to prevent unauthorized access (Source: MyForm.h).


**GUI Dashboard:** A user-friendly Windows Forms interface.

---

## 🛡️ Security Architecture
This project implements a multi-layered security approach:


**Hashing:** Passwords are hashed using **SHA-256**.


**Salting:** A unique **16-byte random salt** is generated for every user to prevent rainbow table attacks.


**Peppering:** A system-wide secret key (**pepper.txt**) is added to the password-salt combination before hashing, protecting against database breaches where the attacker lacks access to the file system.



**Encryption:** Vault data is encrypted using **AES-256-CBC (Advanced Encryption Standard in Cipher Block Chaining mode)**.

**Key Derivation (PBKDF2):** The AES encryption key and IV are derived using **Rfc2898DeriveBytes (PBKDF2)** using the Pepper + Username + Salt (**Source: MyForm.h**).

**Constant-Time Comparison:** Login verification uses constant-time string comparison to mitigate timing attacks (**Source: MyForm.h**).

---

## 🛠️ Technology Stack

**Language:** C++/CLI (Common Language Infrastructure) 


**Framework:** .NET Framework (Windows Forms Application) 


**IDE:** Microsoft Visual Studio 


**Libraries:** System::Security::Cryptography, System::IO, System::Windows::Forms 
 
 ---

## ⚙️ Installation & Setup
**To run this project, you must have Microsoft Visual Studio installed with C++/CLI support.**

 ---

## ⚠️ Critical Configuration (Required Files)
For the application to function correctly, the following text files must exist in the root executable directory (usually Debug or Release folder inside the project):

1. **pepper.txt:** You must create a file named pepper.txt containing the secret key. The application will halt if this file is missing or empty. Create pepper.txt and paste the following content inside as Plaintext: **mySuperSecretPepper!@#2025**

2. **Database Files:** The application relies on local text files to simulate a database. While the application attempts to append to these files during "**Sign Up,**" it is recommended to create them manually to ensure permissions are correct and to prevent "File Not Found" errors during the initial Login attempt. A **usernames.txt** that Stores the list of registered usernames and **passwords.txt** that Stores the Salt:Hash combinations.

---

## How to Run
Clone the repository.

Open the solution in Visual Studio.

Ensure the .txt files described above are created in the project directory.

Build and Run (Ctrl + F5).

---

## 👥 Contributors

**Jahanzeb Khairi**

**Syed Muhammad Murtaza Rizvi**  

**Muhammad Yahya Khan** 

**Instructor: Ms. Abeer Gauhar**

---

## 📄 License & Disclaimer
This project was created for educational purposes for the **Secure Software Design** course at the **National University of Computer & Emerging Sciences, Karachi Campus**. It utilizes standard cryptographic libraries but should be audited before use in a production environment.