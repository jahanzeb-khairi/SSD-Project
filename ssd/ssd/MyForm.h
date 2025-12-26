#include <iostream>
#include <fstream>	

//using namespace std;


#pragma once

namespace ssd {

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;

	using namespace System;
	using namespace System::IO;
	using namespace System::Text;
	using namespace System::Security::Cryptography;
	using namespace System::Collections::Generic;

	/// <summary>
	/// Summary for MyForm
	/// </summary>
	public ref class MyForm : public System::Windows::Forms::Form
	{
		// ---------- Begin security helpers ----------
	private:
		// Read pepper from pepper.txt (must exist in program directory)
		String^ GetPepper()
		{
			String^ path = "pepper.txt";

			if (!File::Exists(path)) {
				MessageBox::Show("pepper.txt not found!", "Error",
					MessageBoxButtons::OK, MessageBoxIcon::Error);
				return "";
			}

			String^ pepper = File::ReadAllText(path)->Trim();
			if (String::IsNullOrWhiteSpace(pepper)) {
				MessageBox::Show("pepper.txt is empty!", "Error",
					MessageBoxButtons::OK, MessageBoxIcon::Error);
				return "";
			}
			return pepper;
		}

		// Generate cryptographically secure random salt (16 bytes). Return base64.
		String^ GenerateSaltBase64(int bytes)
		{
			if (bytes <= 0) bytes = 16;  // simulate default argument

			array<Byte>^ salt = gcnew array<Byte>(bytes);
			RandomNumberGenerator::Create()->GetBytes(salt);

			return Convert::ToBase64String(salt);
		}

		// Compute SHA256 of: salt + password + pepper (all as UTF8). Return base64.
		String^ ComputeSHA256_Base64(String^ saltBase64, String^ password, String^ pepper)
		{
			array<Byte>^ salt = Convert::FromBase64String(saltBase64);
			array<Byte>^ passBytes = Encoding::UTF8->GetBytes(password);
			array<Byte>^ pepBytes = Encoding::UTF8->GetBytes(pepper);

			array<Byte>^ total = gcnew array<Byte>(salt->Length + passBytes->Length + pepBytes->Length);

			Buffer::BlockCopy(salt, 0, total, 0, salt->Length);
			Buffer::BlockCopy(passBytes, 0, total, salt->Length, passBytes->Length);
			Buffer::BlockCopy(pepBytes, 0, total, salt->Length + passBytes->Length, pepBytes->Length);

			SHA256^ sha = SHA256::Create();
			array<Byte>^ hash = sha->ComputeHash(total);

			return Convert::ToBase64String(hash);
		}

		// Constant-time comparison for base64 strings (compares raw bytes)
		bool ConstantTimeEqualsBase64(String^ aBase64, String^ bBase64) {
			array<Byte>^ a = Convert::FromBase64String(aBase64);
			array<Byte>^ b = Convert::FromBase64String(bBase64);
			if (a->Length != b->Length) return false;
			unsigned int diff = 0;
			for (int i = 0; i < a->Length; ++i) diff |= a[i] ^ b[i];
			return diff == 0;
		}

		// AES encrypt plain text and write to filename (AES-256-CBC). Key derived from pepper+username with PBKDF2.
		void AESEncryptToFile(String^ filename, String^ plaintext, String^ username)
		{
			String^ pepper = GetPepper();

			// --- SAFE SALT GENERATION (username → 16-byte salt) ---
			array<Byte>^ nameBytes = Encoding::UTF8->GetBytes(username);
			SHA256^ sha = SHA256::Create();
			array<Byte>^ fullHash = sha->ComputeHash(nameBytes);

			// First 16 bytes = salt
			array<Byte>^ salt = gcnew array<Byte>(16);
			Array::Copy(fullHash, salt, 16);

			// --- PBKDF2 (always safe now) ---
			Rfc2898DeriveBytes^ kdf = gcnew Rfc2898DeriveBytes(pepper, salt, 100000);
			array<Byte>^ key = kdf->GetBytes(32);  // AES-256 key
			array<Byte>^ iv = kdf->GetBytes(16);  // AES-CBC IV

			Aes^ aes = Aes::Create();
			aes->Key = key;
			aes->IV = iv;
			aes->Mode = CipherMode::CBC;
			aes->Padding = PaddingMode::PKCS7;

			array<Byte>^ plainBytes = Encoding::UTF8->GetBytes(plaintext);
			ICryptoTransform^ enc = aes->CreateEncryptor();

			MemoryStream^ ms = gcnew MemoryStream();
			CryptoStream^ cs = gcnew CryptoStream(ms, enc, CryptoStreamMode::Write);
			cs->Write(plainBytes, 0, plainBytes->Length);
			cs->FlushFinalBlock();

			File::WriteAllText(filename, Convert::ToBase64String(ms->ToArray()));
		}


		// AES decrypt file and return plaintext (returns empty string if file missing)
		String^ AESDecryptFromFile(String^ filename, String^ username)
		{
			if (!File::Exists(filename)) return "";

			String^ pepper = GetPepper();
			String^ base64 = File::ReadAllText(filename);
			if (String::IsNullOrEmpty(base64)) return "";

			array<Byte>^ cipher = Convert::FromBase64String(base64);

			// --- FIXED: Use same salt derivation as encryption ---
			array<Byte>^ nameBytes = Encoding::UTF8->GetBytes(username);
			SHA256^ sha = SHA256::Create();
			array<Byte>^ fullHash = sha->ComputeHash(nameBytes);

			// First 16 bytes = salt (same as encryption)
			array<Byte>^ salt = gcnew array<Byte>(16);
			Array::Copy(fullHash, salt, 16);
			// --- End fix ---

			Rfc2898DeriveBytes^ kdf = gcnew Rfc2898DeriveBytes(pepper, salt, 100000);

			array<Byte>^ key = kdf->GetBytes(32);
			array<Byte>^ iv = kdf->GetBytes(16);

			Aes^ aes = Aes::Create();
			aes->Key = key;
			aes->IV = iv;
			aes->Mode = CipherMode::CBC;
			aes->Padding = PaddingMode::PKCS7;

			MemoryStream^ ms = gcnew MemoryStream(cipher);
			ICryptoTransform^ dec = aes->CreateDecryptor();
			CryptoStream^ cs = gcnew CryptoStream(ms, dec, CryptoStreamMode::Read);

			MemoryStream^ output = gcnew MemoryStream();
			array<Byte>^ buffer = gcnew array<Byte>(4096);
			int read = 0;

			while ((read = cs->Read(buffer, 0, buffer->Length)) > 0)
				output->Write(buffer, 0, read);

			return Encoding::UTF8->GetString(output->ToArray());
		}
		// ---------- End security helpers ----------


	private:
		System::Windows::Forms::Timer^ sessionTimer;
		int sessionSeconds;

	private: System::Void SessionTimer_Tick(System::Object^ sender, System::EventArgs^ e) {
		sessionSeconds++;
		// Timeout after 300 seconds (5 minutes)
		if (sessionSeconds >= 300) {
			sessionTimer->Stop();
			// Hide the dashboard panel
			pnlTest->Hide();
			pnlPaas->Hide();
			pnlDash->Hide();
			pnlTerm->Hide();
			pnlSign->Hide();
			MessageBox::Show("Session expired due to inactivity.\nPlease log in again.",
				"Session Timeout",
				MessageBoxButtons::OK,
				MessageBoxIcon::Warning);
		}
	}

	public:
		static String^ currentUser = nullptr;

		MyForm(void)
		{
			InitializeComponent();
			pnlSign->Hide();
			pnlTerm->Hide();
			pnlDash->Hide();
			pnlPaas->Hide();
			pnlTest->Hide();
			//
			//TODO: Add the constructor code here
			//
			sessionTimer = gcnew System::Windows::Forms::Timer();
			sessionTimer->Interval = 1000; // 1 second
			sessionTimer->Tick += gcnew System::EventHandler(this, &MyForm::SessionTimer_Tick);
			sessionSeconds = 0;

		}

		void SetCurrentUser(String^ username) 
		{
			currentUser = username; // Assign logged-in username
		}

	protected:
		/// <summary>
		/// Clean up any resources being used.
		/// </summary>
		~MyForm()
		{
			if (components)
			{
				delete components;
			}
		}



	private: System::Windows::Forms::Label^ label1;
	private: System::Windows::Forms::Label^ label2;
	private: System::Windows::Forms::Label^ label3;
	private: System::Windows::Forms::Label^ label4;
	private: System::Windows::Forms::TextBox^ textBox1;
	private: System::Windows::Forms::Panel^ panel1;
	private: System::Windows::Forms::Panel^ panel2;
	private: System::Windows::Forms::TextBox^ textBox2;
	private: System::Windows::Forms::Button^ button1;
	private: System::Windows::Forms::Button^ button2;
	private: System::Windows::Forms::Button^ button3;
	private: System::Windows::Forms::Panel^ pnlSign;
	private: System::Windows::Forms::Button^ button4;
	private: System::Windows::Forms::Button^ button5;
	private: System::Windows::Forms::Panel^ panel3;
	private: System::Windows::Forms::TextBox^ textBox3;
	private: System::Windows::Forms::Panel^ panel4;
	private: System::Windows::Forms::TextBox^ textBox4;
	private: System::Windows::Forms::Label^ label5;
	private: System::Windows::Forms::Label^ label6;
	private: System::Windows::Forms::Label^ label7;
	private: System::Windows::Forms::Label^ label8;
	private: System::Windows::Forms::CheckBox^ checkBox1;
	private: System::Windows::Forms::Button^ button6;
	private: System::Windows::Forms::Panel^ pnlTerm;
	private: System::Windows::Forms::Label^ label9;
	private: System::Windows::Forms::Label^ label10;
	private: System::Windows::Forms::Button^ button7;
	private: System::Windows::Forms::Button^ button8;
	private: System::Windows::Forms::Panel^ pnlDash;
	private: System::Windows::Forms::Label^ label11;
	private: System::Windows::Forms::Label^ label12;
	private: System::Windows::Forms::Button^ button10;
	private: System::Windows::Forms::Button^ button9;
	private: System::Windows::Forms::Button^ button11;
	private: System::Windows::Forms::Button^ button13;
	private: System::Windows::Forms::Panel^ panel7;
	private: System::Windows::Forms::TextBox^ textBox7;
	private: System::Windows::Forms::Label^ label15;
	private: System::Windows::Forms::Button^ button12;
	private: System::Windows::Forms::Panel^ panel5;
	private: System::Windows::Forms::TextBox^ textBox5;
	private: System::Windows::Forms::Panel^ panel6;
	private: System::Windows::Forms::TextBox^ textBox6;
	private: System::Windows::Forms::Label^ label13;
	private: System::Windows::Forms::Label^ label14;
	private: System::Windows::Forms::Button^ button14;
	private: System::Windows::Forms::Panel^ panel8;
	private: System::Windows::Forms::TextBox^ textBox8;
	private: System::Windows::Forms::Label^ label16;
	private: System::Windows::Forms::Label^ label17;
	private: System::Windows::Forms::Panel^ pnlPaas;

	private: System::Windows::Forms::Button^ button15;
	private: System::Windows::Forms::TextBox^ textBox9;
	private: System::Windows::Forms::Panel^ panel9;
	private: System::Windows::Forms::TextBox^ textBox10;
	private: System::Windows::Forms::Label^ label18;
	private: System::Windows::Forms::Panel^ pnlTest;
	private: System::Windows::Forms::TextBox^ textBox11;
	private: System::Windows::Forms::Button^ button16;


	protected:

	protected:

	private:
		/// <summary>
		/// Required designer variable.
		/// </summary>
		System::ComponentModel::Container ^components;

#pragma region Windows Form Designer generated code
		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
		void InitializeComponent(void)
		{
			System::ComponentModel::ComponentResourceManager^ resources = (gcnew System::ComponentModel::ComponentResourceManager(MyForm::typeid));
			this->label1 = (gcnew System::Windows::Forms::Label());
			this->label2 = (gcnew System::Windows::Forms::Label());
			this->label3 = (gcnew System::Windows::Forms::Label());
			this->label4 = (gcnew System::Windows::Forms::Label());
			this->textBox1 = (gcnew System::Windows::Forms::TextBox());
			this->panel1 = (gcnew System::Windows::Forms::Panel());
			this->panel2 = (gcnew System::Windows::Forms::Panel());
			this->textBox2 = (gcnew System::Windows::Forms::TextBox());
			this->button1 = (gcnew System::Windows::Forms::Button());
			this->button2 = (gcnew System::Windows::Forms::Button());
			this->button3 = (gcnew System::Windows::Forms::Button());
			this->pnlSign = (gcnew System::Windows::Forms::Panel());
			this->pnlTerm = (gcnew System::Windows::Forms::Panel());
			this->pnlDash = (gcnew System::Windows::Forms::Panel());
			this->pnlTest = (gcnew System::Windows::Forms::Panel());
			this->textBox11 = (gcnew System::Windows::Forms::TextBox());
			this->button16 = (gcnew System::Windows::Forms::Button());
			this->pnlPaas = (gcnew System::Windows::Forms::Panel());
			this->textBox9 = (gcnew System::Windows::Forms::TextBox());
			this->button15 = (gcnew System::Windows::Forms::Button());
			this->panel9 = (gcnew System::Windows::Forms::Panel());
			this->textBox10 = (gcnew System::Windows::Forms::TextBox());
			this->label18 = (gcnew System::Windows::Forms::Label());
			this->label17 = (gcnew System::Windows::Forms::Label());
			this->button14 = (gcnew System::Windows::Forms::Button());
			this->panel8 = (gcnew System::Windows::Forms::Panel());
			this->textBox8 = (gcnew System::Windows::Forms::TextBox());
			this->label16 = (gcnew System::Windows::Forms::Label());
			this->button13 = (gcnew System::Windows::Forms::Button());
			this->panel7 = (gcnew System::Windows::Forms::Panel());
			this->textBox7 = (gcnew System::Windows::Forms::TextBox());
			this->label15 = (gcnew System::Windows::Forms::Label());
			this->button12 = (gcnew System::Windows::Forms::Button());
			this->panel5 = (gcnew System::Windows::Forms::Panel());
			this->textBox5 = (gcnew System::Windows::Forms::TextBox());
			this->panel6 = (gcnew System::Windows::Forms::Panel());
			this->textBox6 = (gcnew System::Windows::Forms::TextBox());
			this->label13 = (gcnew System::Windows::Forms::Label());
			this->label14 = (gcnew System::Windows::Forms::Label());
			this->button11 = (gcnew System::Windows::Forms::Button());
			this->button10 = (gcnew System::Windows::Forms::Button());
			this->button9 = (gcnew System::Windows::Forms::Button());
			this->label12 = (gcnew System::Windows::Forms::Label());
			this->label11 = (gcnew System::Windows::Forms::Label());
			this->button8 = (gcnew System::Windows::Forms::Button());
			this->button7 = (gcnew System::Windows::Forms::Button());
			this->label10 = (gcnew System::Windows::Forms::Label());
			this->label9 = (gcnew System::Windows::Forms::Label());
			this->button6 = (gcnew System::Windows::Forms::Button());
			this->label8 = (gcnew System::Windows::Forms::Label());
			this->checkBox1 = (gcnew System::Windows::Forms::CheckBox());
			this->button4 = (gcnew System::Windows::Forms::Button());
			this->button5 = (gcnew System::Windows::Forms::Button());
			this->panel3 = (gcnew System::Windows::Forms::Panel());
			this->textBox3 = (gcnew System::Windows::Forms::TextBox());
			this->panel4 = (gcnew System::Windows::Forms::Panel());
			this->textBox4 = (gcnew System::Windows::Forms::TextBox());
			this->label5 = (gcnew System::Windows::Forms::Label());
			this->label6 = (gcnew System::Windows::Forms::Label());
			this->label7 = (gcnew System::Windows::Forms::Label());
			this->pnlSign->SuspendLayout();
			this->pnlTerm->SuspendLayout();
			this->pnlDash->SuspendLayout();
			this->pnlTest->SuspendLayout();
			this->pnlPaas->SuspendLayout();
			this->SuspendLayout();
			// 
			// label1
			// 
			this->label1->AutoSize = true;
			this->label1->BackColor = System::Drawing::Color::Black;
			this->label1->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 72, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label1->ForeColor = System::Drawing::Color::White;
			this->label1->Location = System::Drawing::Point(1, 9);
			this->label1->Name = L"label1";
			this->label1->Size = System::Drawing::Size(605, 159);
			this->label1->TabIndex = 0;
			this->label1->Text = L"The VAULT";
			this->label1->Click += gcnew System::EventHandler(this, &MyForm::label1_Click_1);
			// 
			// label2
			// 
			this->label2->AutoSize = true;
			this->label2->BackColor = System::Drawing::SystemColors::Desktop;
			this->label2->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 36, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label2->ForeColor = System::Drawing::Color::White;
			this->label2->Location = System::Drawing::Point(182, 215);
			this->label2->Name = L"label2";
			this->label2->Size = System::Drawing::Size(192, 81);
			this->label2->TabIndex = 1;
			this->label2->Text = L"Log In";
			// 
			// label3
			// 
			this->label3->AutoSize = true;
			this->label3->BackColor = System::Drawing::SystemColors::Desktop;
			this->label3->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 14));
			this->label3->ForeColor = System::Drawing::Color::White;
			this->label3->Location = System::Drawing::Point(22, 338);
			this->label3->Name = L"label3";
			this->label3->Size = System::Drawing::Size(116, 32);
			this->label3->TabIndex = 2;
			this->label3->Text = L"Username";
			// 
			// label4
			// 
			this->label4->AutoSize = true;
			this->label4->BackColor = System::Drawing::SystemColors::Desktop;
			this->label4->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 14));
			this->label4->ForeColor = System::Drawing::Color::White;
			this->label4->Location = System::Drawing::Point(22, 436);
			this->label4->Name = L"label4";
			this->label4->Size = System::Drawing::Size(106, 32);
			this->label4->TabIndex = 3;
			this->label4->Text = L"Password";
			this->label4->Click += gcnew System::EventHandler(this, &MyForm::label4_Click);
			// 
			// textBox1
			// 
			this->textBox1->BackColor = System::Drawing::Color::Black;
			this->textBox1->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->textBox1->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 10.2F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->textBox1->ForeColor = System::Drawing::Color::White;
			this->textBox1->Location = System::Drawing::Point(28, 382);
			this->textBox1->Name = L"textBox1";
			this->textBox1->Size = System::Drawing::Size(287, 23);
			this->textBox1->TabIndex = 4;
			// 
			// panel1
			// 
			this->panel1->Location = System::Drawing::Point(28, 411);
			this->panel1->Name = L"panel1";
			this->panel1->Size = System::Drawing::Size(287, 2);
			this->panel1->TabIndex = 5;
			// 
			// panel2
			// 
			this->panel2->Location = System::Drawing::Point(28, 510);
			this->panel2->Name = L"panel2";
			this->panel2->Size = System::Drawing::Size(287, 2);
			this->panel2->TabIndex = 7;
			// 
			// textBox2
			// 
			this->textBox2->BackColor = System::Drawing::Color::Black;
			this->textBox2->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->textBox2->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 10.2F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->textBox2->ForeColor = System::Drawing::Color::White;
			this->textBox2->Location = System::Drawing::Point(28, 481);
			this->textBox2->Name = L"textBox2";
			this->textBox2->Size = System::Drawing::Size(287, 23);
			this->textBox2->TabIndex = 6;
			this->textBox2->UseSystemPasswordChar = true;
			// 
			// button1
			// 
			this->button1->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(64)), static_cast<System::Int32>(static_cast<System::Byte>(64)),
				static_cast<System::Int32>(static_cast<System::Byte>(64)));
			this->button1->FlatAppearance->BorderSize = 0;
			this->button1->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->button1->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 14));
			this->button1->ForeColor = System::Drawing::Color::Black;
			this->button1->Location = System::Drawing::Point(28, 552);
			this->button1->Name = L"button1";
			this->button1->Size = System::Drawing::Size(133, 39);
			this->button1->TabIndex = 8;
			this->button1->Text = L"Log In";
			this->button1->UseVisualStyleBackColor = false;
			this->button1->Click += gcnew System::EventHandler(this, &MyForm::button1_Click);
			// 
			// button2
			// 
			this->button2->BackColor = System::Drawing::Color::Black;
			this->button2->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->button2->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 14));
			this->button2->ForeColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(64)), static_cast<System::Int32>(static_cast<System::Byte>(64)),
				static_cast<System::Int32>(static_cast<System::Byte>(64)));
			this->button2->Location = System::Drawing::Point(167, 552);
			this->button2->Name = L"button2";
			this->button2->Size = System::Drawing::Size(142, 39);
			this->button2->TabIndex = 9;
			this->button2->Text = L"Sign Up";
			this->button2->UseVisualStyleBackColor = false;
			this->button2->Click += gcnew System::EventHandler(this, &MyForm::button2_Click);
			// 
			// button3
			// 
			this->button3->BackColor = System::Drawing::Color::Black;
			this->button3->FlatAppearance->BorderSize = 0;
			this->button3->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->button3->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 14));
			this->button3->ForeColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(64)), static_cast<System::Int32>(static_cast<System::Byte>(64)),
				static_cast<System::Int32>(static_cast<System::Byte>(64)));
			this->button3->Location = System::Drawing::Point(1220, 12);
			this->button3->Name = L"button3";
			this->button3->Size = System::Drawing::Size(37, 39);
			this->button3->TabIndex = 10;
			this->button3->Text = L"X";
			this->button3->UseVisualStyleBackColor = false;
			this->button3->Click += gcnew System::EventHandler(this, &MyForm::button3_Click);
			// 
			// pnlSign
			// 
			this->pnlSign->BackgroundImage = (cli::safe_cast<System::Drawing::Image^>(resources->GetObject(L"pnlSign.BackgroundImage")));
			this->pnlSign->Controls->Add(this->pnlTerm);
			this->pnlSign->Controls->Add(this->button6);
			this->pnlSign->Controls->Add(this->label8);
			this->pnlSign->Controls->Add(this->checkBox1);
			this->pnlSign->Controls->Add(this->button4);
			this->pnlSign->Controls->Add(this->button5);
			this->pnlSign->Controls->Add(this->panel3);
			this->pnlSign->Controls->Add(this->textBox3);
			this->pnlSign->Controls->Add(this->panel4);
			this->pnlSign->Controls->Add(this->textBox4);
			this->pnlSign->Controls->Add(this->label5);
			this->pnlSign->Controls->Add(this->label6);
			this->pnlSign->Controls->Add(this->label7);
			this->pnlSign->Dock = System::Windows::Forms::DockStyle::Fill;
			this->pnlSign->Location = System::Drawing::Point(0, 0);
			this->pnlSign->Name = L"pnlSign";
			this->pnlSign->Size = System::Drawing::Size(1269, 757);
			this->pnlSign->TabIndex = 11;
			this->pnlSign->MouseDown += gcnew System::Windows::Forms::MouseEventHandler(this, &MyForm::MyForm_MouseDown);
			this->pnlSign->MouseMove += gcnew System::Windows::Forms::MouseEventHandler(this, &MyForm::MyForm_MouseMove);
			this->pnlSign->MouseUp += gcnew System::Windows::Forms::MouseEventHandler(this, &MyForm::MyForm_MouseUp);
			// 
			// pnlTerm
			// 
			this->pnlTerm->BackgroundImage = (cli::safe_cast<System::Drawing::Image^>(resources->GetObject(L"pnlTerm.BackgroundImage")));
			this->pnlTerm->Controls->Add(this->pnlDash);
			this->pnlTerm->Controls->Add(this->button8);
			this->pnlTerm->Controls->Add(this->button7);
			this->pnlTerm->Controls->Add(this->label10);
			this->pnlTerm->Controls->Add(this->label9);
			this->pnlTerm->Dock = System::Windows::Forms::DockStyle::Fill;
			this->pnlTerm->Location = System::Drawing::Point(0, 0);
			this->pnlTerm->Name = L"pnlTerm";
			this->pnlTerm->Size = System::Drawing::Size(1269, 757);
			this->pnlTerm->TabIndex = 22;
			this->pnlTerm->MouseDown += gcnew System::Windows::Forms::MouseEventHandler(this, &MyForm::MyForm_MouseDown);
			this->pnlTerm->MouseMove += gcnew System::Windows::Forms::MouseEventHandler(this, &MyForm::MyForm_MouseMove);
			this->pnlTerm->MouseUp += gcnew System::Windows::Forms::MouseEventHandler(this, &MyForm::MyForm_MouseUp);
			// 
			// pnlDash
			// 
			this->pnlDash->BackgroundImage = (cli::safe_cast<System::Drawing::Image^>(resources->GetObject(L"pnlDash.BackgroundImage")));
			this->pnlDash->Controls->Add(this->pnlTest);
			this->pnlDash->Controls->Add(this->pnlPaas);
			this->pnlDash->Controls->Add(this->panel9);
			this->pnlDash->Controls->Add(this->textBox10);
			this->pnlDash->Controls->Add(this->label18);
			this->pnlDash->Controls->Add(this->label17);
			this->pnlDash->Controls->Add(this->button14);
			this->pnlDash->Controls->Add(this->panel8);
			this->pnlDash->Controls->Add(this->textBox8);
			this->pnlDash->Controls->Add(this->label16);
			this->pnlDash->Controls->Add(this->button13);
			this->pnlDash->Controls->Add(this->panel7);
			this->pnlDash->Controls->Add(this->textBox7);
			this->pnlDash->Controls->Add(this->label15);
			this->pnlDash->Controls->Add(this->button12);
			this->pnlDash->Controls->Add(this->panel5);
			this->pnlDash->Controls->Add(this->textBox5);
			this->pnlDash->Controls->Add(this->panel6);
			this->pnlDash->Controls->Add(this->textBox6);
			this->pnlDash->Controls->Add(this->label13);
			this->pnlDash->Controls->Add(this->label14);
			this->pnlDash->Controls->Add(this->button11);
			this->pnlDash->Controls->Add(this->button10);
			this->pnlDash->Controls->Add(this->button9);
			this->pnlDash->Controls->Add(this->label12);
			this->pnlDash->Controls->Add(this->label11);
			this->pnlDash->Dock = System::Windows::Forms::DockStyle::Fill;
			this->pnlDash->Location = System::Drawing::Point(0, 0);
			this->pnlDash->Name = L"pnlDash";
			this->pnlDash->Size = System::Drawing::Size(1269, 757);
			this->pnlDash->TabIndex = 23;
			this->pnlDash->Paint += gcnew System::Windows::Forms::PaintEventHandler(this, &MyForm::pnlDash_Paint);
			this->pnlDash->MouseDown += gcnew System::Windows::Forms::MouseEventHandler(this, &MyForm::MyForm_MouseDown);
			this->pnlDash->MouseMove += gcnew System::Windows::Forms::MouseEventHandler(this, &MyForm::MyForm_MouseMove);
			this->pnlDash->MouseUp += gcnew System::Windows::Forms::MouseEventHandler(this, &MyForm::MyForm_MouseUp);
			// 
			// pnlTest
			// 
			this->pnlTest->BackColor = System::Drawing::Color::MediumOrchid;
			this->pnlTest->Controls->Add(this->textBox11);
			this->pnlTest->Controls->Add(this->button16);
			this->pnlTest->Location = System::Drawing::Point(353, 140);
			this->pnlTest->Name = L"pnlTest";
			this->pnlTest->Size = System::Drawing::Size(810, 556);
			this->pnlTest->TabIndex = 46;
			// 
			// textBox11
			// 
			this->textBox11->BackColor = System::Drawing::Color::DarkOrchid;
			this->textBox11->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->textBox11->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 12, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->textBox11->Location = System::Drawing::Point(52, 36);
			this->textBox11->Multiline = true;
			this->textBox11->Name = L"textBox11";
			this->textBox11->ReadOnly = true;
			this->textBox11->ScrollBars = System::Windows::Forms::ScrollBars::Vertical;
			this->textBox11->Size = System::Drawing::Size(712, 482);
			this->textBox11->TabIndex = 25;
			// 
			// button16
			// 
			this->button16->BackColor = System::Drawing::Color::MediumOrchid;
			this->button16->FlatAppearance->BorderSize = 0;
			this->button16->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->button16->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 14));
			this->button16->ForeColor = System::Drawing::Color::Black;
			this->button16->Location = System::Drawing::Point(770, 8);
			this->button16->Name = L"button16";
			this->button16->Size = System::Drawing::Size(37, 39);
			this->button16->TabIndex = 24;
			this->button16->Text = L"X";
			this->button16->UseVisualStyleBackColor = false;
			this->button16->Click += gcnew System::EventHandler(this, &MyForm::button16_Click);
			// 
			// pnlPaas
			// 
			this->pnlPaas->BackColor = System::Drawing::Color::MediumOrchid;
			this->pnlPaas->Controls->Add(this->textBox9);
			this->pnlPaas->Controls->Add(this->button15);
			this->pnlPaas->Location = System::Drawing::Point(356, 140);
			this->pnlPaas->Name = L"pnlPaas";
			this->pnlPaas->Size = System::Drawing::Size(810, 556);
			this->pnlPaas->TabIndex = 42;
			// 
			// textBox9
			// 
			this->textBox9->BackColor = System::Drawing::Color::DarkOrchid;
			this->textBox9->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->textBox9->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 12, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->textBox9->Location = System::Drawing::Point(52, 36);
			this->textBox9->Multiline = true;
			this->textBox9->Name = L"textBox9";
			this->textBox9->ReadOnly = true;
			this->textBox9->ScrollBars = System::Windows::Forms::ScrollBars::Vertical;
			this->textBox9->Size = System::Drawing::Size(712, 482);
			this->textBox9->TabIndex = 25;
			// 
			// button15
			// 
			this->button15->BackColor = System::Drawing::Color::MediumOrchid;
			this->button15->FlatAppearance->BorderSize = 0;
			this->button15->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->button15->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 14));
			this->button15->ForeColor = System::Drawing::Color::Black;
			this->button15->Location = System::Drawing::Point(770, 8);
			this->button15->Name = L"button15";
			this->button15->Size = System::Drawing::Size(37, 39);
			this->button15->TabIndex = 24;
			this->button15->Text = L"X";
			this->button15->UseVisualStyleBackColor = false;
			this->button15->Click += gcnew System::EventHandler(this, &MyForm::button15_Click);
			// 
			// panel9
			// 
			this->panel9->Location = System::Drawing::Point(402, 592);
			this->panel9->Name = L"panel9";
			this->panel9->Size = System::Drawing::Size(287, 2);
			this->panel9->TabIndex = 45;
			// 
			// textBox10
			// 
			this->textBox10->BackColor = System::Drawing::Color::Black;
			this->textBox10->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->textBox10->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 10.2F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->textBox10->ForeColor = System::Drawing::Color::White;
			this->textBox10->Location = System::Drawing::Point(402, 563);
			this->textBox10->Name = L"textBox10";
			this->textBox10->Size = System::Drawing::Size(287, 23);
			this->textBox10->TabIndex = 44;
			// 
			// label18
			// 
			this->label18->AutoSize = true;
			this->label18->BackColor = System::Drawing::SystemColors::Desktop;
			this->label18->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 14));
			this->label18->ForeColor = System::Drawing::Color::White;
			this->label18->Location = System::Drawing::Point(396, 518);
			this->label18->Name = L"label18";
			this->label18->Size = System::Drawing::Size(176, 32);
			this->label18->TabIndex = 43;
			this->label18->Text = L"Password to Test";
			// 
			// label17
			// 
			this->label17->AutoSize = true;
			this->label17->BackColor = System::Drawing::Color::MediumOrchid;
			this->label17->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 36, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label17->ForeColor = System::Drawing::Color::White;
			this->label17->Location = System::Drawing::Point(46, 140);
			this->label17->Name = L"label17";
			this->label17->Size = System::Drawing::Size(269, 81);
			this->label17->TabIndex = 41;
			this->label17->Text = L"Welcome";
			// 
			// button14
			// 
			this->button14->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(64)), static_cast<System::Int32>(static_cast<System::Byte>(64)),
				static_cast<System::Int32>(static_cast<System::Byte>(64)));
			this->button14->FlatAppearance->BorderSize = 0;
			this->button14->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->button14->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 14));
			this->button14->ForeColor = System::Drawing::Color::Black;
			this->button14->Location = System::Drawing::Point(858, 437);
			this->button14->Name = L"button14";
			this->button14->Size = System::Drawing::Size(257, 39);
			this->button14->TabIndex = 40;
			this->button14->Text = L"Add Password";
			this->button14->UseVisualStyleBackColor = false;
			this->button14->Click += gcnew System::EventHandler(this, &MyForm::button14_Click);
			// 
			// panel8
			// 
			this->panel8->Location = System::Drawing::Point(842, 400);
			this->panel8->Name = L"panel8";
			this->panel8->Size = System::Drawing::Size(287, 2);
			this->panel8->TabIndex = 39;
			// 
			// textBox8
			// 
			this->textBox8->BackColor = System::Drawing::Color::Black;
			this->textBox8->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->textBox8->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 10.2F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->textBox8->ForeColor = System::Drawing::Color::White;
			this->textBox8->Location = System::Drawing::Point(842, 371);
			this->textBox8->Name = L"textBox8";
			this->textBox8->Size = System::Drawing::Size(287, 23);
			this->textBox8->TabIndex = 38;
			// 
			// label16
			// 
			this->label16->AutoSize = true;
			this->label16->BackColor = System::Drawing::SystemColors::Desktop;
			this->label16->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 14));
			this->label16->ForeColor = System::Drawing::Color::White;
			this->label16->Location = System::Drawing::Point(836, 327);
			this->label16->Name = L"label16";
			this->label16->Size = System::Drawing::Size(206, 32);
			this->label16->TabIndex = 37;
			this->label16->Text = L"Add New Password";
			// 
			// button13
			// 
			this->button13->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(64)), static_cast<System::Int32>(static_cast<System::Byte>(64)),
				static_cast<System::Int32>(static_cast<System::Byte>(64)));
			this->button13->FlatAppearance->BorderSize = 0;
			this->button13->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->button13->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 14));
			this->button13->ForeColor = System::Drawing::Color::Black;
			this->button13->Location = System::Drawing::Point(858, 631);
			this->button13->Name = L"button13";
			this->button13->Size = System::Drawing::Size(257, 39);
			this->button13->TabIndex = 36;
			this->button13->Text = L"Delete Password";
			this->button13->UseVisualStyleBackColor = false;
			this->button13->Click += gcnew System::EventHandler(this, &MyForm::button13_Click);
			// 
			// panel7
			// 
			this->panel7->Location = System::Drawing::Point(842, 594);
			this->panel7->Name = L"panel7";
			this->panel7->Size = System::Drawing::Size(287, 2);
			this->panel7->TabIndex = 35;
			// 
			// textBox7
			// 
			this->textBox7->BackColor = System::Drawing::Color::Black;
			this->textBox7->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->textBox7->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 10.2F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->textBox7->ForeColor = System::Drawing::Color::White;
			this->textBox7->Location = System::Drawing::Point(842, 565);
			this->textBox7->Name = L"textBox7";
			this->textBox7->Size = System::Drawing::Size(287, 23);
			this->textBox7->TabIndex = 34;
			// 
			// label15
			// 
			this->label15->AutoSize = true;
			this->label15->BackColor = System::Drawing::SystemColors::Desktop;
			this->label15->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 14));
			this->label15->ForeColor = System::Drawing::Color::White;
			this->label15->Location = System::Drawing::Point(836, 520);
			this->label15->Name = L"label15";
			this->label15->Size = System::Drawing::Size(204, 32);
			this->label15->TabIndex = 33;
			this->label15->Text = L"Password to Delete";
			// 
			// button12
			// 
			this->button12->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(64)), static_cast<System::Int32>(static_cast<System::Byte>(64)),
				static_cast<System::Int32>(static_cast<System::Byte>(64)));
			this->button12->FlatAppearance->BorderSize = 0;
			this->button12->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->button12->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 14));
			this->button12->ForeColor = System::Drawing::Color::Black;
			this->button12->Location = System::Drawing::Point(418, 438);
			this->button12->Name = L"button12";
			this->button12->Size = System::Drawing::Size(257, 39);
			this->button12->TabIndex = 32;
			this->button12->Text = L"Update Password";
			this->button12->UseVisualStyleBackColor = false;
			this->button12->Click += gcnew System::EventHandler(this, &MyForm::button12_Click);
			// 
			// panel5
			// 
			this->panel5->Location = System::Drawing::Point(402, 401);
			this->panel5->Name = L"panel5";
			this->panel5->Size = System::Drawing::Size(287, 2);
			this->panel5->TabIndex = 31;
			// 
			// textBox5
			// 
			this->textBox5->BackColor = System::Drawing::Color::Black;
			this->textBox5->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->textBox5->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 10.2F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->textBox5->ForeColor = System::Drawing::Color::White;
			this->textBox5->Location = System::Drawing::Point(402, 372);
			this->textBox5->Name = L"textBox5";
			this->textBox5->Size = System::Drawing::Size(287, 23);
			this->textBox5->TabIndex = 30;
			// 
			// panel6
			// 
			this->panel6->Location = System::Drawing::Point(402, 302);
			this->panel6->Name = L"panel6";
			this->panel6->Size = System::Drawing::Size(287, 2);
			this->panel6->TabIndex = 29;
			// 
			// textBox6
			// 
			this->textBox6->BackColor = System::Drawing::Color::Black;
			this->textBox6->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->textBox6->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 10.2F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->textBox6->ForeColor = System::Drawing::Color::White;
			this->textBox6->Location = System::Drawing::Point(402, 273);
			this->textBox6->Name = L"textBox6";
			this->textBox6->Size = System::Drawing::Size(287, 23);
			this->textBox6->TabIndex = 28;
			// 
			// label13
			// 
			this->label13->AutoSize = true;
			this->label13->BackColor = System::Drawing::SystemColors::Desktop;
			this->label13->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 14));
			this->label13->ForeColor = System::Drawing::Color::White;
			this->label13->Location = System::Drawing::Point(396, 327);
			this->label13->Name = L"label13";
			this->label13->Size = System::Drawing::Size(158, 32);
			this->label13->TabIndex = 27;
			this->label13->Text = L"New Password";
			// 
			// label14
			// 
			this->label14->AutoSize = true;
			this->label14->BackColor = System::Drawing::SystemColors::Desktop;
			this->label14->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 14));
			this->label14->ForeColor = System::Drawing::Color::White;
			this->label14->Location = System::Drawing::Point(396, 229);
			this->label14->Name = L"label14";
			this->label14->Size = System::Drawing::Size(149, 32);
			this->label14->TabIndex = 26;
			this->label14->Text = L"Old Password";
			// 
			// button11
			// 
			this->button11->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(64)), static_cast<System::Int32>(static_cast<System::Byte>(64)),
				static_cast<System::Int32>(static_cast<System::Byte>(64)));
			this->button11->FlatAppearance->BorderSize = 0;
			this->button11->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->button11->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 14));
			this->button11->ForeColor = System::Drawing::Color::Black;
			this->button11->Location = System::Drawing::Point(418, 625);
			this->button11->Name = L"button11";
			this->button11->Size = System::Drawing::Size(257, 39);
			this->button11->TabIndex = 25;
			this->button11->Text = L"Test Strength";
			this->button11->UseVisualStyleBackColor = false;
			this->button11->Click += gcnew System::EventHandler(this, &MyForm::button11_Click);
			// 
			// button10
			// 
			this->button10->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(64)), static_cast<System::Int32>(static_cast<System::Byte>(64)),
				static_cast<System::Int32>(static_cast<System::Byte>(64)));
			this->button10->FlatAppearance->BorderSize = 0;
			this->button10->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->button10->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 14));
			this->button10->ForeColor = System::Drawing::Color::Black;
			this->button10->Location = System::Drawing::Point(858, 252);
			this->button10->Name = L"button10";
			this->button10->Size = System::Drawing::Size(257, 39);
			this->button10->TabIndex = 24;
			this->button10->Text = L"View Passwords";
			this->button10->UseVisualStyleBackColor = false;
			this->button10->Click += gcnew System::EventHandler(this, &MyForm::button10_Click);
			// 
			// button9
			// 
			this->button9->BackColor = System::Drawing::Color::Black;
			this->button9->FlatAppearance->BorderSize = 0;
			this->button9->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->button9->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 14));
			this->button9->ForeColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(64)), static_cast<System::Int32>(static_cast<System::Byte>(64)),
				static_cast<System::Int32>(static_cast<System::Byte>(64)));
			this->button9->Location = System::Drawing::Point(1220, 12);
			this->button9->Name = L"button9";
			this->button9->Size = System::Drawing::Size(37, 39);
			this->button9->TabIndex = 23;
			this->button9->Text = L"X";
			this->button9->UseVisualStyleBackColor = false;
			this->button9->Click += gcnew System::EventHandler(this, &MyForm::button9_Click);
			// 
			// label12
			// 
			this->label12->AutoSize = true;
			this->label12->BackColor = System::Drawing::Color::MediumOrchid;
			this->label12->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 36, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label12->ForeColor = System::Drawing::Color::White;
			this->label12->Location = System::Drawing::Point(93, 221);
			this->label12->Name = L"label12";
			this->label12->Size = System::Drawing::Size(160, 81);
			this->label12->TabIndex = 1;
			this->label12->Text = L"_____";
			this->label12->Click += gcnew System::EventHandler(this, &MyForm::label12_Click);
			// 
			// label11
			// 
			this->label11->AutoSize = true;
			this->label11->BackColor = System::Drawing::Color::Black;
			this->label11->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 36, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label11->ForeColor = System::Drawing::Color::White;
			this->label11->Location = System::Drawing::Point(404, 22);
			this->label11->Name = L"label11";
			this->label11->Size = System::Drawing::Size(487, 81);
			this->label11->TabIndex = 0;
			this->label11->Text = L"VAULT Dashboard";
			this->label11->Click += gcnew System::EventHandler(this, &MyForm::label11_Click);
			// 
			// button8
			// 
			this->button8->BackColor = System::Drawing::Color::Black;
			this->button8->FlatAppearance->BorderSize = 0;
			this->button8->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->button8->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 14));
			this->button8->ForeColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(64)), static_cast<System::Int32>(static_cast<System::Byte>(64)),
				static_cast<System::Int32>(static_cast<System::Byte>(64)));
			this->button8->Location = System::Drawing::Point(1229, 9);
			this->button8->Name = L"button8";
			this->button8->Size = System::Drawing::Size(37, 39);
			this->button8->TabIndex = 22;
			this->button8->Text = L"X";
			this->button8->UseVisualStyleBackColor = false;
			this->button8->Click += gcnew System::EventHandler(this, &MyForm::button8_Click);
			// 
			// button7
			// 
			this->button7->BackColor = System::Drawing::Color::Black;
			this->button7->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->button7->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 14));
			this->button7->ForeColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(64)), static_cast<System::Int32>(static_cast<System::Byte>(64)),
				static_cast<System::Int32>(static_cast<System::Byte>(64)));
			this->button7->Location = System::Drawing::Point(73, 347);
			this->button7->Name = L"button7";
			this->button7->Size = System::Drawing::Size(142, 39);
			this->button7->TabIndex = 19;
			this->button7->Text = L"Exit";
			this->button7->UseVisualStyleBackColor = false;
			this->button7->Click += gcnew System::EventHandler(this, &MyForm::button7_Click);
			// 
			// label10
			// 
			this->label10->AutoSize = true;
			this->label10->BackColor = System::Drawing::SystemColors::Desktop;
			this->label10->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 10.8F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label10->ForeColor = System::Drawing::Color::White;
			this->label10->Location = System::Drawing::Point(68, 185);
			this->label10->Name = L"label10";
			this->label10->Size = System::Drawing::Size(328, 125);
			this->label10->TabIndex = 12;
			this->label10->Text = L"Following are the Terms and Conditions:--\r\n1) You will follow the rules.\r\n2) You "
				L"will maintain fair use.\r\n3) You will not misuse the application.\r\n4) You will he"
				L"lp others understand";
			// 
			// label9
			// 
			this->label9->AutoSize = true;
			this->label9->BackColor = System::Drawing::SystemColors::Desktop;
			this->label9->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 36, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label9->ForeColor = System::Drawing::Color::White;
			this->label9->Location = System::Drawing::Point(31, 48);
			this->label9->Name = L"label9";
			this->label9->Size = System::Drawing::Size(575, 81);
			this->label9->TabIndex = 11;
			this->label9->Text = L"Terms and Conditions";
			// 
			// button6
			// 
			this->button6->BackColor = System::Drawing::Color::Black;
			this->button6->FlatAppearance->BorderSize = 0;
			this->button6->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->button6->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 14));
			this->button6->ForeColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(64)), static_cast<System::Int32>(static_cast<System::Byte>(64)),
				static_cast<System::Int32>(static_cast<System::Byte>(64)));
			this->button6->Location = System::Drawing::Point(1220, 12);
			this->button6->Name = L"button6";
			this->button6->Size = System::Drawing::Size(37, 39);
			this->button6->TabIndex = 21;
			this->button6->Text = L"X";
			this->button6->UseVisualStyleBackColor = false;
			this->button6->Click += gcnew System::EventHandler(this, &MyForm::button6_Click);
			// 
			// label8
			// 
			this->label8->AutoSize = true;
			this->label8->BackColor = System::Drawing::SystemColors::Desktop;
			this->label8->Cursor = System::Windows::Forms::Cursors::Hand;
			this->label8->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 10.2F));
			this->label8->ForeColor = System::Drawing::Color::Blue;
			this->label8->Location = System::Drawing::Point(273, 522);
			this->label8->Name = L"label8";
			this->label8->Size = System::Drawing::Size(166, 23);
			this->label8->TabIndex = 20;
			this->label8->Text = L"Terms and Conditions";
			this->label8->Click += gcnew System::EventHandler(this, &MyForm::label8_Click);
			// 
			// checkBox1
			// 
			this->checkBox1->AutoSize = true;
			this->checkBox1->BackColor = System::Drawing::Color::Black;
			this->checkBox1->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 10.2F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->checkBox1->ForeColor = System::Drawing::Color::White;
			this->checkBox1->Location = System::Drawing::Point(82, 518);
			this->checkBox1->Name = L"checkBox1";
			this->checkBox1->Size = System::Drawing::Size(199, 27);
			this->checkBox1->TabIndex = 19;
			this->checkBox1->Text = L"Do you agree with the ";
			this->checkBox1->UseVisualStyleBackColor = false;
			this->checkBox1->CheckedChanged += gcnew System::EventHandler(this, &MyForm::checkBox1_CheckedChanged);
			// 
			// button4
			// 
			this->button4->BackColor = System::Drawing::Color::Black;
			this->button4->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->button4->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 14));
			this->button4->ForeColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(64)), static_cast<System::Int32>(static_cast<System::Byte>(64)),
				static_cast<System::Int32>(static_cast<System::Byte>(64)));
			this->button4->Location = System::Drawing::Point(221, 569);
			this->button4->Name = L"button4";
			this->button4->Size = System::Drawing::Size(142, 39);
			this->button4->TabIndex = 18;
			this->button4->Text = L"Exit";
			this->button4->UseVisualStyleBackColor = false;
			this->button4->Click += gcnew System::EventHandler(this, &MyForm::button4_Click);
			// 
			// button5
			// 
			this->button5->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(64)), static_cast<System::Int32>(static_cast<System::Byte>(64)),
				static_cast<System::Int32>(static_cast<System::Byte>(64)));
			this->button5->Enabled = false;
			this->button5->FlatAppearance->BorderSize = 0;
			this->button5->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->button5->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 14));
			this->button5->ForeColor = System::Drawing::Color::Black;
			this->button5->Location = System::Drawing::Point(82, 569);
			this->button5->Name = L"button5";
			this->button5->Size = System::Drawing::Size(133, 39);
			this->button5->TabIndex = 17;
			this->button5->Text = L"Sign Up";
			this->button5->UseVisualStyleBackColor = false;
			this->button5->Click += gcnew System::EventHandler(this, &MyForm::button5_Click);
			// 
			// panel3
			// 
			this->panel3->Location = System::Drawing::Point(82, 475);
			this->panel3->Name = L"panel3";
			this->panel3->Size = System::Drawing::Size(287, 2);
			this->panel3->TabIndex = 16;
			// 
			// textBox3
			// 
			this->textBox3->BackColor = System::Drawing::Color::Black;
			this->textBox3->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->textBox3->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 10.2F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->textBox3->ForeColor = System::Drawing::Color::White;
			this->textBox3->Location = System::Drawing::Point(82, 446);
			this->textBox3->Name = L"textBox3";
			this->textBox3->Size = System::Drawing::Size(287, 23);
			this->textBox3->TabIndex = 15;
			this->textBox3->UseSystemPasswordChar = true;
			this->textBox3->TextChanged += gcnew System::EventHandler(this, &MyForm::textBox3_TextChanged);
			// 
			// panel4
			// 
			this->panel4->Location = System::Drawing::Point(82, 376);
			this->panel4->Name = L"panel4";
			this->panel4->Size = System::Drawing::Size(287, 2);
			this->panel4->TabIndex = 14;
			// 
			// textBox4
			// 
			this->textBox4->BackColor = System::Drawing::Color::Black;
			this->textBox4->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->textBox4->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 10.2F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->textBox4->ForeColor = System::Drawing::Color::White;
			this->textBox4->Location = System::Drawing::Point(82, 347);
			this->textBox4->Name = L"textBox4";
			this->textBox4->Size = System::Drawing::Size(287, 23);
			this->textBox4->TabIndex = 13;
			// 
			// label5
			// 
			this->label5->AutoSize = true;
			this->label5->BackColor = System::Drawing::SystemColors::Desktop;
			this->label5->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 14));
			this->label5->ForeColor = System::Drawing::Color::White;
			this->label5->Location = System::Drawing::Point(76, 401);
			this->label5->Name = L"label5";
			this->label5->Size = System::Drawing::Size(106, 32);
			this->label5->TabIndex = 12;
			this->label5->Text = L"Password";
			// 
			// label6
			// 
			this->label6->AutoSize = true;
			this->label6->BackColor = System::Drawing::SystemColors::Desktop;
			this->label6->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 14));
			this->label6->ForeColor = System::Drawing::Color::White;
			this->label6->Location = System::Drawing::Point(76, 303);
			this->label6->Name = L"label6";
			this->label6->Size = System::Drawing::Size(116, 32);
			this->label6->TabIndex = 11;
			this->label6->Text = L"Username";
			// 
			// label7
			// 
			this->label7->AutoSize = true;
			this->label7->BackColor = System::Drawing::SystemColors::Desktop;
			this->label7->Font = (gcnew System::Drawing::Font(L"Segoe UI Light", 36, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label7->ForeColor = System::Drawing::Color::White;
			this->label7->Location = System::Drawing::Point(118, 168);
			this->label7->Name = L"label7";
			this->label7->Size = System::Drawing::Size(232, 81);
			this->label7->TabIndex = 10;
			this->label7->Text = L"Sign Up";
			// 
			// MyForm
			// 
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::None;
			this->BackgroundImage = (cli::safe_cast<System::Drawing::Image^>(resources->GetObject(L"$this.BackgroundImage")));
			this->ClientSize = System::Drawing::Size(1269, 757);
			this->Controls->Add(this->pnlSign);
			this->Controls->Add(this->button3);
			this->Controls->Add(this->button2);
			this->Controls->Add(this->button1);
			this->Controls->Add(this->panel2);
			this->Controls->Add(this->textBox2);
			this->Controls->Add(this->panel1);
			this->Controls->Add(this->textBox1);
			this->Controls->Add(this->label4);
			this->Controls->Add(this->label3);
			this->Controls->Add(this->label2);
			this->Controls->Add(this->label1);
			this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::None;
			this->Name = L"MyForm";
			this->StartPosition = System::Windows::Forms::FormStartPosition::CenterScreen;
			this->Text = L"MyForm";
			this->Load += gcnew System::EventHandler(this, &MyForm::MyForm_Load);
			this->MouseDown += gcnew System::Windows::Forms::MouseEventHandler(this, &MyForm::MyForm_MouseDown);
			this->MouseMove += gcnew System::Windows::Forms::MouseEventHandler(this, &MyForm::MyForm_MouseMove);
			this->MouseUp += gcnew System::Windows::Forms::MouseEventHandler(this, &MyForm::MyForm_MouseUp);
			this->pnlSign->ResumeLayout(false);
			this->pnlSign->PerformLayout();
			this->pnlTerm->ResumeLayout(false);
			this->pnlTerm->PerformLayout();
			this->pnlDash->ResumeLayout(false);
			this->pnlDash->PerformLayout();
			this->pnlTest->ResumeLayout(false);
			this->pnlTest->PerformLayout();
			this->pnlPaas->ResumeLayout(false);
			this->pnlPaas->PerformLayout();
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion
private: System::Void MyForm_Load(System::Object^ sender, System::EventArgs^ e) {
}
private: System::Void label1_Click(System::Object^ sender, System::EventArgs^ e) {
}
private: System::Void label1_Click_1(System::Object^ sender, System::EventArgs^ e) {
}
private: System::Void label4_Click(System::Object^ sender, System::EventArgs^ e) {
}
//Dragging the form...
bool dragging;
Point offset;
private: System::Void MyForm_MouseDown(System::Object^ sender, System::Windows::Forms::MouseEventArgs^ e) {
	//enable dragging and get mouse position
	dragging = true;
	offset.X = e->X;
	offset.Y = e->Y;
}
private: System::Void MyForm_MouseMove(System::Object^ sender, System::Windows::Forms::MouseEventArgs^ e) {
	//check whether able to move
	if (dragging)
	{
		Point CurrentScreenPosition = PointToScreen(Point(e->X, e->Y));
		Location = Point(CurrentScreenPosition.X - offset.X, CurrentScreenPosition.Y - offset.Y);
	}
}
private: System::Void MyForm_MouseUp(System::Object^ sender, System::Windows::Forms::MouseEventArgs^ e) {
	//disable dragging
	dragging = false;
}
private: System::Void checkBox1_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
	if (checkBox1->Checked == true)
	{
		button5->Enabled = true;
	}
	else
		button5->Enabled = false;
}
private: System::Void button1_Click(System::Object^ sender, System::EventArgs^ e) {
	if (String::IsNullOrWhiteSpace(textBox1->Text) || String::IsNullOrWhiteSpace(textBox2->Text)) {
		MessageBox::Show("Please enter both username and password.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Warning);
		return;
	}
	String^ enteredUsername = textBox1->Text->Trim();
	String^ enteredPassword = textBox2->Text;

	if (!System::IO::File::Exists("usernames.txt") || !System::IO::File::Exists("passwords.txt")) {
		MessageBox::Show("No users registered yet.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
		return;
	}

	// Read all usernames and find index
	cli::array<String^>^ users = System::IO::File::ReadAllLines("usernames.txt");
	int idx = -1;
	for (int i = 0; i < users->Length; ++i) {
		if (users[i]->Equals(enteredUsername, StringComparison::OrdinalIgnoreCase)) {
			idx = i;
			break;
		}
	}
	if (idx == -1) {
		MessageBox::Show("Wrong Credentials", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
		return;
	}

	// Read corresponding passwords line
	cli::array<String^>^ passLines = System::IO::File::ReadAllLines("passwords.txt");
	if (idx >= passLines->Length) {
		MessageBox::Show("Password record missing for this user.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
		return;
	}

	String^ saltAndHash = passLines[idx];
	array<String^>^ parts = saltAndHash->Split(':');
	if (parts->Length != 2) {
		MessageBox::Show("Corrupt password record.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
		return;
	}
	String^ saltB64 = parts[0];
	String^ storedHashB64 = parts[1];

	String^ pepper = GetPepper();
	String^ computedHashB64 = ComputeSHA256_Base64(saltB64, enteredPassword, pepper);

	if (ConstantTimeEqualsBase64(storedHashB64, computedHashB64)) {
		sessionSeconds = 0;
		sessionTimer->Start();
		MessageBox::Show("You have Logged In", "Congratulations", MessageBoxButtons::OK, MessageBoxIcon::Information);
		textBox1->Clear();
		textBox2->Clear();
		SetCurrentUser(enteredUsername);
		label12->Text = MyForm::currentUser;
		pnlSign->Show();
		pnlTerm->Show();
		pnlDash->Show();
	}
	else {
		MessageBox::Show("Wrong Credentials", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
	}
}
private: System::Void button2_Click(System::Object^ sender, System::EventArgs^ e) {
	pnlSign->Show();
}
private: System::Void button3_Click(System::Object^ sender, System::EventArgs^ e) {
	Application::Exit();
}
private: System::Void button4_Click(System::Object^ sender, System::EventArgs^ e) {
	pnlSign->Hide();
}
private: System::Void button5_Click(System::Object^ sender, System::EventArgs^ e) {
	if (String::IsNullOrWhiteSpace(textBox4->Text) || String::IsNullOrWhiteSpace(textBox3->Text)) {
		MessageBox::Show("Username or Password cannot be empty!", "Error", MessageBoxButtons::OK, MessageBoxIcon::Warning);
		return;
	}
	String^ username = textBox4->Text->Trim();
	String^ password = textBox3->Text;

	// username uniqueness check
	if (System::IO::File::Exists("usernames.txt")) {
		System::IO::StreamReader^ reader = gcnew System::IO::StreamReader("usernames.txt");
		String^ line;
		while ((line = reader->ReadLine()) != nullptr) {
			if (line->Equals(username, StringComparison::OrdinalIgnoreCase)) {
				reader->Close();
				MessageBox::Show("Username already exists. Choose a different username.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
				return;
			}
		}
		reader->Close();
	}

	// Generate salt and compute hash
	String^ saltB64 = GenerateSaltBase64(16);
	String^ pepper = GetPepper();
	String^ hashB64 = ComputeSHA256_Base64(saltB64, password, pepper);

	// Append username and encoded salt:hash to files (keep same line order)
	System::IO::StreamWriter^ userFile = gcnew System::IO::StreamWriter("usernames.txt", true);
	userFile->WriteLine(username);
	userFile->Close();

	System::IO::StreamWriter^ passFile = gcnew System::IO::StreamWriter("passwords.txt", true);
	passFile->WriteLine(saltB64 + ":" + hashB64); // store salt:hash
	passFile->Close();

	// Create encrypted empty user vault file (AES)
	String^ filename = username + "_pass.txt";
	// Encrypt empty content
	AESEncryptToFile(filename, String::Empty, username);

	textBox4->Clear();
	textBox3->Clear();
	pnlSign->Hide();
	MessageBox::Show("Sign-Up Successful!", "Success", MessageBoxButtons::OK, MessageBoxIcon::Information);
}
private: System::Void button6_Click(System::Object^ sender, System::EventArgs^ e) {
	Application::Exit();
}
private: System::Void label8_Click(System::Object^ sender, System::EventArgs^ e) {
	pnlTerm->Show();
}
private: System::Void button7_Click(System::Object^ sender, System::EventArgs^ e) {
	pnlTerm->Hide();
}
private: System::Void button8_Click(System::Object^ sender, System::EventArgs^ e) {
	Application::Exit();
}
private: System::Void textBox3_TextChanged(System::Object^ sender, System::EventArgs^ e) {
}
private: System::Void pnlDash_Paint(System::Object^ sender, System::Windows::Forms::PaintEventArgs^ e) {
}
private: System::Void label12_Click(System::Object^ sender, System::EventArgs^ e) {
}
private: System::Void button9_Click(System::Object^ sender, System::EventArgs^ e) {
	Application::Exit();
}
private: System::Void button12_Click(System::Object^ sender, System::EventArgs^ e) {
	String^ oldPass = textBox6->Text;
	String^ newPass = textBox5->Text;
	if (String::IsNullOrWhiteSpace(oldPass) || String::IsNullOrWhiteSpace(newPass)) {
		MessageBox::Show("Please enter both old and new passwords.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Warning);
		return;
	}
	String^ filename = currentUser + "_pass.txt";
	String^ plain = AESDecryptFromFile(filename, currentUser);
	if (String::IsNullOrEmpty(plain)) {
		MessageBox::Show("User password file not found or empty!", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
		return;
	}
	System::Collections::Generic::List<String^>^ list = gcnew System::Collections::Generic::List<String^>(plain->Split(gcnew array<wchar_t>{'\r', '\n'}, StringSplitOptions::RemoveEmptyEntries));
	int idx = list->IndexOf(oldPass);
	if (idx == -1) {
		MessageBox::Show("Old password not found!", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
		return;
	}
	list[idx] = newPass;
	System::Text::StringBuilder^ sb = gcnew System::Text::StringBuilder();
	for each (String ^ s in list) sb->Append(s + "\r\n");
	AESEncryptToFile(filename, sb->ToString(), currentUser);
	MessageBox::Show("Password updated successfully!", "Success", MessageBoxButtons::OK, MessageBoxIcon::Information);
	textBox6->Clear();
	textBox5->Clear();
}
private: System::Void button14_Click(System::Object^ sender, System::EventArgs^ e) {
	String^ newPass = textBox8->Text;
	if (String::IsNullOrWhiteSpace(newPass)) {
		MessageBox::Show("Please enter a password to add.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Warning);
		return;
	}
	String^ filename = currentUser + "_pass.txt";
	// Decrypt existing content
	String^ plain = AESDecryptFromFile(filename, currentUser);
	// build updated content (keep one per line)
	String^ updated;
	if (String::IsNullOrEmpty(plain)) updated = newPass + "\r\n";
	else updated = plain + newPass + "\r\n";

	// Re-encrypt
	AESEncryptToFile(filename, updated, currentUser);
	MessageBox::Show("Password added successfully!", "Success", MessageBoxButtons::OK, MessageBoxIcon::Information);
	textBox8->Clear();
}
private: System::Void button13_Click(System::Object^ sender, System::EventArgs^ e) {
	String^ passToDelete = textBox7->Text;
	if (String::IsNullOrWhiteSpace(passToDelete)) {
		MessageBox::Show("Please enter a password to delete.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Warning);
		return;
	}
	String^ filename = currentUser + "_pass.txt";
	String^ plain = AESDecryptFromFile(filename, currentUser);
	if (String::IsNullOrEmpty(plain)) {
		MessageBox::Show("Password file empty or cannot be read.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
		return;
	}

	// Remove matching line
	System::Collections::Generic::List<String^>^ list = gcnew System::Collections::Generic::List<String^>(plain->Split(gcnew array<wchar_t>{'\r', '\n'}, StringSplitOptions::RemoveEmptyEntries));
	bool removed = list->Remove(passToDelete);
	if (!removed) {
		MessageBox::Show("Password not found!", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
		return;
	}
	// Rebuild and encrypt
	System::Text::StringBuilder^ sb = gcnew System::Text::StringBuilder();
	for each (String ^ s in list) sb->Append(s + "\r\n");
	AESEncryptToFile(filename, sb->ToString(), currentUser);
	MessageBox::Show("Password deleted successfully!", "Success", MessageBoxButtons::OK, MessageBoxIcon::Information);
	textBox7->Clear();
}
private: System::Void button10_Click(System::Object^ sender, System::EventArgs^ e) {
	String^ filename = currentUser + "_pass.txt";
	if (!System::IO::File::Exists(filename)) {
		MessageBox::Show("Password file not found!", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
		return;
	}

	String^ plaintext = AESDecryptFromFile(filename, currentUser);
	if (String::IsNullOrEmpty(plaintext)) {
		textBox9->Text = "No passwords saved.";
	}
	else {
		// Show list numbered
		array<String^>^ lines = plaintext->Split(gcnew array<wchar_t>{'\r', '\n'}, StringSplitOptions::RemoveEmptyEntries);
		System::Text::StringBuilder^ sb = gcnew System::Text::StringBuilder();
		int idx = 1;
		for each (String ^ p in lines) {
			sb->Append(idx.ToString() + ". " + p + "\r\n");
			idx++;
		}
		textBox9->Text = sb->ToString();
	}
	pnlPaas->Show();
}
private: System::Void button11_Click(System::Object^ sender, System::EventArgs^ e) {
	String^ password = textBox10->Text;
	if (String::IsNullOrWhiteSpace(password)) {
		MessageBox::Show("Enter a password to test!",
			"Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
		return;
	}
	// Variables to detect password properties
	bool hasLower = false;
	bool hasUpper = false;
	bool hasDigit = false;
	bool hasSymbol = false;
	for each (char c in password) {
		if (Char::IsLower(c)) hasLower = true;
		else if (Char::IsUpper(c)) hasUpper = true;
		else if (Char::IsDigit(c)) hasDigit = true;
		else hasSymbol = true;
	}
	// Count how many conditions are satisfied
	int score = 0;
	if (password->Length >= 8) score++;
	if (hasLower) score++;
	if (hasUpper) score++;
	if (hasDigit) score++;
	if (hasSymbol) score++;
	// Determine overall strength
	String^ strength;
	if (score <= 2)
		strength = "WEAK";
	else if (score == 3 || score == 4)
		strength = "AVERAGE";
	else
		strength = "STRONG";
	// Build flaw report
	System::Text::StringBuilder^ flaws = gcnew System::Text::StringBuilder();
	flaws->AppendLine("Password Strength: " + strength);
	flaws->AppendLine("------------------------------");
	if (password->Length < 8)
		flaws->AppendLine("• Password is too short (minimum 8 characters).");
	if (!hasLower)
		flaws->AppendLine("• Missing lowercase letters.");
	if (!hasUpper)
		flaws->AppendLine("• Missing uppercase letters.");
	if (!hasDigit)
		flaws->AppendLine("• Missing digits.");
	if (!hasSymbol)
		flaws->AppendLine("• Missing symbols (! @ # $ % etc.).");
	if (flaws->ToString()->Contains("•") == false)
		flaws->AppendLine("• No flaws detected. Good password!");
	// Output to textbox11
	textBox11->Text = flaws->ToString();
	// Show the test panel
	pnlTest->Show();
}
private: System::Void button15_Click(System::Object^ sender, System::EventArgs^ e) {
	pnlPaas->Hide();
}
private: System::Void button16_Click(System::Object^ sender, System::EventArgs^ e) {
	pnlTest->Hide();
}
private: System::Void label11_Click(System::Object^ sender, System::EventArgs^ e) {
}
};
}
