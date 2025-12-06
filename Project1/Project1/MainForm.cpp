#include "MainForm.h"

using namespace EncryptionTool;

// ===== ORIGINAL UI CODE =====

// Initialize encryption when algorithm changes
void MainForm::InitializeEncryption()
{
    if (comboBox1->Items->Count == 0)
    {
        for each (String ^ algo in encryptionAlgorithms)
        {
            comboBox1->Items->Add(algo);
        }
        comboBox1->SelectedIndex = 0;
    }

    UpdateKeyInfo();

    int ivSize = 16;
    String^ algorithm = comboBox1->SelectedItem->ToString();
    if (algorithm == "ChaCha20")
    {
        ivSize = 12;
    }
    else if (algorithm == "RC4")
    {
        ivSize = 0;
    }
    else if (algorithm == "3DES" || algorithm == "Blowfish")
    {
        ivSize = 8; // 3DES and Blowfish require 8-byte IV
    }

    if (algorithm == "RSA")
    {
        // Hide symmetric key controls, show RSA controls
        label3->Visible = false;
        textBoxKey->Visible = false;
        panelKeyType->Visible = false;
        buttonGenerateKey->Visible = false;
        panelRSAKeys->Visible = true;

        // Position buttons differently for RSA
        button1->Location = System::Drawing::Point(320, 280);
        button2->Location = System::Drawing::Point(440, 280);

        label4->Text = "Key: RSA 2048-bit";
        label5->Text = "IV: Not used for RSA";
    }
    else
    {
        // Show symmetric key controls, hide RSA controls
        label3->Visible = true;
        textBoxKey->Visible = true;
        panelKeyType->Visible = true;
        buttonGenerateKey->Visible = true;
        panelRSAKeys->Visible = false;

        // Position buttons back for symmetric algorithms
        button1->Location = System::Drawing::Point(320, 200);
        button2->Location = System::Drawing::Point(440, 200);

        if (ivSize > 0)
        {
            iv = GenerateRandomIV(ivSize);
            label5->Text = "IV: " + iv;
        }
        else
        {
            iv = "";
            label5->Text = "IV: Not used for RC4";
        }
    }
}

void MainForm::UpdateKeyInfo()
{
    String^ algorithm = comboBox1->SelectedItem->ToString();

    if (algorithm == "RSA")
    {
        labelKeyInfo->Text = "RSA 2048-bit (Public/Private Key Pair)";
        labelKeyInfo->ForeColor = Color::DarkGreen;
        return;
    }

    String^ keyText = textBoxKey->Text;

    if (String::IsNullOrEmpty(keyText))
    {
        labelKeyInfo->Text = "Enter key or click Generate Key";
        labelKeyInfo->ForeColor = Color::DarkRed;
        label4->Text = "Key: [Not Set]";
        return;
    }

    try
    {
        array<Byte>^ keyBytes = GetKeyBytesFromInput();
        String^ keyInfo = GetKeySizeInfo(algorithm, keyBytes);
        labelKeyInfo->Text = keyInfo;

        if (ValidateKeySize(algorithm, keyBytes))
        {
            labelKeyInfo->ForeColor = Color::DarkGreen;
            label4->Text = "Key: " + keyInfo;
        }
        else
        {
            labelKeyInfo->ForeColor = Color::DarkRed;
            label4->Text = "Key: " + keyInfo + " - INVALID";
        }
    }
    catch (Exception^ ex)
    {
        labelKeyInfo->Text = "Invalid key format: " + ex->Message;
        labelKeyInfo->ForeColor = Color::DarkRed;
        label4->Text = "Key: Invalid format";
    }
}

bool MainForm::ValidateKeySize(String^ algorithm, array<Byte>^ keyBytes)
{
    int keySizeBits = keyBytes->Length * 8;

    if (algorithm == "AES")
    {
        return (keySizeBits == 128 || keySizeBits == 192 || keySizeBits == 256);
    }
    else if (algorithm == "RC4")
    {
        return (keySizeBits >= 40 && keySizeBits <= 2048);
    }
    else if (algorithm == "ChaCha20")
    {
        return (keySizeBits == 128 || keySizeBits == 256);
    }
    else if (algorithm == "Blowfish")
    {
        return (keySizeBits >= 32 && keySizeBits <= 448 && keySizeBits % 8 == 0);
    }
    else if (algorithm == "3DES")
    {
        return (keySizeBits == 128 || keySizeBits == 192);
    }
    else if (algorithm == "RSA")
    {
        return true; // RSA uses key pair, not symmetric key
    }

    return false;
}

String^ MainForm::GetKeySizeInfo(String^ algorithm, array<Byte>^ keyBytes)
{
    int keySizeBits = keyBytes->Length * 8;
    String^ sizeInfo = keySizeBits + " bit (" + keyBytes->Length + " bytes)";

    if (algorithm == "AES")
    {
        if (keySizeBits == 128 || keySizeBits == 192 || keySizeBits == 256)
            return sizeInfo + " - Valid for AES";
        else
            return sizeInfo + " - Invalid: AES requires 128, 192, or 256 bits";
    }
    else if (algorithm == "RC4")
    {
        if (keySizeBits >= 40 && keySizeBits <= 2048)
            return sizeInfo + " - Valid for RC4";
        else
            return sizeInfo + " - Invalid: RC4 requires 40-2048 bits";
    }
    else if (algorithm == "ChaCha20")
    {
        if (keySizeBits == 128 || keySizeBits == 256)
            return sizeInfo + " - Valid for ChaCha20";
        else
            return sizeInfo + " - Invalid: ChaCha20 requires 128 or 256 bits";
    }
    else if (algorithm == "Blowfish")
    {
        if (keySizeBits >= 32 && keySizeBits <= 448 && keySizeBits % 8 == 0)
            return sizeInfo + " - Valid for Blowfish";
        else
            return sizeInfo + " - Invalid: Blowfish requires 32-448 bits (multiples of 8)";
    }
    else if (algorithm == "3DES")
    {
        if (keySizeBits == 128)
            return sizeInfo + " - Valid for 3DES (2-key)";
        else if (keySizeBits == 192)
            return sizeInfo + " - Valid for 3DES (3-key)";
        else
            return sizeInfo + " - Invalid: 3DES requires 128 or 192 bits";
    }
    else if (algorithm == "RSA")
    {
        return "RSA 2048-bit (Public/Private Key Pair)";
    }

    return sizeInfo + " - Unknown algorithm";
}

array<Byte>^ MainForm::GetKeyBytesFromInput()
{
    String^ keyText = textBoxKey->Text;

    if (radioHexKey->Checked)
    {
        keyText = keyText->Replace(" ", "")->Replace("-", "")->Replace(":", "");

        if (keyText->Length % 2 != 0)
            throw gcnew ArgumentException("Hex key must have even number of characters");

        for (int i = 0; i < keyText->Length; i++)
        {
            if (!Char::IsDigit(keyText[i]) && !(keyText[i] >= 'A' && keyText[i] <= 'F') && !(keyText[i] >= 'a' && keyText[i] <= 'f'))
                throw gcnew ArgumentException("Invalid hex character in key");
        }

        array<Byte>^ keyBytes = gcnew array<Byte>(keyText->Length / 2);
        for (int i = 0; i < keyBytes->Length; i++)
        {
            String^ byteString = keyText->Substring(i * 2, 2);
            keyBytes[i] = Byte::Parse(byteString, System::Globalization::NumberStyles::HexNumber);
        }
        return keyBytes;
    }
    else
    {
        return Encoding::UTF8->GetBytes(keyText);
    }
}

String^ MainForm::GenerateRandomKey(int size)
{
    array<Byte>^ randomBytes = gcnew array<Byte>(size);
    RNGCryptoServiceProvider^ rng = gcnew RNGCryptoServiceProvider();
    rng->GetBytes(randomBytes);

    if (radioHexKey->Checked)
    {
        return BitConverter::ToString(randomBytes)->Replace("-", "");
    }
    else
    {
        return Convert::ToBase64String(randomBytes);
    }
}

String^ MainForm::GenerateRandomIV(int size)
{
    array<Byte>^ randomBytes = gcnew array<Byte>(size);
    RNGCryptoServiceProvider^ rng = gcnew RNGCryptoServiceProvider();
    rng->GetBytes(randomBytes);
    return Convert::ToBase64String(randomBytes);
}

// Event Handlers
void MainForm::button1_Click(System::Object^ sender, System::EventArgs^ e)
{
    try
    {
        String^ plainText = textBox1->Text;
        String^ algorithm = comboBox1->SelectedItem->ToString();

        if (String::IsNullOrEmpty(plainText) || plainText == "Enter your text here...")
        {
            MessageBox::Show(L"Please enter text to encrypt.");
            return;
        }

        if (algorithm == "RSA")
        {
            // RSA encryption
            String^ publicKeyText = textBoxPublicKey->Text;
            if (String::IsNullOrEmpty(publicKeyText))
            {
                MessageBox::Show(L"Please enter or generate RSA public key.");
                return;
            }

            array<Byte>^ plainBytes = Encoding::UTF8->GetBytes(plainText);

            // Parse public key (format: n|e)
            array<String^>^ keyParts = publicKeyText->Split('|');
            if (keyParts->Length != 2)
            {
                MessageBox::Show(L"Invalid public key format. Use format: n|e");
                return;
            }

            BigInteger^ n = ParseBigIntegerFromBase64(keyParts[0]);
            BigInteger^ e = ParseBigIntegerFromBase64(keyParts[1]);

            array<Byte>^ encryptedBytes = RSA_Encrypt(plainBytes, *n, *e);
            String^ encryptedText = Convert::ToBase64String(encryptedBytes);

            richTextBox1->Text = "ENCRYPTED TEXT (RSA 2048-bit):\r\n" + encryptedText;
            richTextBox1->ForeColor = Color::DarkGreen;
        }
        else
        {
            // Symmetric encryption
            String^ keyText = textBoxKey->Text;

            if (String::IsNullOrEmpty(keyText))
            {
                MessageBox::Show(L"Please enter a key or generate one.");
                return;
            }

            array<Byte>^ keyBytes = GetKeyBytesFromInput();
            if (!ValidateKeySize(algorithm, keyBytes))
            {
                MessageBox::Show(L"Invalid key size for selected algorithm. Please check the key information.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
                return;
            }

            String^ encryptedText = EncryptString(plainText, algorithm);
            richTextBox1->Text = "ENCRYPTED TEXT (" + algorithm + " - " + GetKeySizeInfo(algorithm, keyBytes) + "):\r\n" + encryptedText;
            richTextBox1->ForeColor = Color::DarkGreen;
        }
    }
    catch (Exception^ ex)
    {
        MessageBox::Show("Encryption failed: " + ex->Message, "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
    }
}

void MainForm::button2_Click(System::Object^ sender, System::EventArgs^ e)
{
    try
    {
        String^ cipherText = textBox1->Text;
        String^ algorithm = comboBox1->SelectedItem->ToString();

        if (String::IsNullOrEmpty(cipherText) || cipherText == "Enter your text here...")
        {
            MessageBox::Show(L"Please enter text to decrypt.");
            return;
        }

        if (algorithm == "RSA")
        {
            // RSA decryption
            String^ privateKeyText = textBoxPrivateKey->Text;
            if (String::IsNullOrEmpty(privateKeyText))
            {
                MessageBox::Show(L"Please enter RSA private key.");
                return;
            }

            array<Byte>^ cipherBytes = Convert::FromBase64String(cipherText);

            // Parse private key (format: n|d)
            array<String^>^ keyParts = privateKeyText->Split('|');
            if (keyParts->Length != 2)
            {
                MessageBox::Show(L"Invalid private key format. Use format: n|d");
                return;
            }

            BigInteger^ n = ParseBigIntegerFromBase64(keyParts[0]);
            BigInteger^ d = ParseBigIntegerFromBase64(keyParts[1]);

            array<Byte>^ decryptedBytes = RSA_Decrypt(cipherBytes, *n, *d);
            String^ decryptedText = Encoding::UTF8->GetString(decryptedBytes);

            richTextBox1->Text = "DECRYPTED TEXT (RSA 2048-bit):\r\n" + decryptedText;
            richTextBox1->ForeColor = Color::DarkBlue;
        }
        else
        {
            // Symmetric decryption
            String^ keyText = textBoxKey->Text;

            if (String::IsNullOrEmpty(keyText))
            {
                MessageBox::Show(L"Please enter a key or generate one.");
                return;
            }

            array<Byte>^ keyBytes = GetKeyBytesFromInput();
            if (!ValidateKeySize(algorithm, keyBytes))
            {
                MessageBox::Show(L"Invalid key size for selected algorithm. Please check the key information.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
                return;
            }

            String^ decryptedText = DecryptString(cipherText, algorithm);
            richTextBox1->Text = "DECRYPTED TEXT (" + algorithm + " - " + GetKeySizeInfo(algorithm, keyBytes) + "):\r\n" + decryptedText;
            richTextBox1->ForeColor = Color::DarkBlue;
        }
    }
    catch (Exception^ ex)
    {
        MessageBox::Show("Decryption failed: " + ex->Message, "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
    }
}

void MainForm::button3_Click(System::Object^ sender, System::EventArgs^ e)
{
    OpenFileDialog^ openFileDialog = gcnew OpenFileDialog();
    openFileDialog->Filter = "All files (*.*)|*.*";
    openFileDialog->Title = "Select file to encrypt/decrypt";
    if (openFileDialog->ShowDialog() == System::Windows::Forms::DialogResult::OK)
    {
        textBox2->Text = openFileDialog->FileName;
    }
}

void MainForm::button4_Click(System::Object^ sender, System::EventArgs^ e)
{
    try
    {
        String^ inputFile = textBox2->Text;
        String^ algorithm = comboBox1->SelectedItem->ToString();

        if (String::IsNullOrEmpty(inputFile) || !File::Exists(inputFile) || inputFile == "Select a file...")
        {
            MessageBox::Show(L"Please select a valid file to encrypt.");
            return;
        }

        if (algorithm == "RSA")
        {
            MessageBox::Show(L"RSA is not suitable for large file encryption. Please use hybrid encryption (RSA for key, AES for data).", "Info", MessageBoxButtons::OK, MessageBoxIcon::Information);
            return;
        }

        String^ keyText = textBoxKey->Text;
        if (String::IsNullOrEmpty(keyText))
        {
            MessageBox::Show(L"Please enter a key or generate one.");
            return;
        }

        array<Byte>^ keyBytes = GetKeyBytesFromInput();
        if (!ValidateKeySize(algorithm, keyBytes))
        {
            MessageBox::Show(L"Invalid key size for selected algorithm. Please check the key information.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
            return;
        }

        String^ outputFile = Path::Combine(Path::GetDirectoryName(inputFile),
            Path::GetFileNameWithoutExtension(inputFile) + "_encrypted" + Path::GetExtension(inputFile));

        if (EncryptFile(inputFile, outputFile, algorithm))
        {
            richTextBox1->Text = "FILE ENCRYPTED SUCCESSFULLY!\r\nAlgorithm: " + algorithm +
                " (" + GetKeySizeInfo(algorithm, keyBytes) + ")\r\nInput: " + inputFile + "\r\nOutput: " + outputFile;
            richTextBox1->ForeColor = Color::DarkGreen;
        }
        else
        {
            MessageBox::Show(L"File encryption failed.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
        }
    }
    catch (Exception^ ex)
    {
        MessageBox::Show("File encryption failed: " + ex->Message, "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
    }
}

void MainForm::button5_Click(System::Object^ sender, System::EventArgs^ e)
{
    try
    {
        String^ inputFile = textBox2->Text;
        String^ algorithm = comboBox1->SelectedItem->ToString();

        if (String::IsNullOrEmpty(inputFile) || !File::Exists(inputFile) || inputFile == "Select a file...")
        {
            MessageBox::Show(L"Please select a valid file to decrypt.");
            return;
        }

        if (algorithm == "RSA")
        {
            MessageBox::Show(L"RSA is not suitable for large file decryption. Please use hybrid encryption (RSA for key, AES for data).", "Info", MessageBoxButtons::OK, MessageBoxIcon::Information);
            return;
        }

        String^ keyText = textBoxKey->Text;
        if (String::IsNullOrEmpty(keyText))
        {
            MessageBox::Show(L"Please enter a key or generate one.");
            return;
        }

        array<Byte>^ keyBytes = GetKeyBytesFromInput();
        if (!ValidateKeySize(algorithm, keyBytes))
        {
            MessageBox::Show(L"Invalid key size for selected algorithm. Please check the key information.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
            return;
        }

        String^ outputFile = Path::Combine(Path::GetDirectoryName(inputFile),
            Path::GetFileNameWithoutExtension(inputFile) + "_decrypted" + Path::GetExtension(inputFile));

        if (DecryptFile(inputFile, outputFile, algorithm))
        {
            richTextBox1->Text = "FILE DECRYPTED SUCCESSFULLY!\r\nAlgorithm: " + algorithm +
                " (" + GetKeySizeInfo(algorithm, keyBytes) + ")\r\nInput: " + inputFile + "\r\nOutput: " + outputFile;
            richTextBox1->ForeColor = Color::DarkBlue;
        }
        else
        {
            MessageBox::Show(L"File decryption failed.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
        }
    }
    catch (Exception^ ex)
    {
        MessageBox::Show("File decryption failed: " + ex->Message, "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
    }
}

void MainForm::comboBox1_SelectedIndexChanged(System::Object^ sender, System::EventArgs^ e)
{
    InitializeEncryption();
    UpdateKeyInfo();
}

void MainForm::textBoxKey_TextChanged(System::Object^ sender, System::EventArgs^ e)
{
    UpdateKeyInfo();
}

void MainForm::buttonGenerateKey_Click(System::Object^ sender, System::EventArgs^ e)
{
    String^ algorithm = comboBox1->SelectedItem->ToString();
    int keySizeBytes = 32;

    if (algorithm == "AES")
    {
        keySizeBytes = 16;
    }
    else if (algorithm == "RC4")
    {
        keySizeBytes = 16;
    }
    else if (algorithm == "ChaCha20")
    {
        keySizeBytes = 32;
    }
    else if (algorithm == "Blowfish")
    {
        keySizeBytes = 32;
    }
    else if (algorithm == "3DES")
    {
        keySizeBytes = 24; // Generate 24-byte key for 3DES (168-bit)
    }

    textBoxKey->Text = GenerateRandomKey(keySizeBytes);
}

void MainForm::buttonGenerateRSAKeys_Click(System::Object^ sender, System::EventArgs^ e)
{
    try
    {
        richTextBox1->Text = "Generating RSA 2048-bit key pair... This may take a few seconds.";
        richTextBox1->ForeColor = Color::DarkBlue;
        Application::DoEvents(); // Update UI

        RSAKeyPair^ keyPair = GenerateRSAKeyPair(2048);

        // Format: n|e for public key, n|d for private key
        String^ publicKey = BigIntegerToBase64(keyPair->n) + "|" + BigIntegerToBase64(keyPair->e);
        String^ privateKey = BigIntegerToBase64(keyPair->n) + "|" + BigIntegerToBase64(keyPair->d);

        textBoxPublicKey->Text = publicKey;
        textBoxPrivateKey->Text = privateKey;

        richTextBox1->Text = "RSA 2048-bit key pair generated successfully!\r\n\r\n" +
            "Public Key (n|e): " + publicKey->Substring(0, Math::Min(100, publicKey->Length)) + "...\r\n" +
            "Private Key (n|d): " + privateKey->Substring(0, Math::Min(100, privateKey->Length)) + "...";
        richTextBox1->ForeColor = Color::DarkGreen;
    }
    catch (Exception^ ex)
    {
        MessageBox::Show("RSA key generation failed: " + ex->Message, "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
    }
}

void MainForm::radioKeyType_CheckedChanged(System::Object^ sender, System::EventArgs^ e)
{
    UpdateKeyInfo();
}

// ===== RSA IMPLEMENTATION =====

MainForm::RSAKeyPair^ MainForm::GenerateRSAKeyPair(int keySize)
{
    RSAKeyPair^ keyPair = gcnew RSAKeyPair();

    // Generate two large prime numbers
    BigInteger p = GenerateRandomPrime(keySize / 2);
    BigInteger q = GenerateRandomPrime(keySize / 2);

    // Ensure p and q are not equal
    while (BigInteger::Compare(p, q) == 0)
    {
        q = GenerateRandomPrime(keySize / 2);
    }

    // Compute n = p * q
    keyPair->n = BigInteger::Multiply(p, q);

    // Compute φ(n) = (p-1)*(q-1)
    BigInteger p_minus_1 = BigInteger::Subtract(p, BigInteger::One);
    BigInteger q_minus_1 = BigInteger::Subtract(q, BigInteger::One);
    BigInteger phi = BigInteger::Multiply(p_minus_1, q_minus_1);

    // Choose public exponent e (common values: 3, 17, 65537)
    keyPair->e = BigInteger(65537);

    // Ensure e and φ(n) are coprime
    while (BigInteger::GreatestCommonDivisor(keyPair->e, phi) != BigInteger::One)
    {
        keyPair->e = BigInteger::Add(keyPair->e, 2);
    }

    // Compute private exponent d = e^(-1) mod φ(n)
    keyPair->d = ModularInverse(keyPair->e, phi);

    return keyPair;
}

BigInteger MainForm::ModularInverse(BigInteger a, BigInteger m)
{
    BigInteger m0 = m;
    BigInteger y = BigInteger::Zero;
    BigInteger x = BigInteger::One;

    if (BigInteger::Compare(m, BigInteger::One) == 0)
        return BigInteger::Zero;

    while (BigInteger::Compare(a, BigInteger::One) > 0)
    {
        // q is quotient
        BigInteger q = BigInteger::Divide(a, m);
        BigInteger t = m;

        // m is remainder now, process same as Euclid's algo
        m = BigInteger::Remainder(a, m);
        a = t;
        t = y;

        // Update y and x
        y = BigInteger::Subtract(x, BigInteger::Multiply(q, y));
        x = t;
    }

    // Make x positive
    if (BigInteger::Compare(x, BigInteger::Zero) < 0)
        x = BigInteger::Add(x, m0);

    return x;
}

bool MainForm::IsPrime(BigInteger n, int k)
{
    if (BigInteger::Compare(n, BigInteger::One) <= 0) return false;
    if (BigInteger::Compare(n, 3) <= 0) return true;

    // Check if even
    if (BigInteger::Remainder(n, 2).IsZero) return false;

    // Write n-1 as 2^r * d
    BigInteger d = BigInteger::Subtract(n, BigInteger::One);
    int r = 0;
    while (BigInteger::Remainder(d, 2).IsZero)
    {
        d = BigInteger::Divide(d, 2);
        r++;
    }

    // Witness loop
    Random^ rand = gcnew Random();
    for (int i = 0; i < k; i++)
    {
        // Pick a random number a in [2, n-2]
        array<Byte>^ bytes = gcnew array<Byte>(n.ToByteArray()->Length);
        rand->NextBytes(bytes);
        BigInteger a = BigInteger(bytes);

        // Ensure a is positive
        if (a.Sign < 0) a = BigInteger::Negate(a);

        // Ensure a is in range [2, n-2]
        if (BigInteger::Compare(a, 2) < 0)
            a = BigInteger(2);
        if (BigInteger::Compare(a, BigInteger::Subtract(n, 2)) >= 0)
            a = BigInteger::Subtract(n, 3);

        // Compute x = a^d mod n
        BigInteger x = ModularPow(a, d, n);

        if (BigInteger::Compare(x, BigInteger::One) == 0 ||
            BigInteger::Compare(x, BigInteger::Subtract(n, BigInteger::One)) == 0)
            continue;

        bool continueLoop = false;
        for (int j = 0; j < r - 1; j++)
        {
            x = ModularPow(x, 2, n);
            if (BigInteger::Compare(x, BigInteger::Subtract(n, BigInteger::One)) == 0)
            {
                continueLoop = true;
                break;
            }
        }

        if (continueLoop)
            continue;

        return false; // n is composite
    }

    return true; // n is probably prime
}

BigInteger MainForm::GenerateRandomPrime(int bits)
{
    RNGCryptoServiceProvider^ rng = gcnew RNGCryptoServiceProvider();
    int byteCount = (bits + 7) / 8;

    while (true)
    {
        // Generate random bytes
        array<Byte>^ bytes = gcnew array<Byte>(byteCount);
        rng->GetBytes(bytes);

        // Ensure the number is odd and has the right bit length
        bytes[bytes->Length - 1] |= 0x01; // Make odd
        bytes[0] |= 0x80; // Ensure high bit is set for correct bit length

        BigInteger candidate = BigInteger(bytes);

        // Ensure positive
        if (candidate.Sign < 0)
            candidate = BigInteger::Negate(candidate);

        // Simple primality test with fewer rounds for speed
        if (IsPrime(candidate, 3))
            return candidate;
    }
}

BigInteger MainForm::ModularPow(BigInteger base, BigInteger exponent, BigInteger modulus)
{
    if (BigInteger::Compare(modulus, BigInteger::One) == 0)
        return BigInteger::Zero;

    BigInteger result = BigInteger::One;
    base = BigInteger::Remainder(base, modulus);

    BigInteger exp = exponent;
    while (BigInteger::Compare(exp, BigInteger::Zero) > 0)
    {
        if (!BigInteger::Remainder(exp, 2).IsZero)
        {
            result = BigInteger::Remainder(BigInteger::Multiply(result, base), modulus);
        }

        exp = BigInteger::Divide(exp, 2);
        base = BigInteger::Remainder(BigInteger::Multiply(base, base), modulus);
    }

    return result;
}

BigInteger MainForm::GCD(BigInteger a, BigInteger b)
{
    while (BigInteger::Compare(b, BigInteger::Zero) != 0)
    {
        BigInteger temp = b;
        b = BigInteger::Remainder(a, b);
        a = temp;
    }
    return a;
}

array<Byte>^ MainForm::MGF1(array<Byte>^ seed, int length)
{
    // Simple MGF1 using SHA1
    array<Byte>^ result = gcnew array<Byte>(length);
    int hLen = 20; // SHA1 hash length

    for (int i = 0; i < (length + hLen - 1) / hLen; i++)
    {
        array<Byte>^ counter = BitConverter::GetBytes(i);
        array<Byte>^ data = gcnew array<Byte>(seed->Length + 4);
        Array::Copy(seed, data, seed->Length);
        Array::Copy(counter, 0, data, seed->Length, 4);

        SHA1^ sha1 = SHA1::Create();
        array<Byte>^ hash = sha1->ComputeHash(data);

        int copyLength = Math::Min(hLen, length - i * hLen);
        if (copyLength > 0)
        {
            Array::Copy(hash, 0, result, i * hLen, copyLength);
        }
    }

    return result;
}

array<Byte>^ MainForm::XOR(array<Byte>^ a, array<Byte>^ b)
{
    if (a->Length != b->Length)
        throw gcnew ArgumentException("Arrays must have same length");

    array<Byte>^ result = gcnew array<Byte>(a->Length);
    for (int i = 0; i < a->Length; i++)
    {
        result[i] = (Byte)(a[i] ^ b[i]);
    }
    return result;
}

array<Byte>^ MainForm::OAEP_Pad(array<Byte>^ data, int keySizeBytes)
{
    int maxDataSize = keySizeBytes - 2 * 20 - 2; // For SHA1 (20 bytes)
    if (data->Length > maxDataSize)
        throw gcnew ArgumentException("Data too large for RSA key size");

    // Generate random seed
    array<Byte>^ seed = gcnew array<Byte>(20);
    RNGCryptoServiceProvider^ rng = gcnew RNGCryptoServiceProvider();
    rng->GetBytes(seed);

    // Data block: PS | 0x01 | M
    array<Byte>^ dataBlock = gcnew array<Byte>(keySizeBytes - 20 - 1);
    int psLength = dataBlock->Length - data->Length - 1;

    // Padding string PS (all zeros)
    for (int i = 0; i < psLength; i++)
        dataBlock[i] = 0;

    dataBlock[psLength] = 0x01; // Separator
    Array::Copy(data, 0, dataBlock, psLength + 1, data->Length);

    // maskedDB = dataBlock XOR MGF1(seed, dataBlock.Length)
    array<Byte>^ maskedDB = XOR(dataBlock, MGF1(seed, dataBlock->Length));

    // maskedSeed = seed XOR MGF1(maskedDB, seed.Length)
    array<Byte>^ maskedSeed = XOR(seed, MGF1(maskedDB, seed->Length));

    // EM = 0x00 || maskedSeed || maskedDB
    array<Byte>^ em = gcnew array<Byte>(keySizeBytes);
    em[0] = 0x00;
    Array::Copy(maskedSeed, 0, em, 1, maskedSeed->Length);
    Array::Copy(maskedDB, 0, em, 1 + maskedSeed->Length, maskedDB->Length);

    return em;
}

array<Byte>^ MainForm::OAEP_Unpad(array<Byte>^ data, int keySizeBytes)
{
    if (data->Length != keySizeBytes)
        throw gcnew ArgumentException("Invalid data length");

    if (data[0] != 0x00)
        throw gcnew ArgumentException("Invalid OAEP padding");

    int seedLength = 20;
    array<Byte>^ maskedSeed = gcnew array<Byte>(seedLength);
    array<Byte>^ maskedDB = gcnew array<Byte>(keySizeBytes - seedLength - 1);

    Array::Copy(data, 1, maskedSeed, 0, seedLength);
    Array::Copy(data, 1 + seedLength, maskedDB, 0, maskedDB->Length);

    // seed = maskedSeed XOR MGF1(maskedDB, seedLength)
    array<Byte>^ seed = XOR(maskedSeed, MGF1(maskedDB, seedLength));

    // DB = maskedDB XOR MGF1(seed, maskedDB.Length)
    array<Byte>^ DB = XOR(maskedDB, MGF1(seed, maskedDB->Length));

    // Find the 0x01 separator
    int separatorIndex = -1;
    for (int i = 0; i < DB->Length; i++)
    {
        if (DB[i] == 0x01)
        {
            separatorIndex = i;
            break;
        }
        else if (DB[i] != 0x00)
        {
            throw gcnew ArgumentException("Invalid OAEP padding");
        }
    }

    if (separatorIndex == -1)
        throw gcnew ArgumentException("Invalid OAEP padding");

    // Extract message
    array<Byte>^ message = gcnew array<Byte>(DB->Length - separatorIndex - 1);
    Array::Copy(DB, separatorIndex + 1, message, 0, message->Length);

    return message;
}

array<Byte>^ MainForm::RSA_Encrypt(array<Byte>^ data, BigInteger n, BigInteger e)
{
    int keySizeBytes = n.ToByteArray()->Length;

    // Apply OAEP padding
    array<Byte>^ paddedData = OAEP_Pad(data, keySizeBytes);

    // Convert padded data to BigInteger
    BigInteger m = BigInteger(paddedData);

    // Check if m >= n
    if (BigInteger::Compare(m, n) >= 0)
        throw gcnew ArgumentException("Message too long for RSA key size");

    // Encrypt: c = m^e mod n
    BigInteger c = ModularPow(m, e, n);

    // Convert result back to byte array
    return c.ToByteArray();
}

array<Byte>^ MainForm::RSA_Decrypt(array<Byte>^ data, BigInteger n, BigInteger d)
{
    // Convert ciphertext to BigInteger
    BigInteger c = BigInteger(data);

    // Check if c >= n
    if (BigInteger::Compare(c, n) >= 0)
        throw gcnew ArgumentException("Ciphertext too large for RSA key size");

    // Decrypt: m = c^d mod n
    BigInteger m = ModularPow(c, d, n);

    // Convert result to byte array
    array<Byte>^ paddedData = m.ToByteArray();

    // Apply OAEP unpadding
    int keySizeBytes = n.ToByteArray()->Length;

    // Ensure padded data has correct length
    if (paddedData->Length < keySizeBytes)
    {
        array<Byte>^ temp = gcnew array<Byte>(keySizeBytes);
        Array::Copy(paddedData, 0, temp, keySizeBytes - paddedData->Length, paddedData->Length);
        paddedData = temp;
    }
    else if (paddedData->Length > keySizeBytes)
    {
        // Remove leading zero if present
        if (paddedData[0] == 0)
        {
            array<Byte>^ temp = gcnew array<Byte>(keySizeBytes);
            Array::Copy(paddedData, 1, temp, 0, keySizeBytes);
            paddedData = temp;
        }
    }

    return OAEP_Unpad(paddedData, keySizeBytes);
}

BigInteger MainForm::ParseBigIntegerFromBase64(String^ base64)
{
    try
    {
        array<Byte>^ bytes = Convert::FromBase64String(base64);
        return BigInteger(bytes);
    }
    catch (Exception^ ex)
    {
        throw gcnew ArgumentException("Invalid Base64 string: " + ex->Message);
    }
}

String^ MainForm::BigIntegerToBase64(BigInteger value)
{
    array<Byte>^ bytes = value.ToByteArray();
    return Convert::ToBase64String(bytes);
}
// ===== ENCRYPTION METHODS =====

String^ MainForm::EncryptString(String^ plainText, String^ algorithm)
{
    array<Byte>^ plainBytes = Encoding::UTF8->GetBytes(plainText);
    array<Byte>^ keyBytes = GetKeyBytesFromInput();
    array<Byte>^ encryptedBytes;

    if (algorithm == "AES")
    {
        array<Byte>^ ivBytes = Convert::FromBase64String(iv);
        encryptedBytes = AES_Encrypt(plainBytes, keyBytes, ivBytes);
    }
    else if (algorithm == "RC4")
    {
        encryptedBytes = RC4_Encrypt(plainBytes, keyBytes);
    }
    else if (algorithm == "ChaCha20")
    {
        array<Byte>^ ivBytes = Convert::FromBase64String(iv);
        array<Byte>^ nonce = gcnew array<Byte>(12);
        Array::Copy(ivBytes, nonce, 12);
        encryptedBytes = ChaCha20_Encrypt(plainBytes, keyBytes, nonce);
    }
    else if (algorithm == "3DES")
    {
        array<Byte>^ ivBytes = Convert::FromBase64String(iv);
        encryptedBytes = TripleDES_Encrypt(plainBytes, keyBytes, ivBytes);
    }
    else if (algorithm == "Blowfish")
    {
        array<Byte>^ ivBytes = Convert::FromBase64String(iv);
        encryptedBytes = Blowfish_Encrypt(plainBytes, keyBytes, ivBytes);
    }
    else
    {
        throw gcnew ArgumentException("Unsupported algorithm: " + algorithm);
    }

    return Convert::ToBase64String(encryptedBytes);
}

String^ MainForm::DecryptString(String^ cipherText, String^ algorithm)
{
    array<Byte>^ cipherBytes = Convert::FromBase64String(cipherText);
    array<Byte>^ keyBytes = GetKeyBytesFromInput();
    array<Byte>^ decryptedBytes;

    if (algorithm == "AES")
    {
        array<Byte>^ ivBytes = Convert::FromBase64String(iv);
        decryptedBytes = AES_Decrypt(cipherBytes, keyBytes, ivBytes);
    }
    else if (algorithm == "RC4")
    {
        decryptedBytes = RC4_Decrypt(cipherBytes, keyBytes);
    }
    else if (algorithm == "ChaCha20")
    {
        array<Byte>^ ivBytes = Convert::FromBase64String(iv);
        array<Byte>^ nonce = gcnew array<Byte>(12);
        Array::Copy(ivBytes, nonce, 12);
        decryptedBytes = ChaCha20_Decrypt(cipherBytes, keyBytes, nonce);
    }
    else if (algorithm == "3DES")
    {
        array<Byte>^ ivBytes = Convert::FromBase64String(iv);
        decryptedBytes = TripleDES_Decrypt(cipherBytes, keyBytes, ivBytes);
    }
    else if (algorithm == "Blowfish")
    {
        array<Byte>^ ivBytes = Convert::FromBase64String(iv);
        decryptedBytes = Blowfish_Decrypt(cipherBytes, keyBytes, ivBytes);
    }
    else
    {
        throw gcnew ArgumentException("Unsupported algorithm: " + algorithm);
    }

    return Encoding::UTF8->GetString(decryptedBytes);
}

bool MainForm::EncryptFile(String^ inputFile, String^ outputFile, String^ algorithm)
{
    try
    {
        array<Byte>^ fileData = File::ReadAllBytes(inputFile);
        array<Byte>^ keyBytes = GetKeyBytesFromInput();
        array<Byte>^ encryptedData;

        if (algorithm == "AES")
        {
            array<Byte>^ ivBytes = Convert::FromBase64String(iv);
            encryptedData = AES_Encrypt(fileData, keyBytes, ivBytes);
        }
        else if (algorithm == "RC4")
        {
            encryptedData = RC4_Encrypt(fileData, keyBytes);
        }
        else if (algorithm == "ChaCha20")
        {
            array<Byte>^ ivBytes = Convert::FromBase64String(iv);
            array<Byte>^ nonce = gcnew array<Byte>(12);
            Array::Copy(ivBytes, nonce, 12);
            encryptedData = ChaCha20_Encrypt(fileData, keyBytes, nonce);
        }
        else if (algorithm == "3DES")
        {
            array<Byte>^ ivBytes = Convert::FromBase64String(iv);
            encryptedData = TripleDES_Encrypt(fileData, keyBytes, ivBytes);
        }
        else if (algorithm == "Blowfish")
        {
            array<Byte>^ ivBytes = Convert::FromBase64String(iv);
            encryptedData = Blowfish_Encrypt(fileData, keyBytes, ivBytes);
        }
        else
        {
            return false;
        }

        File::WriteAllBytes(outputFile, encryptedData);
        return true;
    }
    catch (Exception^)
    {
        return false;
    }
}

bool MainForm::DecryptFile(String^ inputFile, String^ outputFile, String^ algorithm)
{
    try
    {
        array<Byte>^ fileData = File::ReadAllBytes(inputFile);
        array<Byte>^ keyBytes = GetKeyBytesFromInput();
        array<Byte>^ decryptedData;

        if (algorithm == "AES")
        {
            array<Byte>^ ivBytes = Convert::FromBase64String(iv);
            decryptedData = AES_Decrypt(fileData, keyBytes, ivBytes);
        }
        else if (algorithm == "RC4")
        {
            decryptedData = RC4_Decrypt(fileData, keyBytes);
        }
        else if (algorithm == "ChaCha20")
        {
            array<Byte>^ ivBytes = Convert::FromBase64String(iv);
            array<Byte>^ nonce = gcnew array<Byte>(12);
            Array::Copy(ivBytes, nonce, 12);
            decryptedData = ChaCha20_Decrypt(fileData, keyBytes, nonce);
        }
        else if (algorithm == "3DES")
        {
            array<Byte>^ ivBytes = Convert::FromBase64String(iv);
            decryptedData = TripleDES_Decrypt(fileData, keyBytes, ivBytes);
        }
        else if (algorithm == "Blowfish")
        {
            array<Byte>^ ivBytes = Convert::FromBase64String(iv);
            decryptedData = Blowfish_Decrypt(fileData, keyBytes, ivBytes);
        }
        else
        {
            return false;
        }

        File::WriteAllBytes(outputFile, decryptedData);
        return true;
    }
    catch (Exception^)
    {
        return false;
    }
}

// ===== EXISTING ALGORITHM IMPLEMENTATIONS =====
// [All existing algorithm implementations remain the same as in the original code]
// AES, 3DES, RC4, ChaCha20, Blowfish implementations...

// Note: The existing algorithm implementations (AES, 3DES, RC4, ChaCha20, Blowfish)
// remain exactly the same as in your original code. I've omitted them here
// for brevity, but you should keep them in your MainForm.cpp file.

// ===== CUSTOM AES IMPLEMENTATION =====

// AES Helper Functions
UInt32 MainForm::AES_SubWord(UInt32 word)
{
    array<Byte>^ sbox = GetAES_SBOX();
    return (sbox[(word >> 24) & 0xFF] << 24) |
        (sbox[(word >> 16) & 0xFF] << 16) |
        (sbox[(word >> 8) & 0xFF] << 8) |
        sbox[word & 0xFF];
}

UInt32 MainForm::AES_RotWord(UInt32 word)
{
    return (word << 8) | (word >> 24);
}

void MainForm::AES_KeyExpansion(array<Byte>^ key, array<UInt32>^ w)
{
    int Nk = key->Length / 4;
    int Nr = Nk + 6;
    int i = 0;
    array<UInt32>^ rcon = GetAES_RCON();

    // Copy the original key
    for (i = 0; i < Nk; i++)
    {
        w[i] = (UInt32)(key[4 * i] << 24) | (UInt32)(key[4 * i + 1] << 16) |
            (UInt32)(key[4 * i + 2] << 8) | (UInt32)(key[4 * i + 3]);
    }

    // Expand the key
    for (i = Nk; i < 4 * (Nr + 1); i++)
    {
        UInt32 temp = w[i - 1];
        if (i % Nk == 0)
        {
            temp = AES_SubWord(AES_RotWord(temp)) ^ rcon[i / Nk - 1];
        }
        else if (Nk > 6 && i % Nk == 4)
        {
            temp = AES_SubWord(temp);
        }
        w[i] = w[i - Nk] ^ temp;
    }
}

void MainForm::AES_AddRoundKey(array<UInt32>^ state, array<UInt32>^ w, int round)
{
    for (int c = 0; c < 4; c++)
    {
        state[c] ^= w[round * 4 + c];
    }
}

void MainForm::AES_SubBytes(array<UInt32>^ state)
{
    array<Byte>^ sbox = GetAES_SBOX();
    for (int i = 0; i < 4; i++)
    {
        state[i] = (sbox[(state[i] >> 24) & 0xFF] << 24) |
            (sbox[(state[i] >> 16) & 0xFF] << 16) |
            (sbox[(state[i] >> 8) & 0xFF] << 8) |
            sbox[state[i] & 0xFF];
    }
}

void MainForm::AES_InvSubBytes(array<UInt32>^ state)
{
    array<Byte>^ inv_sbox = GetAES_INV_SBOX();
    for (int i = 0; i < 4; i++)
    {
        state[i] = (inv_sbox[(state[i] >> 24) & 0xFF] << 24) |
            (inv_sbox[(state[i] >> 16) & 0xFF] << 16) |
            (inv_sbox[(state[i] >> 8) & 0xFF] << 8) |
            inv_sbox[state[i] & 0xFF];
    }
}

void MainForm::AES_ShiftRows(array<UInt32>^ state)
{
    array<Byte>^ temp = gcnew array<Byte>(16);

    // Convert state to bytes
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            temp[i * 4 + j] = (Byte)((state[j] >> (24 - 8 * i)) & 0xFF);
        }
    }

    // Shift rows
    for (int i = 1; i < 4; i++)
    {
        for (int j = 0; j < i; j++)
        {
            Byte t = temp[i * 4];
            temp[i * 4] = temp[i * 4 + 1];
            temp[i * 4 + 1] = temp[i * 4 + 2];
            temp[i * 4 + 2] = temp[i * 4 + 3];
            temp[i * 4 + 3] = t;
        }
    }

    // Convert back to words
    for (int i = 0; i < 4; i++)
    {
        state[i] = 0;
        for (int j = 0; j < 4; j++)
        {
            state[i] |= (UInt32)(temp[j * 4 + i] << (24 - 8 * j));
        }
    }
}

void MainForm::AES_InvShiftRows(array<UInt32>^ state)
{
    array<Byte>^ temp = gcnew array<Byte>(16);

    // Convert state to bytes
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            temp[i * 4 + j] = (Byte)((state[j] >> (24 - 8 * i)) & 0xFF);
        }
    }

    // Inverse shift rows
    for (int i = 1; i < 4; i++)
    {
        for (int j = 0; j < i; j++)
        {
            Byte t = temp[i * 4 + 3];
            temp[i * 4 + 3] = temp[i * 4 + 2];
            temp[i * 4 + 2] = temp[i * 4 + 1];
            temp[i * 4 + 1] = temp[i * 4];
            temp[i * 4] = t;
        }
    }

    // Convert back to words
    for (int i = 0; i < 4; i++)
    {
        state[i] = 0;
        for (int j = 0; j < 4; j++)
        {
            state[i] |= (UInt32)(temp[j * 4 + i] << (24 - 8 * j));
        }
    }
}

Byte MainForm::AES_GFMultiply(Byte a, Byte b)
{
    Byte result = 0;
    Byte hiBit;

    for (int i = 0; i < 8; i++)
    {
        if ((b & 1) == 1)
            result ^= a;
        hiBit = (Byte)(a & 0x80);
        a <<= 1;
        if (hiBit == 0x80)
            a ^= 0x1B;
        b >>= 1;
    }

    return result;
}

void MainForm::AES_MixColumns(array<UInt32>^ state)
{
    array<Byte>^ temp = gcnew array<Byte>(16);

    // Convert state to bytes
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            temp[i * 4 + j] = (Byte)((state[j] >> (24 - 8 * i)) & 0xFF);
        }
    }

    // Mix columns
    for (int i = 0; i < 4; i++)
    {
        Byte a0 = temp[i * 4];
        Byte a1 = temp[i * 4 + 1];
        Byte a2 = temp[i * 4 + 2];
        Byte a3 = temp[i * 4 + 3];

        temp[i * 4] = (Byte)(AES_GFMultiply(0x02, a0) ^ AES_GFMultiply(0x03, a1) ^ a2 ^ a3);
        temp[i * 4 + 1] = (Byte)(a0 ^ AES_GFMultiply(0x02, a1) ^ AES_GFMultiply(0x03, a2) ^ a3);
        temp[i * 4 + 2] = (Byte)(a0 ^ a1 ^ AES_GFMultiply(0x02, a2) ^ AES_GFMultiply(0x03, a3));
        temp[i * 4 + 3] = (Byte)(AES_GFMultiply(0x03, a0) ^ a1 ^ a2 ^ AES_GFMultiply(0x02, a3));
    }

    // Convert back to words
    for (int i = 0; i < 4; i++)
    {
        state[i] = 0;
        for (int j = 0; j < 4; j++)
        {
            state[i] |= (UInt32)(temp[j * 4 + i] << (24 - 8 * j));
        }
    }
}

void MainForm::AES_InvMixColumns(array<UInt32>^ state)
{
    array<Byte>^ temp = gcnew array<Byte>(16);

    // Convert state to bytes
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            temp[i * 4 + j] = (Byte)((state[j] >> (24 - 8 * i)) & 0xFF);
        }
    }

    // Inverse mix columns
    for (int i = 0; i < 4; i++)
    {
        Byte a0 = temp[i * 4];
        Byte a1 = temp[i * 4 + 1];
        Byte a2 = temp[i * 4 + 2];
        Byte a3 = temp[i * 4 + 3];

        temp[i * 4] = (Byte)(AES_GFMultiply(0x0E, a0) ^ AES_GFMultiply(0x0B, a1) ^ AES_GFMultiply(0x0D, a2) ^ AES_GFMultiply(0x09, a3));
        temp[i * 4 + 1] = (Byte)(AES_GFMultiply(0x09, a0) ^ AES_GFMultiply(0x0E, a1) ^ AES_GFMultiply(0x0B, a2) ^ AES_GFMultiply(0x0D, a3));
        temp[i * 4 + 2] = (Byte)(AES_GFMultiply(0x0D, a0) ^ AES_GFMultiply(0x09, a1) ^ AES_GFMultiply(0x0E, a2) ^ AES_GFMultiply(0x0B, a3));
        temp[i * 4 + 3] = (Byte)(AES_GFMultiply(0x0B, a0) ^ AES_GFMultiply(0x0D, a1) ^ AES_GFMultiply(0x09, a2) ^ AES_GFMultiply(0x0E, a3));
    }

    // Convert back to words
    for (int i = 0; i < 4; i++)
    {
        state[i] = 0;
        for (int j = 0; j < 4; j++)
        {
            state[i] |= (UInt32)(temp[j * 4 + i] << (24 - 8 * j));
        }
    }
}

// Main AES Encryption/Decryption
array<Byte>^ MainForm::AES_Encrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ iv)
{
    if (key->Length != 16 && key->Length != 24 && key->Length != 32)
    {
        throw gcnew ArgumentException("AES requires key sizes of 16, 24, or 32 bytes (128, 192, or 256 bits)");
    }

    if (iv->Length != 16)
    {
        throw gcnew ArgumentException("AES requires a 16-byte (128-bit) IV");
    }

    // Determine parameters based on key size
    int Nk = key->Length / 4;  // Number of 32-bit words in key
    int Nr = Nk + 6;           // Number of rounds

    // Expand key
    array<UInt32>^ w = gcnew array<UInt32>(4 * (Nr + 1));
    AES_KeyExpansion(key, w);

    // Pad data to multiple of 16 bytes using PKCS7
    int paddedLength = ((data->Length + 15) / 16) * 16;
    array<Byte>^ paddedData = gcnew array<Byte>(paddedLength);
    Array::Copy(data, paddedData, data->Length);

    Byte padValue = (Byte)(paddedLength - data->Length);
    for (int i = data->Length; i < paddedLength; i++)
    {
        paddedData[i] = padValue;
    }

    array<Byte>^ result = gcnew array<Byte>(paddedLength);
    array<Byte>^ previousBlock = (array<Byte>^)iv->Clone();

    // Process each 16-byte block
    for (int block = 0; block < paddedLength; block += 16)
    {
        array<Byte>^ blockData = gcnew array<Byte>(16);
        Array::Copy(paddedData, block, blockData, 0, 16);

        // XOR with previous block (CBC mode)
        for (int i = 0; i < 16; i++)
        {
            blockData[i] ^= previousBlock[i];
        }

        // Convert block to state (column-major order)
        array<UInt32>^ state = gcnew array<UInt32>(4);
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                state[i] |= (UInt32)(blockData[j * 4 + i] << (24 - 8 * j));
            }
        }

        // AES Encryption Rounds
        AES_AddRoundKey(state, w, 0);

        for (int round = 1; round < Nr; round++)
        {
            AES_SubBytes(state);
            AES_ShiftRows(state);
            AES_MixColumns(state);
            AES_AddRoundKey(state, w, round);
        }

        // Final round (no MixColumns)
        AES_SubBytes(state);
        AES_ShiftRows(state);
        AES_AddRoundKey(state, w, Nr);

        // Convert state back to bytes
        array<Byte>^ encryptedBlock = gcnew array<Byte>(16);
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                encryptedBlock[j * 4 + i] = (Byte)((state[i] >> (24 - 8 * j)) & 0xFF);
            }
        }

        Array::Copy(encryptedBlock, 0, result, block, 16);
        previousBlock = encryptedBlock;
    }

    return result;
}

array<Byte>^ MainForm::AES_Decrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ iv)
{
    if (key->Length != 16 && key->Length != 24 && key->Length != 32)
    {
        throw gcnew ArgumentException("AES requires key sizes of 16, 24, or 32 bytes (128, 192, or 256 bits)");
    }

    if (iv->Length != 16)
    {
        throw gcnew ArgumentException("AES requires a 16-byte (128-bit) IV");
    }

    if (data->Length % 16 != 0)
    {
        throw gcnew ArgumentException("AES encrypted data must be multiple of 16 bytes");
    }

    // Determine parameters based on key size
    int Nk = key->Length / 4;  // Number of 32-bit words in key
    int Nr = Nk + 6;           // Number of rounds

    // Expand key
    array<UInt32>^ w = gcnew array<UInt32>(4 * (Nr + 1));
    AES_KeyExpansion(key, w);

    array<Byte>^ result = gcnew array<Byte>(data->Length);
    array<Byte>^ previousBlock = (array<Byte>^)iv->Clone();

    // Process each 16-byte block
    for (int block = 0; block < data->Length; block += 16)
    {
        array<Byte>^ blockData = gcnew array<Byte>(16);
        Array::Copy(data, block, blockData, 0, 16);

        array<Byte>^ tempBlock = (array<Byte>^)blockData->Clone();

        // Convert block to state (column-major order)
        array<UInt32>^ state = gcnew array<UInt32>(4);
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                state[i] |= (UInt32)(blockData[j * 4 + i] << (24 - 8 * j));
            }
        }

        // AES Decryption Rounds
        AES_AddRoundKey(state, w, Nr);
        AES_InvShiftRows(state);
        AES_InvSubBytes(state);

        for (int round = Nr - 1; round >= 1; round--)
        {
            AES_AddRoundKey(state, w, round);
            AES_InvMixColumns(state);
            AES_InvShiftRows(state);
            AES_InvSubBytes(state);
        }

        AES_AddRoundKey(state, w, 0);

        // Convert state back to bytes
        array<Byte>^ decryptedBlock = gcnew array<Byte>(16);
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                decryptedBlock[j * 4 + i] = (Byte)((state[i] >> (24 - 8 * j)) & 0xFF);
            }
        }

        // XOR with previous block (CBC mode)
        for (int i = 0; i < 16; i++)
        {
            decryptedBlock[i] ^= previousBlock[i];
            result[block + i] = decryptedBlock[i];
        }

        previousBlock = tempBlock;
    }

    // Remove PKCS7 padding
    Byte padValue = result[result->Length - 1];
    if (padValue > 0 && padValue <= 16)
    {
        bool validPadding = true;
        for (int i = result->Length - padValue; i < result->Length; i++)
        {
            if (result[i] != padValue)
            {
                validPadding = false;
                break;
            }
        }
        if (validPadding)
        {
            array<Byte>^ unpaddedResult = gcnew array<Byte>(result->Length - padValue);
            Array::Copy(result, unpaddedResult, unpaddedResult->Length);
            return unpaddedResult;
        }
    }

    return result;
}

// ===== CUSTOM 3DES IMPLEMENTATION =====

// 3DES Helper Functions
UInt64 MainForm::DES_Permute(UInt64 data, array<Byte>^ table, int inputSize)
{
    UInt64 result = 0;
    for (int i = 0; i < table->Length; i++)
    {
        int bitPos = inputSize - table[i];
        if ((data & (1ULL << bitPos)) != 0)
        {
            result |= (1ULL << (table->Length - 1 - i));
        }
    }
    return result;
}

void MainForm::DES_GenerateSubkeys(UInt64 key, array<UInt64>^ subkeys)
{
    array<Byte>^ pc1 = GetDES_PC1();
    array<Byte>^ pc2 = GetDES_PC2();
    array<Byte>^ shifts = GetDES_SHIFTS();

    // Apply PC1 permutation
    UInt64 permutedKey = DES_Permute(key, pc1, 64);

    UInt32 left = (UInt32)(permutedKey >> 28) & 0x0FFFFFFF;
    UInt32 right = (UInt32)(permutedKey & 0x0FFFFFFF);

    for (int i = 0; i < 16; i++)
    {
        // Apply shifts
        left = ((left << shifts[i]) | (left >> (28 - shifts[i]))) & 0x0FFFFFFF;
        right = ((right << shifts[i]) | (right >> (28 - shifts[i]))) & 0x0FFFFFFF;

        // Combine and apply PC2
        UInt64 combined = ((UInt64)left << 28) | right;
        subkeys[i] = DES_Permute(combined, pc2, 56);
    }
}

UInt32 MainForm::DES_Function(UInt32 right, UInt64 subkey)
{
    array<Byte>^ e = GetDES_E();
    array<Byte>^ p = GetDES_P();
    array<array<Byte>^>^ sboxes = GetDES_SBOX();

    // Expand right half to 48 bits
    UInt64 expanded = DES_Permute(right, e, 32);

    // XOR with subkey
    expanded ^= subkey;

    // Apply S-boxes
    UInt32 result = 0;
    for (int i = 0; i < 8; i++)
    {
        int shift = 42 - 6 * i;
        int sboxInput = (int)((expanded >> shift) & 0x3F);
        int row = ((sboxInput & 0x20) >> 4) | (sboxInput & 0x01);
        int col = (sboxInput >> 1) & 0x0F;
        int sboxOutput = sboxes[i][row * 16 + col];
        result |= (UInt32)(sboxOutput << (28 - 4 * i));
    }

    // Apply P permutation
    return (UInt32)DES_Permute(result, p, 32);
}

UInt64 MainForm::DES_ProcessBlock(UInt64 block, array<UInt64>^ subkeys, bool encrypt)
{
    array<Byte>^ ip = GetDES_IP();
    array<Byte>^ fp = GetDES_FP();

    // Apply initial permutation
    block = DES_Permute(block, ip, 64);

    UInt32 left = (UInt32)(block >> 32);
    UInt32 right = (UInt32)(block & 0xFFFFFFFF);

    // 16 rounds
    for (int i = 0; i < 16; i++)
    {
        int round = encrypt ? i : 15 - i;
        UInt64 subkey = subkeys[round];

        UInt32 newRight = left ^ DES_Function(right, subkey);
        left = right;
        right = newRight;
    }

    // Final swap and apply final permutation
    UInt64 result = ((UInt64)right << 32) | left;
    return DES_Permute(result, fp, 64);
}

// 3DES Main Functions
array<Byte>^ MainForm::TripleDES_Encrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ iv)
{
    if (key->Length != 16 && key->Length != 24)
    {
        throw gcnew ArgumentException("3DES requires key sizes of 16 or 24 bytes (112 or 168 bits)");
    }

    if (iv->Length != 8)
    {
        throw gcnew ArgumentException("3DES requires an 8-byte IV");
    }

    // Prepare keys
    array<UInt64>^ keys = gcnew array<UInt64>(3);

    if (key->Length == 16)
    {
        // 2-key 3DES: K1 = first 8 bytes, K2 = last 8 bytes, K3 = first 8 bytes
        keys[0] = BitConverter::ToUInt64(key, 0);
        keys[1] = BitConverter::ToUInt64(key, 8);
        keys[2] = keys[0];
    }
    else
    {
        // 3-key 3DES: K1, K2, K3 from 24 bytes
        keys[0] = BitConverter::ToUInt64(key, 0);
        keys[1] = BitConverter::ToUInt64(key, 8);
        keys[2] = BitConverter::ToUInt64(key, 16);
    }

    // Generate subkeys for each key
    array<array<UInt64>^>^ subkeys = gcnew array<array<UInt64>^>(3);
    for (int i = 0; i < 3; i++)
    {
        subkeys[i] = gcnew array<UInt64>(16);
        DES_GenerateSubkeys(keys[i], subkeys[i]);
    }

    // Pad data to multiple of 8 bytes using PKCS7
    int paddedLength = ((data->Length + 7) / 8) * 8;
    array<Byte>^ paddedData = gcnew array<Byte>(paddedLength);
    Array::Copy(data, paddedData, data->Length);

    Byte padValue = (Byte)(paddedLength - data->Length);
    for (int i = data->Length; i < paddedLength; i++)
    {
        paddedData[i] = padValue;
    }

    array<Byte>^ result = gcnew array<Byte>(paddedLength);
    UInt64 previousBlock = BitConverter::ToUInt64(iv, 0);

    // Process each 8-byte block
    for (int block = 0; block < paddedLength; block += 8)
    {
        UInt64 blockData = BitConverter::ToUInt64(paddedData, block);

        // CBC mode: XOR with previous block
        blockData ^= previousBlock;

        // 3DES: Encrypt with K1, Decrypt with K2, Encrypt with K3
        UInt64 encrypted = DES_ProcessBlock(blockData, subkeys[0], true);  // Encrypt with K1
        encrypted = DES_ProcessBlock(encrypted, subkeys[1], false);        // Decrypt with K2
        encrypted = DES_ProcessBlock(encrypted, subkeys[2], true);         // Encrypt with K3

        array<Byte>^ encryptedBytes = BitConverter::GetBytes(encrypted);
        Array::Copy(encryptedBytes, 0, result, block, 8);

        previousBlock = encrypted;
    }

    return result;
}

array<Byte>^ MainForm::TripleDES_Decrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ iv)
{
    if (key->Length != 16 && key->Length != 24)
    {
        throw gcnew ArgumentException("3DES requires key sizes of 16 or 24 bytes (112 or 168 bits)");
    }

    if (iv->Length != 8)
    {
        throw gcnew ArgumentException("3DES requires an 8-byte IV");
    }

    if (data->Length % 8 != 0)
    {
        throw gcnew ArgumentException("3DES encrypted data must be multiple of 8 bytes");
    }

    // Prepare keys (same as encryption)
    array<UInt64>^ keys = gcnew array<UInt64>(3);

    if (key->Length == 16)
    {
        keys[0] = BitConverter::ToUInt64(key, 0);
        keys[1] = BitConverter::ToUInt64(key, 8);
        keys[2] = keys[0];
    }
    else
    {
        keys[0] = BitConverter::ToUInt64(key, 0);
        keys[1] = BitConverter::ToUInt64(key, 8);
        keys[2] = BitConverter::ToUInt64(key, 16);
    }

    // Generate subkeys for each key
    array<array<UInt64>^>^ subkeys = gcnew array<array<UInt64>^>(3);
    for (int i = 0; i < 3; i++)
    {
        subkeys[i] = gcnew array<UInt64>(16);
        DES_GenerateSubkeys(keys[i], subkeys[i]);
    }

    array<Byte>^ result = gcnew array<Byte>(data->Length);
    UInt64 previousBlock = BitConverter::ToUInt64(iv, 0);

    // Process each 8-byte block
    for (int block = 0; block < data->Length; block += 8)
    {
        UInt64 blockData = BitConverter::ToUInt64(data, block);
        UInt64 tempBlock = blockData;

        // 3DES: Decrypt with K3, Encrypt with K2, Decrypt with K1
        UInt64 decrypted = DES_ProcessBlock(blockData, subkeys[2], false); // Decrypt with K3
        decrypted = DES_ProcessBlock(decrypted, subkeys[1], true);         // Encrypt with K2
        decrypted = DES_ProcessBlock(decrypted, subkeys[0], false);        // Decrypt with K1

        // CBC mode: XOR with previous block
        decrypted ^= previousBlock;

        array<Byte>^ decryptedBytes = BitConverter::GetBytes(decrypted);
        Array::Copy(decryptedBytes, 0, result, block, 8);

        previousBlock = tempBlock;
    }

    // Remove PKCS7 padding
    Byte padValue = result[result->Length - 1];
    if (padValue > 0 && padValue <= 8)
    {
        bool validPadding = true;
        for (int i = result->Length - padValue; i < result->Length; i++)
        {
            if (result[i] != padValue)
            {
                validPadding = false;
                break;
            }
        }
        if (validPadding)
        {
            array<Byte>^ unpaddedResult = gcnew array<Byte>(result->Length - padValue);
            Array::Copy(result, unpaddedResult, unpaddedResult->Length);
            return unpaddedResult;
        }
    }

    return result;
}

// ===== EXISTING ALGORITHMS (RC4, ChaCha20, Blowfish) =====

array<Byte>^ MainForm::RC4_Encrypt(array<Byte>^ data, array<Byte>^ key)
{
    array<Byte>^ result = gcnew array<Byte>(data->Length);
    array<int>^ s = gcnew array<int>(256);

    for (int i = 0; i < 256; i++)
    {
        s[i] = i;
    }

    int j = 0;
    for (int i = 0; i < 256; i++)
    {
        j = (j + s[i] + key[i % key->Length]) % 256;
        int temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }

    int i_index = 0;
    j = 0;
    for (int k = 0; k < data->Length; k++)
    {
        i_index = (i_index + 1) % 256;
        j = (j + s[i_index]) % 256;

        int temp = s[i_index];
        s[i_index] = s[j];
        s[j] = temp;

        int t = (s[i_index] + s[j]) % 256;
        result[k] = data[k] ^ (Byte)s[t];
    }

    return result;
}

array<Byte>^ MainForm::RC4_Decrypt(array<Byte>^ data, array<Byte>^ key)
{
    return RC4_Encrypt(data, key);
}

UInt32 MainForm::RotateLeft(UInt32 value, int offset)
{
    return (value << offset) | (value >> (32 - offset));
}

void MainForm::QuarterRound(array<UInt32>^ state, int a, int b, int c, int d)
{
    state[a] += state[b]; state[d] = RotateLeft(state[d] ^ state[a], 16);
    state[c] += state[d]; state[b] = RotateLeft(state[b] ^ state[c], 12);
    state[a] += state[b]; state[d] = RotateLeft(state[d] ^ state[a], 8);
    state[c] += state[d]; state[b] = RotateLeft(state[b] ^ state[c], 7);
}

array<Byte>^ MainForm::ChaCha20_Encrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ nonce)
{
    if (key->Length != 16 && key->Length != 32)
    {
        throw gcnew ArgumentException("ChaCha20 requires key sizes of 16 or 32 bytes (128 or 256 bits)");
    }

    array<Byte>^ result = gcnew array<Byte>(data->Length);
    array<UInt32>^ state = gcnew array<UInt32>(16);

    // ChaCha20 constants
    state[0] = 0x61707865;  // "expa"
    state[1] = 0x3320646e;  // "nd 3"
    state[2] = 0x79622d32;  // "2-by"
    state[3] = 0x6b206574;  // "te k"

    // Key setup - handle both 128-bit and 256-bit keys
    if (key->Length == 16)
    {
        // For 128-bit key, use the key twice (as in RFC7539)
        for (int i = 0; i < 4; i++)
        {
            state[4 + i] = BitConverter::ToUInt32(key, i * 4);
            state[8 + i] = BitConverter::ToUInt32(key, i * 4);
        }
    }
    else
    {
        // For 256-bit key
        for (int i = 0; i < 8; i++)
        {
            state[4 + i] = BitConverter::ToUInt32(key, i * 4);
        }
    }

    // Counter (set to 0)
    state[12] = 0;

    // Nonce (96 bits)
    for (int i = 0; i < 3; i++)
    {
        state[13 + i] = BitConverter::ToUInt32(nonce, i * 4);
    }

    int blockCount = (data->Length + 63) / 64;
    for (int block = 0; block < blockCount; block++)
    {
        state[12] = (UInt32)block;
        array<UInt32>^ workingState = (array<UInt32>^)state->Clone();

        // 20 rounds (10 double rounds)
        for (int round = 0; round < 10; round++)
        {
            // Column rounds
            QuarterRound(workingState, 0, 4, 8, 12);
            QuarterRound(workingState, 1, 5, 9, 13);
            QuarterRound(workingState, 2, 6, 10, 14);
            QuarterRound(workingState, 3, 7, 11, 15);

            // Diagonal rounds
            QuarterRound(workingState, 0, 5, 10, 15);
            QuarterRound(workingState, 1, 6, 11, 12);
            QuarterRound(workingState, 2, 7, 8, 13);
            QuarterRound(workingState, 3, 4, 9, 14);
        }

        // Add initial state to working state
        for (int i = 0; i < 16; i++)
        {
            workingState[i] += state[i];
        }

        // Convert state to byte array
        array<Byte>^ keyStream = gcnew array<Byte>(64);
        for (int i = 0; i < 16; i++)
        {
            array<Byte>^ word = BitConverter::GetBytes(workingState[i]);
            Array::Copy(word, 0, keyStream, i * 4, 4);
        }

        // XOR with data
        int blockStart = block * 64;
        int blockSize = Math::Min(64, data->Length - blockStart);
        for (int i = 0; i < blockSize; i++)
        {
            result[blockStart + i] = (Byte)(data[blockStart + i] ^ keyStream[i]);
        }
    }

    return result;
}

array<Byte>^ MainForm::ChaCha20_Decrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ nonce)
{
    return ChaCha20_Encrypt(data, key, nonce);
}

// Blowfish F function
UInt32 MainForm::F(UInt32 x)
{
    UInt32 a = (x >> 24) & 0xFF;
    UInt32 b = (x >> 16) & 0xFF;
    UInt32 c = (x >> 8) & 0xFF;
    UInt32 d = x & 0xFF;

    UInt32 y = S[0][a] + S[1][b];
    y = y ^ S[2][c];
    y = y + S[3][d];

    return y;
}

// Blowfish encryption for a single 64-bit block
void MainForm::EncryptBlock(array<UInt32>^ block)
{
    UInt32 left = block[0];
    UInt32 right = block[1];

    for (int i = 0; i < 16; i++)
    {
        left ^= P[i];
        right ^= F(left);

        // Swap
        UInt32 temp = left;
        left = right;
        right = temp;
    }

    // Final swap and XOR
    UInt32 temp = left;
    left = right;
    right = temp;

    right ^= P[16];
    left ^= P[17];

    block[0] = left;
    block[1] = right;
}

// Blowfish decryption for a single 64-bit block
void MainForm::DecryptBlock(array<UInt32>^ block)
{
    UInt32 left = block[0];
    UInt32 right = block[1];

    for (int i = 17; i > 1; i--)
    {
        left ^= P[i];
        right ^= F(left);

        // Swap
        UInt32 temp = left;
        left = right;
        right = temp;
    }

    // Final swap and XOR
    UInt32 temp = left;
    left = right;
    right = temp;

    right ^= P[1];
    left ^= P[0];

    block[0] = left;
    block[1] = right;
}

// Initialize Blowfish with key
void MainForm::InitializeBlowfish(array<Byte>^ key)
{
    array<UInt32>^ p_init = GetP_INIT();
    array<UInt32>^ s_init = GetS_INIT();

    // Initialize P and S arrays with initial values
    for (int i = 0; i < 18; i++)
    {
        P[i] = p_init[i];
    }

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 256; j++)
        {
            S[i][j] = s_init[i * 256 + j];
        }
    }

    // XOR P array with key
    int keyIndex = 0;
    for (int i = 0; i < 18; i++)
    {
        UInt32 data = 0;
        for (int j = 0; j < 4; j++)
        {
            data = (data << 8) | key[keyIndex];
            keyIndex = (keyIndex + 1) % key->Length;
        }
        P[i] ^= data;
    }

    // Encrypt zero blocks to further randomize P and S arrays
    array<UInt32>^ block = gcnew array<UInt32>(2);
    block[0] = 0;
    block[1] = 0;

    for (int i = 0; i < 18; i += 2)
    {
        EncryptBlock(block);
        P[i] = block[0];
        P[i + 1] = block[1];
    }

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 256; j += 2)
        {
            EncryptBlock(block);
            S[i][j] = block[0];
            S[i][j + 1] = block[1];
        }
    }
}

array<Byte>^ MainForm::Blowfish_Encrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ iv)
{
    if (key->Length < 4 || key->Length > 56)
    {
        throw gcnew ArgumentException("Blowfish requires key sizes between 4 and 56 bytes (32-448 bits)");
    }

    // Initialize Blowfish with the key
    InitializeBlowfish(key);

    // Pad data to multiple of 8 bytes using PKCS7
    int paddedLength = ((data->Length + 7) / 8) * 8;
    array<Byte>^ paddedData = gcnew array<Byte>(paddedLength);
    Array::Copy(data, paddedData, data->Length);

    // PKCS7 padding
    Byte padValue = (Byte)(paddedLength - data->Length);
    for (int i = data->Length; i < paddedLength; i++)
    {
        paddedData[i] = padValue;
    }

    array<Byte>^ result = gcnew array<Byte>(paddedLength);
    array<Byte>^ previousBlock = (array<Byte>^)iv->Clone();

    for (int i = 0; i < paddedLength; i += 8)
    {
        array<Byte>^ block = gcnew array<Byte>(8);
        Array::Copy(paddedData, i, block, 0, 8);

        // XOR with previous block (CBC mode)
        for (int j = 0; j < 8; j++)
        {
            block[j] ^= previousBlock[j];
        }

        // Convert to 32-bit words for encryption
        array<UInt32>^ words = gcnew array<UInt32>(2);
        words[0] = (UInt32)(block[0] << 24) | (UInt32)(block[1] << 16) | (UInt32)(block[2] << 8) | block[3];
        words[1] = (UInt32)(block[4] << 24) | (UInt32)(block[5] << 16) | (UInt32)(block[6] << 8) | block[7];

        // Encrypt the block
        EncryptBlock(words);

        // Convert back to bytes
        array<Byte>^ encryptedBlock = gcnew array<Byte>(8);
        encryptedBlock[0] = (Byte)((words[0] >> 24) & 0xFF);
        encryptedBlock[1] = (Byte)((words[0] >> 16) & 0xFF);
        encryptedBlock[2] = (Byte)((words[0] >> 8) & 0xFF);
        encryptedBlock[3] = (Byte)(words[0] & 0xFF);
        encryptedBlock[4] = (Byte)((words[1] >> 24) & 0xFF);
        encryptedBlock[5] = (Byte)((words[1] >> 16) & 0xFF);
        encryptedBlock[6] = (Byte)((words[1] >> 8) & 0xFF);
        encryptedBlock[7] = (Byte)(words[1] & 0xFF);

        Array::Copy(encryptedBlock, 0, result, i, 8);
        previousBlock = encryptedBlock;
    }

    return result;
}

array<Byte>^ MainForm::Blowfish_Decrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ iv)
{
    if (key->Length < 4 || key->Length > 56)
    {
        throw gcnew ArgumentException("Blowfish requires key sizes between 4 and 56 bytes (32-448 bits)");
    }

    if (data->Length % 8 != 0)
    {
        throw gcnew ArgumentException("Blowfish encrypted data must be multiple of 8 bytes");
    }

    InitializeBlowfish(key);

    array<Byte>^ result = gcnew array<Byte>(data->Length);
    array<Byte>^ previousBlock = (array<Byte>^)iv->Clone();

    for (int i = 0; i < data->Length; i += 8)
    {
        array<Byte>^ block = gcnew array<Byte>(8);
        Array::Copy(data, i, block, 0, 8);

        array<Byte>^ tempBlock = (array<Byte>^)block->Clone();

        array<UInt32>^ words = gcnew array<UInt32>(2);
        words[0] = (UInt32)(block[0] << 24) | (UInt32)(block[1] << 16) | (UInt32)(block[2] << 8) | block[3];
        words[1] = (UInt32)(block[4] << 24) | (UInt32)(block[5] << 16) | (UInt32)(block[6] << 8) | block[7];

        DecryptBlock(words);

        array<Byte>^ decryptedBlock = gcnew array<Byte>(8);
        decryptedBlock[0] = (Byte)((words[0] >> 24) & 0xFF);
        decryptedBlock[1] = (Byte)((words[0] >> 16) & 0xFF);
        decryptedBlock[2] = (Byte)((words[0] >> 8) & 0xFF);
        decryptedBlock[3] = (Byte)(words[0] & 0xFF);
        decryptedBlock[4] = (Byte)((words[1] >> 24) & 0xFF);
        decryptedBlock[5] = (Byte)((words[1] >> 16) & 0xFF);
        decryptedBlock[6] = (Byte)((words[1] >> 8) & 0xFF);
        decryptedBlock[7] = (Byte)(words[1] & 0xFF);

        for (int j = 0; j < 8; j++)
        {
            decryptedBlock[j] ^= previousBlock[j];
            result[i + j] = decryptedBlock[j];
        }

        previousBlock = tempBlock;
    }

    // Remove PKCS7 padding
    Byte padValue = result[result->Length - 1];
    if (padValue > 0 && padValue <= 8)
    {
        bool validPadding = true;
        for (int i = result->Length - padValue; i < result->Length; i++)
        {
            if (result[i] != padValue)
            {
                validPadding = false;
                break;
            }
        }
        if (validPadding)
        {
            array<Byte>^ unpaddedResult = gcnew array<Byte>(result->Length - padValue);
            Array::Copy(result, unpaddedResult, unpaddedResult->Length);
            return unpaddedResult;
        }
    }

    return result;
}