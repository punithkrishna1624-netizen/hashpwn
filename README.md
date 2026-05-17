# 🔓 HashPwn

> A Python-based password hash cracking tool built for educational purposes and ethical security research.

---

## 📌 Description

**HashPwn** is a command-line tool that attempts to recover plaintext passwords from their hashed values. It supports multiple hashing algorithms and uses wordlist-based attacks to identify weak or common passwords.

This tool was built as part of a personal cybersecurity learning journey on Kali Linux.

---

## ⚙️ Features

- 🔍 Crack hashed passwords using wordlist attacks
- 🧠 Supports multiple hash algorithms (MD5, SHA1, SHA256, SHA512)
- 💻 Simple command-line interface
- ⚡ Fast and lightweight — built in pure Python
- 🐧 Optimized for Kali Linux / Linux environments

---

## 🛠️ Requirements

- Python 3.x
- Kali Linux (or any Linux distro)
- A wordlist (e.g. `rockyou.txt`)

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/YourUsername/hashpwn-tool.git

# Navigate to the folder
cd hashpwn-tool

# Run the tool
python3 hashpwn.py
```

---

## 📖 Usage

```bash
python3 hashpwn.py -h <hash_value> -w <wordlist_path> -t <hash_type>
```

### Example:

```bash
python3 hashpwn.py -h 5f4dcc3b5aa765d61d8327deb882cf99 -w /usr/share/wordlists/rockyou.txt -t md5
```

### Options:

| Flag | Description |
|------|-------------|
| `-h` | The hash value you want to crack |
| `-w` | Path to your wordlist file |
| `-t` | Hash type (md5, sha1, sha256, sha512) |

---

## 📸 Screenshot

> *(Add a screenshot of your tool running here)*

---

## ⚠️ Disclaimer

> This tool is intended **strictly for educational purposes and authorized security testing only.**
> 
> Do **NOT** use this tool on systems or accounts you do not own or have explicit permission to test.
> Unauthorized use is illegal and unethical.
> 
> The developer is not responsible for any misuse of this tool.

---

## 👨‍💻 Author

**Your Name**  
🔗 [LinkedIn](https://www.linkedin.com/in/yourprofile)  
🐙 [GitHub](https://github.com/YourUsername)

---

## 📄 License

This project is licensed under the **MIT License** — feel free to use and modify it for educational purposes.

---

⭐ If you found this useful, give it a star on GitHub!
