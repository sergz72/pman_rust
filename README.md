# pman_rust

Zero trust password manager

The idea:

Passwords database consists of 4 files:

1. RSA public key file (local storage)
2. Parameters file (can be stored locally or in cloud, for example on OneDrive)
3. Data file part 1 (contains only even bytes of the entire data file, cloud-only storage, for example AWS S3)
4. Data file part 2 (contains only odd bytes of the entire data file, cloud-only storage, for example GCP CloudStorage)

Security protection for data/parameters file:

1. Two passwords, program uses the following password hashes:
   - SHA256 of password1
   - SHA256 of password2
   - SHA256 of (SHA256 of password1 + SHA256 of password2)
   - SHA256 of (SHA256 of password2 + SHA256 of password1)
2. Key derivation function - Argon2
3. Encryption - AES256, ChaCha20

Zero trust points:

1. Each of data file parts cannot be unencrypted because it contains only half of data.
2. Parameters file can be cracked, but data file cannot be accessed without RSA public key file.
3. Parameters file does not contain S3 passwords information - it is stored on QS3 server.

In case when local device is lost or stolen - just replace RSA key file

QS3 server - UDP service that:
- Uses configuration file with S3 access details excluding password
- Accepts file name and s3 password
- Returns presigned URL for download/upload


For now only console application is ready
