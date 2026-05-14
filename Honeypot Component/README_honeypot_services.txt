Cowrie Honeypot Support Files

Files included:

1. cowrie_encrypt.py
   Encrypts the latest Cowrie JSON log using AES-256-GCM.
   Suggested Linux path:
   /usr/local/bin/cowrie_encrypt.py

2. cowrie_decrypt.py
   Decrypts the encrypted Cowrie log for analysis/demo.
   Suggested Linux path:
   /usr/local/bin/cowrie_decrypt.py

3. cowrie-log-encrypt.service
   systemd service file for running the encryption script.

4. cowrie-log-encrypt.timer
   systemd timer file for running encryption every 5 minutes.

5. cowrie.service
   systemd service file for auto-starting Cowrie when Raspberry Pi boots.

Installation commands:

sudo cp cowrie_encrypt.py /usr/local/bin/cowrie_encrypt.py
sudo cp cowrie_decrypt.py /usr/local/bin/cowrie_decrypt.py
sudo chmod +x /usr/local/bin/cowrie_encrypt.py
sudo chmod +x /usr/local/bin/cowrie_decrypt.py

sudo cp cowrie-log-encrypt.service /etc/systemd/system/cowrie-log-encrypt.service
sudo cp cowrie-log-encrypt.timer /etc/systemd/system/cowrie-log-encrypt.timer
sudo cp cowrie.service /etc/systemd/system/cowrie.service

sudo systemctl daemon-reload

sudo systemctl enable cowrie.service
sudo systemctl start cowrie.service

sudo systemctl enable cowrie-log-encrypt.timer
sudo systemctl start cowrie-log-encrypt.timer

Check commands:

sudo systemctl status cowrie.service
sudo systemctl status cowrie-log-encrypt.timer
systemctl list-timers | grep cowrie
journalctl -u cowrie-log-encrypt.service -n 50
