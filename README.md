# pam_nfc

## requirements
* __crypt.h__: from `libxcrypt`, already required by `pam`
* __pam_modules.h__: from `pam`, already required by `systemd`
* __winscard.h__: from `pcsclite`
```sh
sudo pacman -S pcsclite
sudo systemctl enable --now pcscd.service
```

## build
* pam_nfc_init:  
  `gcc -Wall -I/usr/include/PCSC -lpcsclite -lcrypto -lssl -o pam_nfc_init nfc.c pam_nfc_init.c`
* pam_nfc_scan:  
  `gcc -Wall -I/usr/include/PCSC -lpcsclite -lcrypt -o pam_nfc_scan nfc.c pam_nfc_scan.c`
* pam_nfc.so:  
  `gcc -Wall -fPIC -fno-stack-protector -shared -I/usr/include/PCSC -lpcsclite -lcrypt -lpam -o pam_nfc.so nfc.c pam_nfc.c`

## usage
* pam_nfc_init:
  * Place card on your NFC reader.
  * Then run:
    * `./pam_nfc_init ACR122U`: This will try to init card with factory key `ffffffffffffffff` and generate a new key.
    * `./pam_nfc_init ACR122U 1234123412341234 abcdabcdabcdabcd`: This will use `1234123412341234` as old key and `abcdabcdabcdabcd` as new key.
* pam_nfc_scan:
  * Place card on your NFC reader.
  * Then run `./pam_nfc_scan ACR122U`.
* pam_nfc.so:
  * `sudo cp pam_nfc.so /usr/lib/security/pam_nfc.so`.
  * insert rule into your `/etc/pam.d/(login|sddm|kde|sudo)`:  
    `auth sufficient pam_nfc.so reader=ACR122U uid=310a74ef user=nian pass=5fsyAhM4aW/7Mne8hGYTmg`
