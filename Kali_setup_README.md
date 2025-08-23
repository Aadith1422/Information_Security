# 🐉 Kali Linux Inside Kali (VirtualBox Setup)

This project documents the process of installing **Kali Linux inside another Kali Linux system** using **Oracle VirtualBox**.  

---

## 📌 Table of Contents

- [Prerequisites](#-prerequisites)  
- [Step 1: Download Kali VirtualBox Image](#-step-1-download-kali-virtualbox-image)  
- [Step 2: Install Dependencies & VirtualBox](#-step-2-install-dependencies--virtualbox)  
- [Step 3: Launch VirtualBox](#-step-3-launch-virtualbox)  
- [Step 4: Import Kali VirtualBox Image](#-step-4-import-kali-virtualbox-image)  
- [Step 5: Start the VM](#-step-5-start-the-vm)  
- [Troubleshooting](#-troubleshooting)  
- [Result](#-result)  

---

## 📌 Prerequisites

- Host System: Kali Linux  
- Virtualization: Oracle VirtualBox  
- RAM: Minimum **4 GB** (Recommended: 8 GB+)  
- Disk Space: At least **25 GB** free  

---

## 📥 Step 1: Download Kali VirtualBox Image

Download the official Kali VirtualBox image from:  
👉 [Kali Downloads – Virtual Machines](https://www.kali.org/get-kali/#kali-virtual-machines)

Example downloaded file:  
```
kali-linux-2025.2-virtualbox-amd64.7z
```

![Download Kali VM](./Screenshot%20from%202025-08-21%2019-57-09.png)

---

## 🧰 Step 2: Install Dependencies & VirtualBox

Update and install required packages:

```bash
sudo apt update
sudo apt install -y gcc make perl dkms build-essential
```

Then, download and install the correct VirtualBox `.deb` package from:  
👉 [VirtualBox Linux Downloads](https://www.virtualbox.org/wiki/Linux_Downloads)

Example:

```bash
sudo dpkg -i virtualbox-7.1_7.1.12-169651~Debian~bookworm_amd64.deb
sudo apt --fix-broken install
```

---

## ⚙️ Step 3: Launch VirtualBox

Run VirtualBox:

```bash
virtualbox
```

You should now see the VirtualBox GUI.

---

## 🆕 Step 4: Import Kali VirtualBox Image

1. Open VirtualBox  
2. Click **File → Import Appliance**  
3. Select the downloaded `.ova` file  
4. Follow the wizard to finish setup  

---

## 🖥️ Step 5: Start the VM

Once imported, select the VM and click **Start**.

![Kali VM Running](./VirtualBox_kali-linux-2025.2-virtualbox-amd64_21_08_2025_20_23_28.png)

---

## 🔧 Troubleshooting

### Kernel Driver Error (`rc=-1908`)

If you see this error:

```bash
Kernel driver not installed (rc=-1908)
```

Fix it by running:

```bash
sudo apt install linux-headers-$(uname -r)
sudo modprobe vboxdrv
```

---

## 🎉 Result

You now have **Kali running inside Kali** using VirtualBox! 🚀  

---

📸 **Screenshots included in this repo**  
📝 Documented by *[AADITH C H]*  
