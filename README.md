# adb-hunter
A powerful Python tool **created by DEEPSEEK** for scanning the internet to discover exposed Android Debug Bridge (ADB) devices. This scanner can target specific IP ranges, regions, or perform continuous random scanning to find vulnerable devices.
Features

    Multi-region scanning: Focus on specific regions (North America, Europe, Asia, etc.)

    Multiple port support: Scan common ADB ports (5555, 5554, 5556, 5557)

    Geolocation data: Get approximate location and ISP information for found devices

    Flexible targeting: Support for single IPs, CIDR notation, and IP ranges

    High performance: Multi-threaded scanning for efficient large-scale operations

    Continuous scanning: Option for ongoing random scanning of different regions

    Detailed reporting: Save results to file with device information and locations
**Installation**

    git clone https://github.com/hxrofo/adb-hunter
    
    cd adb-hunter
    
    pip3 install requests --break-system-packages

**Usage Examples**

    python3 adb-hunter.py -o results.txt -c
    
    python3 adb-hunter.py -o results.txt -ip 192.168.1.1 192.168.1.100
    
    python3 adb-hunter.py -o results.txt -ip 192.168.1.0/24
    
    python3 adb-hunter.py -o results.txt -ip 192.168.1.1-192.168.1.100
    
    python3 adb-hunter.py -o results.txt -c -r europe asia -b 2000
    
    python3 adb-hunter.py -o results.txt -f targets.txt
    
    python3 adb-hunter.py -o results.txt -c -p 5555 5556 -t 200

    Type: python3 adb-hunter.py -h for help

**Output Format:**
   
    [+] ADB Found | Target: 123.45.67.89:5555 | Product: samsung | Model: SM-G950F | Device: dreamlte | Location: Berlin, Germany | ISP: Deutsche Telekom AG

**Disclaimer:**
   
   This tool is provided for educational and security research purposes only. The authors are not responsible for any misuse or damage     
   
   caused by this program. Always ensure you have proper authorization before scanning any network. 
    
