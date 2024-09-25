# Home Lab

## Objective

The Home Lab project was created to provide a controlled environment for hands-on experience with various programs, with a strong focus on learning and gaining experience in SIEM. Another objective was to practice following documentation on installations, configurations, and integrations while troubleshooting and resolving issues that arise. The experience aimed to further my knowledge of Linux/Windows and to set up a lab to replicate attacking, defending, and detecting in future projects.

### Skills Learned

- Installations and configurations of various programs within Linux and Windows
- Integrating programs within one another
- Enhanced problem solving and researching skills when faced with various technical challenges
- Advanced understanding of SIEM concepts and practical application
- Proficiency in analyzing and interpreting network logs
- Ability to generate and recognize attack signatures and patterns

### Tools Used

- VirtualBox - A Virtualization software that allows uers to create and run virtual machines
- Wazuh - A Security Information and Event Management (SIEM) system for log ingestion and analysis
- Suricata - An Intrusion Detection system (IDS) and Intrusion Prevention System (IPS) to detect and monitor networks for suspicious activity
- VirusTotal - An online service that analyzes files, URLs, domains, and IP Addresses to detect malware and other threats

## Steps

#### <ins>Virtual Machine and Wazuh Setup
- Downloaded and installed Windows and Ubuntu VDI files into VirtualBox  
- Configured all VMs with appropriate CPU/Storage and a NAT network
- Downloaded and installed Wazuh v4.8.1 OVA into VirtualBox with a bridged network connection
  
  ![WINWORD_6yrQJzCiyK](https://github.com/user-attachments/assets/28c7a83d-0bca-429f-b2f2-c49e929c8062)

#### <ins>Adding Agents
- Ran the following command with the appropriate local IP to install the agent on the Linux VM:
  ```bash
  wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.8.2-1_amd64.deb &&
  sudo WAZUH_MANAGER='Local IP' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='Linux' dpkg
  -i ./wazuh-agent_4.8.2-1_amd64.deb
- After the installation completed, the following command was ran to start the agent:
  ```bash
  sudo systemctl daemon-reload
  sudo systemctl enable wazuh-agent
  sudo systemctl start wazuh-agent
- Ran the following command in PowerShell with the appropriate local IP to install the agent on the Windows VM:
  ```powershell
  Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.8.2-1.msi
  -OutFile ${env.tmp}\wazuh-agent; msiexec.exe /i ${env.tmp}\wazuh-agent /q WAZUH_MANAGER='Local IP'
  WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='Windows'
- After the installation completed, the following command was ran to start the agent:
  ```powershell
  NET START WazuhSvc
- All agents connected, see image below
  
   ![WINWORD_4VP0V33yKY](https://github.com/user-attachments/assets/4264ec7f-2a01-4923-9ab1-aca6012c2d0c)

#### <ins>Suricata Installation and Configuration
- Added the Suricata repository to the Linux system with:
  ```bash
  sudo add-apt-respository ppa:oisf/suricata-stable
- The following command is used to update the package list on the system and to install it, a -y flag was used to answer yes to all prompts:
  ```bash
  sudo apt-get update && sudo apt-get install suricata -y
- Enabled Suricata on start up with:
  ```bash
  sudo systemctl enable suricata.service
- Ran ‘ip a s’ in the terminal to gather the IP and subnet range
- Ran 'ifconfig' in the terminal to gather the correct network interface
- Entered Suricata configuration files at /etc/suricata/suricata.yaml with:
  ```bash
  sudo vim /etc/suricata/suricata.yaml
  ```
    - *Use / to find the following and i to insert/change text*:
    - Changed the IP connected to HOME_NET to match the local IP of the home device
    - Changed the interface of af-packet to match system's interface
    - Changed the interface of pcap to match the system's interface
    - Changed the value of community-id from false to true so records matched outputs on other tools
    - ctrl + c :wq to save and quit the file
- Updated Suricata:
  ```bash
  sudo suricata-update
- Ran the following command to show all available rules for Suricata
  ```bash
  sudo suricata-update list-sources
  ```
- Added maliso/win-malware for additional rules with the following command:
  ```bash
  sudo suricata-update enable-source malislo/win-malware
- To test if all configurations were correct the following command was ran:
  ```bash
  sudo suricata -T -c /etc/suricata/suricata.yaml -v
  ```
  ![WINWORD_itf7v7Np56](https://github.com/user-attachments/assets/0f9b5a28-4656-4e09-93b4-96aea0c45f6e)

#### <ins>Suricata Integration
- Opened the suricata.yaml file with the following:
  ```bash
  sudo vim /etc/suricata/suricata.yaml
  ```
- Changed the configuration of outputs to the following:
  ```xml
  - outputs:
     syslog:
      enabled: yes
      facility: local1
      format: "[%i] <%d> -- "
      server: local IP
      port: 514
  ```
- Opened the ossec.conf file at /var/ossec/etc/ossec.conf with the following:
  ```bash
  sudo vim /var/ossec/etc/ossec.conf
  ```
- Added configuration:
  ```xml
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
  ```
- After :wq, the Wazuh Agent was restarted with:
  ```bash
  sudo systemctl restart wazuh-agent
  ```
- Restarted Suricata with:
  ```bash
  sudo systemctl restart suricata
  ```
- Added the following configuration in /var/ossec/etc/ossec.conf on the Wazuh Manager to receive logs from Suricata via syslog:
  ```xml
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>tcp</protocol>
    <allowed-ips>10.0.2.15</allowed-ips>
  </remote>
  ```
  
#### <ins>Testing the Integration
- To test if Suricata was properly integrated into Wazuh, the following command was ran:
  ```bash
  curl http://testmynids.org/uid/index.html
  ```
- In a separate terminal, the following command was ran:
  ```bash
  sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
  ```
- Received output:
  ```bash
  alert ip any any -> any any (msg:”GPL ATTACK_RESPONSE id check returned root”;
  content:”uid=0|28|root|29”; classtype:bad-unknown; sid:2100498; rev:7; metadata:created_at 2010_09_23;)
- To confirm Wazuh received the Suricata log, I logged into the Wazuh Dashboard via local IP > Threat Hunting > Events:

  ![WINWORD_ZSw5JUKPoH](https://github.com/user-attachments/assets/61a45470-9980-4513-949b-cd17c01c997c)

#### <ins>Integrating VirusTotal
- Opened the configuration file /var/ossec/etc/ossec.conf on the Wazuh server with the following command:
  ```bash
  sudo vim /var/ossec/etc/ossec.conf
  ```
    - Added configuration
  ```xml
  <integration>
  <name>virustotal</name>
  <api_key> Log into virustotal to obtain API key </api_key>
  <group>syscheck</group> 
  <alert_format>json</alert_format>
  <integration>
- Added the following configuration to the <syscheck> section of the configuration file, the path is subjective, I used "/home/ant/Documents".
  ```xml
  <directories check_all="yes" realtime="yes">/home/ant/Documents</directories>
- Once done, :wq to save and quit. Restarted wazuh-manager with the following command:
  ```bash
  sudo systemctl restart wazuh-manager
  ```
- I downloaded the Eicar file which is a safe malicious file meant to be used for testing:
  ```bash
  sudo curl -Lo /home/ant/Documents/suspicious-file.exe https://secure.eicar.org/eicar.com
- To test the integration, I logged into the Wazuh dashboard via local IP > VirusTotal:

  ![chrome_Utpnfy2SlJ](https://github.com/user-attachments/assets/ed4ca871-9fbf-4ede-aa57-8bf0fd13b91e)

