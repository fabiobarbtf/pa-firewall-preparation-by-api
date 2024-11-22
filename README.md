# Palo Alto Firewall Preparation by API

> The script consists of using the PAN-OS library for Pytrhon and the Palo Alto REST API to do the initial preparations of a firewall.

## 💻 Prerequisites

Before you begin, make sure you have met the following requirements:

* You have installed the Requests library `<pip install requests>`
* You have installed the Urllib3 library `<pip install urllib3>`
* You have installed the Time library `<pip install time>`
* You have installed the PAN-OS library `<pip install pan-os-python>`
* You have installed the Random library `<pip install random>`

## 🚀 Using the Palo Alto Firewall Preparation by API script

To use the <Palo Alto Firewall Preparation by API>, follow these steps:

1. Start the script as desired!
2. When starting, you must enter the IP Address, Username and Password configured on the firewall.
3. In addition, you must enter the Base Version that will be installed on the desired firewall (follow the versions present in the script).
4. After completing the steps above, the options menu will be available, where you can:
      Create Security Profiles Best Practices recommended by Palo Alto Networks itself;
      Create External Dynamics Lists recommended by Palo Alto Networks itself (license required);
      Delete the default settings and objects, which are configured on Palo Alto Networks physical firewalls;
      Configure a random password for the 'admin' user;
      Configure the Interface Management information (IP, Netmask, Gateway and DNS).
5. After using the desired function, simply choose function '8', and the script will close and the configured information will be saved in a .txt file

Note: The script does not commit the configurations made, to avoid losing access to the firewall due to possible errors.

## 🤝 Creator

To people who contributed and created this project:

<table>
  <tr>
    <td align="center">
      <a href="#">
        <img src="https://avatars.githubusercontent.com/u/144133682" width="100px;" alt="Photo by Fábio Barbosa on GitHub"/><br>
        <sub>
          <b>Fábio Barbosa</b>
        </sub>
      </a>
    </td>
  </tr>
</table>
