## Deployment Notes for Cloudflare Integration with HCL Domino Server Setup

These notes are from a deployment done in 2024.

### Deployment of HCL Domino v12 or v14 server(s) on VPS

<table>
<tr>
<th>
Location
</th>
<th>
Server Final Name
</th>
<th>
Linux Host FQDN
</th>
<th>
IP Address
</th>
<th>
Remarks
</th>
</tr>

<tr>
<td>
VPS1 AlmaLinux9
</td>
<td>
S1/ACME
</td>
<td>
s1.acme.org
</td>
<td>
Private: ppp.qqq.rrr.sss
</td>
<td>
First server, AdminP server, CA server, ID vault, CertMgr server
</td>
</tr>

<tr>
<td>
VPS2 AlmaLinux9
</td>
<td>
S2/ACME
</td>
<td>
s2.acme.org
</td>
<td>
Public: aaa.bbb.ccc.ddd 
</td>
<td>
Additional server, Web & App server, Router, HTTP, CertMgr client
</td>
</tr>

<tr>
<td>
VPS3 AlmaLinux9
</td>
<td>
S3/ACME
</td>
<td>
s3.acme.org
</td>
<td>
Public: eee.fff.ggg.hhh
</td>
<td>
Additional server, Mail server,  Router, HTTP, POP. IMAP, SMTP, CertMgr client
</td>
</tr>
</table>

#### Domino installation directories:

<table>
<tr>
<th>
Server
</th>
<th>
Sx/ACME
</th>
</tr>

<tr>
<td>
Program Directory
</td>

<td>
/opt/hcl/domino
</td>
</tr>

<tr>
<td>
Data Directory
</td>

<td>
/local/notesdata
</td>
</tr>

<tr>
<td>
Logs Directory
</td>

<td>
/local/notesdata and /var/log
</td>
</tr>
</table>

S1/ACME - Admin server with minimal essential services, encrypted databases with secure ACLs, to be connected only through private IP address accessible through VPN to HCL Notes Administrator client application over port 1352, NRPC protocol.

Installed – AdminP, CA, ID Vault, CertMgr

Not installed - HTTPS, LDAP, POP, IMAP, SMTP

S2/ACME – Web & App server with Router, HTTP, CertMgr client, encrypted databases with secure ACLs, to be connected using HCL Notes Administrator client application over port 1352, NRPC protocol; HCL Domino Volt and Xpages-based Web Apps over port 443, HTTPs protocol; HCL Verse over port 443, HTTPs protocol. 

Not installed – CA, ID Vault, LDAP, POP, IMAP, SMTP

Public IP ‘aaa.bbb.ccc.ddd’ used for web access needs to be protected from DDoS attacks 

S3/ACME – Mail server with Router, LDAP, HTTP, POP, IMAP, SMTP, CertMgr client, encrypted databases with secure ACLs, to be connected using HCL Notes Administrator client application over port 1352, NRPC protocol. SMTPs connected only to external mail relay (Zoho) through 465/ 587.

Not installed – CA, ID Vault, LDAP

Public IP ‘eee.fff.ggg.hhh’ not being used for web access.

KeepassXC or Veracrypt can be used by admins as secure repository for certificates and keys. KeepassXC repository can also be used by clients for TOTP on desktops/ laptops.

The repositories can be stored securely in a bucket on Cloudflare R2, the high-performance storage for files and objects with zero egress charges. Manage through S3 API, public URL access not allowed

### Configure Cloudflare DNS for acme.org domain for use with HCL Domino 14 server(s) on VPS

Subscribe to acme.org domain through Cloudflare or any other registrar

Add acme.org site to Cloudflare free acct (2FA enabled)

Account ID: 

Zone ID: 

<table>
<tr>
<th>
Type
</th>
<th>
Name
</th>
<th>
Content
</th>
<th>
Proxy status
</th>
<th>
TTL
</th>
</tr>

<tr>
<td>
A
</td>
<td>
acme.org
</td>
<td>
aaa.bbb.ccc.ddd
</td>
<td>
Proxied
</td>
<td>
Auto
</td>
</tr>

<tr>
<td>
AAAA
</td>
<td>
acme.org
</td>
<td>
</td>
<td>
Proxied
</td>
<td>
Auto
</td>
</tr>

<tr>
<td>
CNAME
</td>
<td>
s2
</td>
<td>
acme.org
</td>
<td>
Proxied
</td>
<td>
Auto
</td>
</tr>

<tr>
<td>
CNAME
</td>
<td>
app
</td>
<td>
acme.org
</td>
<td>
Proxied
</td>
<td>
Auto
</td>
</tr>

<tr>
<td>
CNAME
</td>
<td>
verse
</td>
<td>
acme.org
</td>
<td>
Proxied
</td>
<td>
Auto
</td>
</tr>

<tr>
<td>
A
</td>
<td>
s3
</td>
<td>
eee.fff.ggg.hhh
</td>
<td>
Proxied
</td>
<td>
Auto
</td>
</tr>
  
<tr>
<td>
MX
</td>
<td>
mail
</td>
<td>
mx.zoho.com
</td>
<td>
DNS Only
</td>
<td>
Auto
</td>
</tr>
</table>

NS    xx.ns.cloudflare.com    yy.ns.cloudflare.com

#### Create API tokens, view Global API key, Origin CA key

[https://dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)

Cloudflare root and other certificates, Global API key, Origin CA key, Origin Server key to be stored securely.

#### DNSSEC - Enabled

DNSSEC protects against forged DNS answers. DNSSEC protected zones are cryptographically signed to ensure the DNS records received are identical to the DNS records published by the domain owner.

#### CNAME Flattening - Done

Cloudflare will follow a CNAME to where it points and return that IP address instead of the CNAME record. By default, Cloudflare will only flatten the CNAME at the root of your domain.

Flatten CNAME at root acme.org

#### Automatic HTTPS Rewrites - Enabled

Automatic HTTPS Rewrites helps fix mixed content by changing “http” to “https” for all resources or links on your web site that can be served with HTTPS.

#### Always Use HTTPS - Enabled

Redirect all requests with scheme “http” to “https”. This applies to all http requests to the zone.

#### Brotli - Enabled

Speed up page load times for your visitor’s HTTPS traffic by applying Brotli compression.

#### SSL/TLS

Advanced Certificate Manager - Universal SSL (current plan) $0.00 / month

Basic certificate: Dedicated to your domain, Only protects acme.org and *.acme.org, Common name of ssl123456.cloudflaressl.com

Edge certificates:  encrypt traffic between your visitors and Cloudflare.

<table>
<tr>
<th>
Hosts
</th>
<th>
Type
</th>
<th>
Status
</th>
<th>
Expires On
</th>
</tr>

<tr>
<td>
*.acme.org, acme.org
</td>
<td>
Universal
</td>
<td>
Active
</td>
<td>
2025-04-01(Managed)
</td>
</tr>

<tr>
<td>
*.acme.org, acme.org
</td>
<td>
Backup
</td>
<td>
Backup Issued
</td>
<td>
2025-04-01(Managed)
</td>
</tr>
</table>

The universal certificates for acme.org, *.acme.org are managed and auto-renewed by Cloudflare from LetsEncrypt.

Certificate - ECDSA SHA384

Expiration - 2025-04-01 (Managed by Cloudflare)

Certificate Validity Period - 3 months

Certificate validation method - TXT

Certificate Authority - Let's Encrypt

#### Client Certificates

Create client certificates using Cloudflare public key infrastructure (PKI).

Secure and authenticate your APIs and web applications with client certificates. Block traffic from devices that do not have a valid client SSL/TLS certificate with mTLS rules.

Hosts - Choose which host(s) you wish to enable mTLS (preferably hosts used for admin purpose)

#### SSL/TLS encryption mode is Full (strict)

Encrypts end-to-end but requires a trusted CA or Cloudflare Origin CA certificate on the server. 

Origin Server - Customize encryption of traffic between your origin server and Cloudflare.

Origin Certificates - Generate free TLS certificate signed by Cloudflare to install on your origin server.

Origin Certificates are only valid for encryption between Cloudflare and your origin server.

Authenticated Origin Pulls – Not Enabled

TLS client certificate presented for authentication on origin pull.

Custom Hostnames – Not Enabled

Extend the security and performance benefits of Cloudflare’s network to your customers/ collaborators via their own custom domains.

SSL/TLS Recommender - Enabled

To check if your website can use a more secure SSL/TLS mode, enable the SSL/TLS Recommender. Receive an email with Cloudflare’s recommendation.

HTTP Strict Transport Security (HSTS) – Not Enabled

Enforce web security policy for your website.

Minimum TLS Version – 1.2

Only allow HTTPS connections from visitors that support the selected TLS protocol version or newer.

TLS 1.3 - Enabled

Enable the latest version of the TLS protocol for improved security and performance.

Opportunistic Encryption - Enabled

Opportunistic Encryption allows browsers to benefit from the improved performance of HTTP/2 by letting them know that your site is available over an encrypted connection. Browsers will continue to show “http” in the address bar, not “https”.

Encrypted ClientHello (ECH) - Enabled by default for Free zones.

Enable the Encrypted ClientHello feature for the TLS 1.3 protocol for improved privacy.

Certificate Transparency Monitoring - Enabled

Receive an email when a Certificate Authority issues a certificate for your domain.

Disable Universal SSL - No

#### Security

##### WAF

Zone-level Web Application Firewall (WAF) detects and mitigates malicious requests across all traffic under this zone.

Custom Rules - Protect your website and API from malicious traffic with custom rules. Configure mitigation criteria and actions, or explore templates, for better security.

Geo Block custom rule added

IP Access Rules - IP Access Rules can be based on IP address, IP address range, Autonomous System Number (ASN) or country.

##### DDoS

Automatic DDoS protection that constantly analyzes traffic and generates real-time signatures to mitigate attacks across the network and application layers.

HTTP DDoS attack protection

Ruleset managed by Cloudflare that automatically mitigates HTTP-based DDoS attacks such as HTTP floods, amplification HTTP attacks, and reflection HTTP attacks. HTTP DDoS attack protection is always enabled.

Network-layer and SSL/TLS DDoS attack protection

Rulesets managed by Cloudflare that automatically mitigate SSL/TLS-based and Network-layer DDoS attacks. Network-layer DDoS attack protection protects all Cloudflare customers.

SSL/TLS DDoS attack protection - Automatic mitigation of SSL/TLS based DDoS attacks and encryption-based attacks such as DDoS attacks, SSL exhaustion floods, and SSL negotiation attacks.

Network-layer DDoS attack protection - Automatic mitigation of network-layer DDoS attacks such as ACK floods, SYN-ACK amplification attacks, UDP attacks, ICMP attacks and DDoS attacks launched by botnets such as Mirai.

##### Network

IPv6 Compatibility - Enabled

Enable IPv6 support and gateway.

WebSockets - Enabled

Allow WebSockets connections to your origin server.

##### Web3

Develop Web3 applications without having to run infrastructure.

### Configuring for Full (Strict) SSL/TLS

Generate SSL/TLS Origin Server certificate and key to install in HCL Domino certmgr.nsf (on S1) and used by S2 & S3. Follow the steps below to generate a certificate on your origin server:

The first step in generating a certificate for your origin is creating a private key and a Certificate Signing Request (CSR). You can provide your own CSR or we can generate a key and CSR using your web browser.

Generate private key (ECC) and CSR with Cloudflare - acme.org.pem and acme.org.key

List the hostnames (including wildcards) on your origin that the certificate should protect. By default your origin certificate covers the apex of your domain (example.com) and wildcard (*.example.com). Hostnames *.acme.org, acme.org

Choose how long before your certificate expires. By default your certificate will be valid for fifteen (15) years. If you’d like to decrease how long your certificate will be valid make a selection below.

Certificate Validity 15 years

Save the certificate and private key below to your client. To save, Click to copy and paste the contents into different files on your client, e.g. acme.org.pem and acme.org.key

Key Format PEM, PKCS#7, DER

Origin Certificate (public key .pem, .p7b, .der)

Private Key (.key)

Copy the contents of your private key below to your web server and set file permissions such that only your http server can access it. Additionally, you can optionally encrypt this file and provide a password to decrypt it during your origin web server startup. The private key data will not be stored at Cloudflare and will no longer be accessible once the creation is complete. Please make sure you have a local copy of this key. 

Web Server for Installation: Instructions specific to HCL Domino are given separately.

#### Cloudflare configuration on VPS2 and VPS3 

Configure firewall to allow IP addresses of origin server

https://developers.cloudflare.com/fundamentals/setup/allow-cloudflare-ip-addresses/

https://www.cloudflare.com/ips/

#### Configure HCL Domino servers

**CertMgr configuration**

Configure CertMgr to use Cloudflare Origin certificates for acme.org

a) Cloudflare Edge certificates: The universal certificates for acme.org, *.acme.org are managed and auto-renewed by Cloudflare from LetsEncrypt.

Set Cloudflare SSL/TLS encryption mode to Full (strict): Encrypts end-to-end, but requires a trusted CA or Cloudflare Origin CA certificate on the server

b) Install Cloudflare Root and Origin certificates to be installed in HCL Domino certmgr.nsf. 

Cloudflare root certificate

[https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/#cloudflare-origin-ca-root-certificate](https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/) 

Cloudflare Origin Server certificate [generate from Cloudflare dashboard- SSL/TLS-Origin Server free TLS certificate signed by Cloudflare to install on your origin server. Origin Certificates are only valid for encryption between Cloudflare and your origin server. TLS certificate is generated for two hosts - *.acme.org, acme.org]

Authenticated Origin Pulls Enabled. TLS client certificate presented for authentication on origin pull.

[https://opensource.hcltechsw.com/domino-cert-manager/faq/](https://opensource.hcltechsw.com/domino-cert-manager/faq/)

[https://support.cloudways.com/en/articles/5130554-how-to-configure-cloudflare-origin-certificate](https://support.cloudways.com/en/articles/5130554-how-to-configure-cloudflare-origin-certificate)

Start CertMgr server on S1:

On S1 console

load certmgr    [Domino CertMgr v14 is started]

CertMgr: Configuring domain wide CertMgr server …

CertMgr: Certificate Manager started

CertMgr: Cannot open CertStore when reading global configuration : File does not exist

CertStore: Created new CertStore database [certstore.nsf]

CertStore: Publish CertMgr [CN=S1/O=ACME] in Domino Directory profile

CertStore: Info: Updated CertMgr server in Domino Directory -> [CN=S1/O=ACME]

CertMgr: Info: New Proxy Account created

Check Certificate Store (certstore.nsf) ACL. LocalDomainAdmins and LocalDomainServers should have Manager access and the Administrator role. Admin/ACME should be in LocalDomainAdmins group and S1/ACME should be in LocalDomainServers group.

On S1, configure Certificate Manager for TLS certificates generated as Cloudflare Origin certificates

Cert Manager Server: S1

1. Edit Global Settings:

Admin server: S1/ACME

Key algorithm: ECDSA, NIST P-256

Certificate provider: Manual (to use Cloudflare Origin CA)

2. Add Cloudflare Origin CA Root certificate into CertMgr (certstore.nsf): 

Paste the contents of ‘origin_ca_ecc_root.pem’ into CertMgr Configurations-Trusted Roots-Add Trusted Root-Certificates-Paste Certificates & Roots (PEM) and Submit.

Check in Trusted Roots that OU=CloudFlare Origin SSL ECC Certificate Authority/O=CloudFlare, Inc./L=San Francisco/ST=California/C=US is added as  trusted root certificate

3. CertMgr-TLS Credentials-By Hostname-Add TLS Credentials

Host names: acme.org

Servers with access: <select S1/ACME, S2/ACME, S3/ACME from Domino Directory.

Certificate provider: Manual

Keyring file: acme.org 

Add trusted root certificate: select Security/Keys tab of the TLS Credentials document, in the Trusted Roots field, select the Cloudflare trusted root certificate you added previously to certstore.nsf.

4. Import into CertMgr a PEM file containing concatenated public and private keys of the issued Cloudflare Origin certificate [cloudflare_origin_certificate_pub&key.pem]

Method 1: CertMgr-TLS Credentials-Import TLS Credentials 

In the Action field, select Import TLS credentials only - Not exportable.

In the Format field, select encryption format: Base64 encoded X.509 (PEM, AES256 encrypted)

In the File name field, select the file containing the certificates to import.

Password field need not be filled since TLS credentials are not exportable

Results

CertMgr writes the new certificate chain to the new TLS Credentials document. Any Domino server listed in the Servers with access field can use the certificate chain once the new document replicates to its replica of the certstore.nsf database.

Method 2: Use S1 server console

Upload file cloudflare_origin_certificate_pub&key.pem (having cloudflare origin certificate public & private keys) to S1 domino data directory

[https://help.hcltechsw.com/domino/14.0.0/admin/secu_le_certmgr_commands.html](https://help.hcltechsw.com/domino/14.0.0/admin/secu_le_certmgr_commands.html) 

load certmgr -importpem cloudflare_origin_certificate_pub&key.pem

CertMgr: Successfully imported [cloudflare_origin_certificate_pub&key.pem]

CertMgr: Shutdown

load certmgr -showcerts

Subject key identifier    Key info     Expiration   KeyFile/Tag            Host names (SANs)

C027 156E E70A 90F1 ...   NIST P-256    15.0 years                         *.acme.org acme.org

1 TLS Credentials

CertMgr: Shutdown

S1 is not configured for Internet (https) access. Hence, once the additional servers S2 and S3 (with https active) are added and replication to S1 server is done, open CertMgr on S2 and S3, open the issued certificate and add S2/ACME and S3/ACME to the Servers with access. This will enable S2 and S3 servers to also use the TLS certificates

### Use Zoho Mail and Mail Relay for HCL Domino

Configuring S3/ACME for email routing of [users@acme.org](mailto:users@acme.org) through Zoho Mail

Zoho Mail business account: Mail Lite (Paid) Users (total 3)

[admin@acme.org](mailto:admin@acme.org), Admin ACME, User Id: 99999999

[user1@acme.org](mailto:user1@acme.org), User1 ACME, User Id:

[user2@acme.org](mailto:user2@acme.org), User2 ACME, User Id:

Use Zoho Directory (Free plan - 10 Users):

[https://directory.zoho.com/directory/acme/adminhome#/orgdomains](https://directory.zoho.com/directory/acme/adminhome#/orgdomains) 

[https://directory.zoho.com/directory/acme/home#/myapps](https://directory.zoho.com/directory/acme/home#/myapps)

Map to custom domain to enable users to access Zoho Directory through registered custom domain.

Verify the ownership of the custom domain name by setting up CNAME record in your domain name provider's website:

CNAME    zohodir directory.zoho.com/directory/acme/

Zoho mail business acct – [admin@acme.org](mailto:admin@acme.org), [user1@acme.org](mailto:user1@acme.org) 

poppro.zoho.com:995

smtppro.zoho.com:587

[https://support.plesk.com/hc/en-us/articles/12377663714711-How-to-verify-that-SSL-for-IMAP-POP3-SMTP-works-and-a-proper-SSL-certificate-is-in-use](https://support.plesk.com/hc/en-us/articles/12377663714711-How-to-verify-that-SSL-for-IMAP-POP3-SMTP-works-and-a-proper-SSL-certificate-is-in-use) 

Zoho mail acct checks using >openssl s_client OR >gnutls-cli

$ gnutls-cli -p 995 poppro.zoho.com

$ gnutls-cli -p 465 eee.fff.ggg.hhh

Configure domain acme.org for split delivery between Zoho and HCL Domino S3/ACME Mail Servers:

[https://www.zoho.com/mail/help/adminconsole/configure-dual-delivery.html](https://www.zoho.com/mail/help/adminconsole/configure-dual-delivery.html) 

[https://www.zoho.com/mail/help/adminconsole/email-routing.html](https://www.zoho.com/mail/help/adminconsole/email-routing.html)

User [user1@acme.org](mailto:user1@acme.org) exists in both Zoho and Domino mail servers  

User [admin@acme.org](mailto:admin@acme.org) exists only in Zoho mail server

User [user2@acme.org](mailto:user2@acme.org) exists only in Domino mail server

#### Configure S3/ACME to relay mail through Zoho ACME setup

Configuration Document

Router/ SMTP >> Basic: Add number of mailboxes to 2 and SMTP mail server IP in the

relay host for messages leaving local internet domain.

Router/ SMTP >> Advance >> Journaling: Enable Journaling and the following as shown

below in the screenshot.

SMTP Server Implementation Steps

Setting up SMTP Routing

The following settings needs to be done in the configuration document

Configuration Settings >> Router/SMTP >> Basic: The Relay host for messaging leaving internet

local domain should not have any value. In this case the SMTP server will connect directly to the other SMTP severs directly.

Configuration Settings >> Router/SMTP >> Restriction and Controls >> SMTP Inbound

Controls: Adding IP addresses of the local mail and app servers and Enabling the Domain

Authentication Controls

Configuring DKIM signing for messages routed to external Internet domains

The Domino SMTP server is configured with the DKIM signing. The setup is done using the

following link [https://help.hcltechsw.com/domino/12.0.2/admin/conf_dkimsigning.html](https://help.hcltechsw.com/domino/12.0.2/admin/conf_dkimsigning.html)

#### Configure Email Routing in Zoho Mail

Add new routing configuration:

Domain to enable email routing: acme.org

Destination host (Domain name / MX / IP Address): s3.acme.org

Verification email address: [admin@acme.org](mailto:admin@acme.org) 

Inbound Gateway

Outbound Gateway


### Zero Trust configuration

#### Settings-Downloads

Download certificate and deploy it to your end users' browsers. If the browser is not using this certificate, the user will encounter a browser error for HTTPS connections.

Download Cloudflare WARP client that allows individuals or organizations to have a faster, more secure and private experience online.

Download cloudflared,  a lightweight daemon that runs in your infrastructure and lets you securely expose internal resources to the Cloudflare edge.

cloudflared

https://github.com/cloudflare/cloudflared

https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/

Cloudflare Tunnel provides you with a secure way to connect your resources to Cloudflare without a publicly routable IP address. With Tunnel, you do not send traffic to an external IP — instead, a lightweight daemon in your infrastructure (cloudflared) creates outbound-only connections to Cloudflare’s global network. Cloudflare Tunnel can connect HTTP web servers, SSH servers, remote desktops, and other protocols safely to Cloudflare. This way, your origins can serve traffic through Cloudflare without being vulnerable to attacks that bypass Cloudflare.

Add cloudflared packages

https://pkg.cloudflare.com/index.html

Ubuntu 22.04 (Jammy Jellyfish)

Add cloudflare gpg key

sudo mkdir -p --mode=0755 /usr/share/keyrings

curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null

Add this repo to your apt repositories

echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared jammy main' | sudo tee /etc/apt/sources.list.d/cloudflared.list

install cloudflared

sudo apt-get update && sudo apt-get install cloudflared

If you installed cloudflared with a package manager, you must update it using the same package manager. On Linux, you can check if cloudflared is owned by a package manager by running

$ ls -la /usr/local/etc/cloudflared/

-rw-r--r-- 1 root root    0 Oct  4 21:32 .installedFromPackageManager

To update, again run sudo apt-get install cloudflared

https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/

$ cloudflared tunnel --url http://localhost:8080

https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/get-started/create-remote-tunnel/

https://developers.cloudflare.com/fundamentals/setup/account-setup/add-site/

#### Settings-WARP Client

Manage preferences for the WARP client

#### Settings-Custom Pages

Personalize the Cloudflare Zero Trust experience for your end-users.

#### Settings-Network

Manage your filtering preferences for outbound traffic.

#### Settings-Authentication

Set global preferences for applications protected behind Access.

#### My Team-Devices

Cloudflare Zero Trust allows you to establish which users in your organization can enroll new devices or revoke access to connected devices.

##### My Team-Devices-Connect a device

1. Create a device enrollment policy

Define who can connect devices to your organization. Users, whose email id ends in @acme.org

2. Install WARP client on end devices.

3. Enter your team name on end devices via WARP - acme

On the installed WARP client, navigate to Preferences > Account. Click “Login with Cloudflare Zero Trust” and enter the team name below. Opens a window for sending the login code to email id and verifying the code on the WARP login app

[https://acme.cloudflareaccess.com/cdn-cgi/access/verify-code/acme.cloudflareaccess.com](https://acme.cloudflareaccess.com/cdn-cgi/access/verify-code/acme.cloudflareaccess.com)

Once verified, open in browser [https://acme.cloudflareaccess.com](https://acme.cloudflareaccess.com) or installed WARP client

4. Download the Cloudflare root certificate – use option B below. This option is only necessary when you plan to [enable TLS Decryption](https://developers.cloudflare.com/cloudflare-one/policies/filtering/http-policies/tls-decryption/) for your account.

Install and deploy this certificate on devices connected to Cloudflare Zero Trust. This will prevent connection issues, as well as enable advance security features like HTTP filtering.

A. [https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/user-side-certificates/](https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/user-side-certificates/)

B. [https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/user-side-certificates/install-cert-with-warp/](https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/user-side-certificates/install-cert-with-warp/)    

Use the installed Cloudflare WARP client to connect to Cloudflare network.

To login into Zero Trust Access using One-time PIN login

[https://acme.cloudflareaccess.com](https://acme.cloudflareaccess.com) to open the Zero Trust App Launcher

Cloudflare Access can send a one-time PIN (OTP) to approved email addresses as an alternative to integrating an identity provider. You can simultaneously configure OTP login and the identity provider of your choice to allow users to select their own authentication method.

For example, if your team uses Okta® or Keycloak but you are collaborating with someone outside your organization, you can use OTP to grant access to guests.

##### Set up OTP

In Zero Trust, go to Settings > Authentication.

Under Login methods, select Add new.

##### Select One-time PIN.

If your organization uses a third-party email scanning service (for example, Mimecast or Barracuda), add noreply@notify.cloudflare.com to the email scanning allowlist.

To grant a user access to an application, simply add their email address to an Access policy.

##### Log in with OTP

To log in to Access using the one-time PIN:

Go to the application protected by Access.

On the Access login page, enter your email address and select Send me a code.

Enter email to sign in with OTP.

If the email is allowed by an Access policy, you will receive a PIN in your inbox. This secure PIN expires 10 minutes after the initial request.

By design, blocked users will not receive an email. The login page will always say A code has been emailed to you, regardless of whether or not an email was sent.

Paste the PIN into the Access login page and select Sign in.

Enter PIN to sign in.

If the code was valid, you will be redirected to the application.

If the code was invalid, you will see That account does not have access.

Once connected, device details can be seen under My Team-Devices
