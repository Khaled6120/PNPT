
# Hunting Subdomains
There are both *active* and *passive* ways to find and identify subdomains of a target.
## Why Subdomains?
You may come across a bunch of different [subdomains](/networking/DNS/DNS.md) of a target domain during your investigation.

Gathering information on these subdomains is important because doing so will give you a better idea of the target landscape.
### Juicy Targets
#### Production Environments
- `dev.blank.blank`
- `qa.blank.blank`
- `stage`/`stg.blank.blank`
#### Abandoned Subdomains
If someone has abandoned a subdomain, it is vulnerable to [subdomain takeover](/cybersecurity/TTPs/delivery/subdomain-takeover.md).
##### What to look for:
Using the [dig](/CLI-tools/dig.md) command, you can spot a vulnerable subdomain when the server responds with `NXDOMAIN`, `SERVFAIL`, `REFUSED`, or `no servers could be reached`.

Once you've found a subdomain which is possibly abandoned, you can `dig` that as well.
## [Sublist3r](https://www.kali.org/tools/sublist3r/)
Sublist3r is a tool written in python which can be used to enumerate subdomains. It does so using search engines like Yahoo, Google, etc. so it is considered OSINT (b/c it's not actively trying to find subdomains using something like a wordlist on a root domain).

Sublist3r is capable of finding 3rd and 4th level domains.

*However* Sublist3r can be used to do brute force (active/ not OSINT) enumeration using the Subbrute integrated tool.
```
sudo apt install sublist3r
sublist3r -d DOMAIN_NAME(eg: tesla.com)
```
## [httprobe](https://github.com/tomnomnom/httprobe)
Take a list of domains and probe for working HTTP and HTTPS servers. (checking which domain is alive)
```
go install github.com/tomnomnom/httprobe@latest
cat DOMAINS_FILE.txt | httprobe
```

## [Crt.sh](https://crt.sh)

This site can be used to find subdomains deeper even than the second and third levels of a domain name. It can be used to find all of the sub and sub-sub-domains of a domain name.
## Other Resources
### [DNS Dumpster](https://dnsdumpster.com/)
A free online tool which you can use to discover hosts r/t a domain. Also includes hosting IP block, DNS servers, MX Records, TXT Records, etc.. 

## OWASP [Amass](/cybersecurity/tools/scanning-enumeration/dir-and-subdomain/amass.md)


You can also get a map of the domain and subdomains like this:
![](PNPT/PNPT-pics/hunting-subdomains-1.png)
![](/PNPT-pics/hunting-subdomains-1.png)

> [!Resources]
> - [Sublist3r](https://www.kali.org/tools/sublist3r/)
> - [IPlocation.io](https://iplocation.io/ssl-certificate-fingerprint)
> - [OWASP: Test for Subdomain Takeover](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)

