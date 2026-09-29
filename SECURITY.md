# Security Policy

This repository is defensive traffic-analysis tooling.

## Safety boundaries

The analyzer:

- reads authorized PCAP/PCAPNG files or authorized interface traffic
- stores metadata summaries only
- does not save packet payloads
- does not inject, replay, modify, or transmit packets
- does not extract passwords, cookies, tokens, or message contents
- does not scan networks or bypass access controls

Only capture traffic on systems and networks where you have explicit authorization. Treat IP addresses, DNS names, and traffic reports as potentially sensitive.

## Reporting

Use a private security report when possible. Do not attach credentials, private PCAPs, or personal data to public issues.