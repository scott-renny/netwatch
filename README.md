> [!IMPORTANT]
> ## 📦 Legacy Engineering Portfolio Project
>
> This repository documents one of the custom infrastructure platforms I
> developed while building my home cybersecurity environment.
>
> Rather than deleting or replacing it, I have intentionally preserved
> it as part of my **Legacy Project Archive** to document my growth as
> an infrastructure and cybersecurity engineer.
>
> NET-WATCH demonstrates full-stack infrastructure engineering by
> combining network discovery, DNS policy management, bandwidth
> analytics, security monitoring, and web application development into a
> single operational dashboard.
>
> Every engineering decision, architectural tradeoff, implementation
> challenge, and lesson learned has been preserved to document the
> engineering process---not just the finished application.

# 📡 NET-WATCH

## Real-Time Network Visibility Platform

> **Real-time network visibility for a home SOC lab.**\
> Built on Ubuntu Server · Python Flask · Nmap · vnStat · Pi-hole v6 ·
> Wazuh · Nginx

------------------------------------------------------------------------

## Project Background

NET-WATCH started as a project to manage internet access schedules and
daily usage limits for different groups of devices on my home network.

As development progressed, it evolved into a complete infrastructure
monitoring platform that combines network discovery, DNS policy
management, bandwidth analytics, security monitoring, and device
management into a single dashboard.

What began as a family automation project became a practical exercise in
infrastructure engineering, Linux administration, backend development,
network security, and security operations.

------------------------------------------------------------------------

## Core Platform Capabilities

-   Continuous network discovery using Nmap
-   Profile-based scheduling and internet access policies
-   Pi-hole Group Management API integration
-   Per-profile DNS filtering
-   Real-time bandwidth monitoring via vnStat
-   Wazuh SIEM integration with MITRE ATT&CK mappings
-   Automatic startup using systemd

------------------------------------------------------------------------

## Technology Stack

  Layer                 Technology
  --------------------- ------------------------------------
  Backend API           Python 3 / Flask
  Network Scanning      Nmap
  Bandwidth Tracking    vnStat
  DNS Access Control    Pi-hole v6 REST API
  Security Monitoring   Wazuh REST API
  Web Server            Nginx
  Process Management    systemd
  Frontend              Vanilla JS / Chart.js / HTML + CSS
  Platform              Ubuntu Server 22.04

------------------------------------------------------------------------

## Engineering Capabilities Demonstrated

-   Infrastructure monitoring
-   Python backend development
-   REST API development
-   Linux administration
-   Network discovery automation
-   DNS policy enforcement
-   Security operations integration
-   Reverse proxy configuration
-   Dashboard development
-   System automation

------------------------------------------------------------------------

## Security+ Domain Mapping

  -----------------------------------------------------------------------
  Domain                              Coverage
  ----------------------------------- -----------------------------------
  **D2 --- Network Architecture**     Network segmentation, Pi-hole
                                      Groups, VLAN-ready configuration

  **D3 --- Implementation**           Nmap, vnStat, Nginx, UFW, Linux
                                      services

  **D4 --- Security Operations**      Wazuh SIEM, MITRE ATT&CK mapping,
                                      alerting, profile controls
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## Architecture Overview

``` text
Devices
      │
Continuous Nmap Discovery
      │
Python Flask Backend
      ├── Pi-hole API
      ├── Wazuh API
      ├── vnStat
      └── JSON Configuration
             │
         REST API
             │
      Web Dashboard
```

------------------------------------------------------------------------

## Project Structure

Retain your existing project structure from the original repository.

## Quick Install

Retain your existing installation instructions.

## API Endpoints

Retain your existing API endpoint documentation.

## Pi-hole Integration

Retain your existing Pi-hole integration documentation.

------------------------------------------------------------------------

## Future Enhancements

-   VLAN support
-   Wazuh vulnerability integration
-   Per-device bandwidth monitoring
-   Email/Webhook notifications
-   Optional authentication

------------------------------------------------------------------------

## Build Guide

The included build guide provides complete deployment instructions,
troubleshooting, validation steps, and portfolio checkpoints.

------------------------------------------------------------------------

## Engineering Philosophy

NET-WATCH represents an important milestone in my engineering journey.

Rather than simply deploying existing software, this project required
designing and integrating multiple independent systems into a unified
operational platform.

It reflects my approach to infrastructure engineering: automate
repetitive tasks, centralize visibility, document decisions, and
continuously improve through iterative development.

------------------------------------------------------------------------

## Current Engineering Focus

-   🛡️ Cyber Operations Center Engineering Program *(Flagship Project)*
-   🏗️ Project Atlas
-   🐉 Project Hydra
-   🏛️ Project Olympus
-   🔥 Project Hestia

------------------------------------------------------------------------

## Author

**Scott Renny**

Aspiring SOC Analyst • Infrastructure Engineer • Home Lab Builder
