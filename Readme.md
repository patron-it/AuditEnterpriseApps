# AuditEnterpriseApps

Creates a report of Enterprise applications (Service Principals [API name]) and App registrations (Applications [API name]) for audit/review usage and to detect misconfigurations/vulnerabilities. 

* It reads out all information through Microsoft Graph (Required scopes: Directory.Read.All, CrossTenantInformation.ReadBasic.All)
* Combines the information to give you an overview of your Apps, their usage, permissions and configuration. So you can easily audit them.
* First party apps (from Microsoft), disabled apps and apps with no or low privileges are excluded from the report.

Script is suitable for small and medium organizations. For large organizations it can be too noisy and take hours to generate (reading out sign-in logs for all applications takes a lot of the time - it can be disabled by modifying ).

Sample report is included "[SampleReport.html](SampleReport.html)".

## What it can help you detect

You can use the report to detect:

* **Service Principals with role assigned**
* **Service Principals with dangerous application permissions**
* **Service Principals with dangerous delegated rights permissions**
* **Service Principals and Applications with owners assigned** - It can lead to lateral movement. When the owner account is compromised attacker can add secrets to the instance (Service Principal, Application) and impersonate the Service Principal.
* **Not used Service Principals** - Based on the sign-in logs. Unused Service Principals with permissions can be once misused (initial access, privilege escalation, persistence).
* **Expired secrets/keys for Service Principals/Applications** - can indicate abandoned/not used application.

**Recommended remediation**: The preferred way is to disable the Service Principal (set "Enabled for users to sign-in?" to No). It will effectively block all types of access for this application (User sign-ins [interactive and non-interactive] and Service Principal Sign-ins) while keeping all the configuration (in case you need to enable the app again).