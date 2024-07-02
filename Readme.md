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

## Dangerous application permissions

Following application permissions can lead to full tenant compromise.

* **RoleManagement.ReadWrite.Directory** - Allows the app to add itself (and any other application/user) to any role (eg. become Global Admin). PoC: [Azure Privilege Escalation via Azure API Permissions Abuse](https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48)
* **AppRoleAssignment.ReadWrite.All** - Allows the app to add itself (and any other application) any permission including "RoleManagement.ReadWrite.Directory" and become a Global Admin. PoC: [Azure Privilege Escalation via Azure API Permissions Abuse](https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48)
* **Domain.ReadWrite.All** - Allows to setup federation and impersonate any user even bypassing MFA. PoC: [Entra Roles Allowing To Abuse Entra ID Federation for Persistence and Privilege Escalation](https://medium.com/tenable-techblog/roles-allowing-to-abuse-entra-id-federation-for-persistence-and-privilege-escalation-df9ca6e58360).
* **RoleAssignmentSchedule.ReadWrite.Directory** - Read, update, and delete all policies for privileged role assignments of your company's directory. It is a PIM/PAM thing has to try the misuse.
* **RoleEligibilitySchedule.ReadWrite.Directory** - Read, update, and delete all eligible role assignments and schedules for your company's directory. It is a PIM/PAM thing has to try the misuse.
* **Application.ReadWrite.All** - Allows the calling app to create, & manage (read, update, update application secrets and delete) applications & service principals without a signed-in user. This also allows an application to act as other entities & use the privileges they were granted.
* **Organization.ReadWrite.All** - Enables to add trusted CA for Certificate-based authentication (it needs to be enabled).
* **Organization.ReadWrite.All + (Policy.ReadWrite.AuthenticationMethod or Authentication Policy Admin role)** – Enables to enable Certificate-based authentication, add trusted CA and impersonate any user. [Passwordless Persistence and Privilege Escalation in Azure](https://posts.specterops.io/passwordless-persistence-and-privilege-escalation-in-azure-98a01310be3f)
* **UserAuthenticationMethod.ReadWrite.All** - Allows application to add TAP (temporary access password), e-mail or phone (for SMS and mail MFA) for any user.
* **Policy.ReadWrite.PermissionGrant** – Allows the app to manage policies related to consent and permission grants for applications. So the application can allow any user to consent any permission back to this (or any other application) including RoleManagement.ReadWrite.Directory and lead to full tenant compromise. PoC: [Manipulating roles and permissions in Microsoft 365 environment via MS Graph](https://www.tenchisecurity.com/manipulating-roles-and-permissions-in-microsoft-365-environment-via-ms-graph/)
* (disputed) **Directory.ReadWrite.All** - Microsoft says "[Directory.ReadWrite.All grants access that is broadly equivalent to a global tenant admin.](https://learn.microsoft.com/en-us/graph/permissions-reference#directoryreadwriteall)". However Andy Robbins has disputed it's sensitivity "[Directory.ReadWrite.All Is Not As Powerful As You Might Think](https://posts.specterops.io/passwordless-persistence-and-privilege-escalation-in-azure-98a01310be3f)". So it is unsure if this privilege can lead to full tenant compromise. The same permission exists in Azure Graph - maybe it was sensitive there and Microsoft just copied the text about sensitivity.

## Dangerous delegated permissions

Delegated permissions can be misused too, but it depends more on the circumstances (I will try to elaborate more when I have time).

* All the application permissions from previous chapter.
* **Directory.AccessAsUser.All** – Allows application to impersonate all user’s privileges

## Other useful resources

* Azure Attack Paths - <https://cloudbrothers.info/en/azure-attack-paths/>
* Abuse Azure API Permissions - <https://github.com/Hagrid29/AbuseAzureAPIPermissions?tab=readme-ov-file>
* BloodHound Edges - <https://support.bloodhoundenterprise.io/hc/en-us/sections/16600927744411-Edges>
