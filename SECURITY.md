# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 5.1.x   | :white_check_mark: |
| 5.0.x   | :x:                |
| 4.0.x   | :white_check_mark: |
| < 4.0   | :x:                |

## Reporting a Vulnerability

Use this section to tell people how to report a vulnerability.

Tell them where to go, how often they can expect to get an update on a
reported vulnerability, what to expect if the vulnerability is accepted or
declined, etc.
# Security Guidelines

This document defines security practices for the automate-everything repository.

## 1. Logging

- Logs must be written to a secured, admin-only path:
  - Default: %ProgramData%\AutomateEverything\Logs
  - Directory and files must be ACL’d for BUILTIN\Administrators and NT AUTHORITY\SYSTEM only.
- Never log secrets:
  - Passwords (including DSRM/SafeMode), API keys, access tokens, connection strings.
  - Mask or omit sensitive values before passing to Write-Log.
- Prefer INFO/WARN/ERROR for operational events and limit DEBUG usage in production.

## 2. Privileges

- All scripts that alter system state require Administrator.
- Use [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')] on high-impact functions (e.g., AD modifications, ACL changes, storage operations).
- Honor -WhatIf and -Confirm consistently.

## 3. Active Directory Safety

- Membership checks:
  - Avoid enumerating large group memberships (Get-ADGroupMember) for existence tests.
  - Prefer querying the child’s memberOf attribute:
    - Example: (Get-ADGroup -Identity $child -Properties memberOf).memberOf -contains $parent.DistinguishedName
- Use explicit domain controller or -Server when operating in multi-domain environments.
- Validate DN inputs (Path, Group names) and handle NotFound errors gracefully without partial state.

## 4. Storage for AD DS (NTDS/SYSVOL)

- Use Mirror resiliency for volumes that host NTDS/SYSVOL (reliability over performance).
- Enable auditing (SACL) on sensitive directories and avoid replacing ACLs blindly unless you fully manage them.

## 5. BPA and Post-Install

- Do not auto-exclude BPA Error/Warning results.
- Log and surface them for operator action; if you must exclude, document rationale and scope to specific rules.

## 6. Secrets Handling

- Collect secrets using Read-Host -AsSecureString and convert only in-memory for immediate use.
- Never write secrets to disk, logs, or transcripts.
- Encourage retrieval from a secure secret store (DPAPI-protected file, Windows Credential Manager, or enterprise vault).

## 7. Safe Defaults and Validation

- Validate all paths and inputs.
- Default to safest options (e.g., Mirror for AD DS volumes, Fixed provisioning).
- Fail closed: on check failure, stop and log, do not continue.

## 8. Operational Hardening

- Sign scripts in production environments.
- Restrict script execution policy to AllSigned or RemoteSigned.
- Review scheduled tasks/services for least privilege and restricted scope.

## 9. Incident Response

- Keep logs centralized and protected.
- Document rollback procedures for AD and storage changes.
