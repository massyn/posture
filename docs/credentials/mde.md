# Microsoft Defender for Endpoint — credential setup

[← back to collector docs](../collectors/mde.md)

These steps create an Entra ID app registration with read-only access to
Defender for Endpoint. Auth is shared plumbing
(`posture.collectors._azure_oauth`) with [Intune](intune.md) and
[Entra ID](azure_entra.md) — the same app registration can serve all three
collectors if you'd rather provision one `CCM - Read Only` identity for all
of Azure AD client-credentials auth rather than one per collector; grant it
the union of all three permission tables and reuse the same tenant ID/
client ID/client secret for each.

## Create the app registration

* Sign in to the [Entra admin centre](https://entra.microsoft.com) as a
  Global Administrator or Application Administrator.
* Navigate to **Identity** > **Applications** > **App registrations**.
* Select **New registration**.
* Fill in the following fields:
    * **Name**: `CCM - Read Only`
    * **Supported account types**: Accounts in this organisational directory
      only (single tenant)
    * **Redirect URI**: leave blank
* Select **Register**.
* Note the **Application (client) ID** and **Directory (tenant) ID** from the
  Overview page.

## Create a client secret

* In the app registration, navigate to **Certificates and secrets**.
* Select **New client secret**.
* Set a **Description** of `CCM` and choose an appropriate expiry period.
* Select **Add**.
* Copy the secret **Value** immediately — it is only shown once.

## Add API permissions

Navigate to **API permissions** and add the following **Application**
permissions (not Delegated). Search under "APIs my organisation uses" for
**WindowsDefenderATP**:

| Permission | Purpose |
| --- | --- |
| `Alert.ReadWrite.All` | Defender for Endpoint alerts — Microsoft does not provide a read-only variant of this scope |
| `Machine.Read.All` | `machines`, `device_av_info` |
| `Vulnerability.Read.All` | `vulnerabilities`, `machine_vulnerabilities` |
| `AttackSimulation.Read.All` | Microsoft Attack Simulation (used by [Intune](intune.md)'s `attack_simulations`/`attack_simulation_users`, not this collector directly — add it here too if provisioning one shared app registration) |

After adding permissions, select **Grant admin consent** and confirm.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Directory (tenant) ID | `tenant_id` | `MDE_TENANT_ID` |
| Application (client) ID | `client_id` | `MDE_CLIENT_ID` |
| Client secret | `client_secret` | `MDE_CLIENT_SECRET` |
