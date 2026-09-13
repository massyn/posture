# Microsoft Defender for Cloud — credential setup

[← back to collector docs](../collectors/defender_for_cloud.md)

This collector authenticates against Azure Resource Manager (ARM), not
Microsoft Graph — so access is granted as an Azure RBAC role on the
subscription, not an API permission on the app registration. It is a
separate app registration from the Graph-based collectors ([Entra
ID](azure_entra.md), [Intune](intune.md), [MDE](mde.md)); it can't share
their app registration because it needs a different token scope.

## Create the app registration

* Sign in to the [Entra admin centre](https://entra.microsoft.com) as a
  Global Administrator or Application Administrator.
* Navigate to **Identity** > **Applications** > **App registrations**.
* Select **New registration**, name it `CCM - Read Only (Defender for
  Cloud)`, leave the redirect URI blank, and select **Register**.
* Note the **Application (client) ID** and **Directory (tenant) ID** from
  the Overview page.

## Create a client secret

* In the app registration, navigate to **Certificates and secrets**.
* Select **New client secret**, set a description of `CCM`, and choose an
  expiry period.
* Copy the secret **Value** immediately — it is only shown once.

## Grant the Security Reader role on the subscription

* Navigate to the target **Subscription** > **Access control (IAM)**.
* Select **Add** > **Add role assignment**.
* Choose the **Security Reader** built-in role — read-only access to
  Defender for Cloud's alerts, assessments, and recommendations, with no
  write/remediate access.
* Assign it to the app registration (search for it by name under
  **Members**).

## Record the credentials

| Value | Config key | Environment variable |
| --- | --- | --- |
| Directory (tenant) ID | `tenant_id` | `DEFENDER_FOR_CLOUD_TENANT_ID` |
| Application (client) ID | `client_id` | `DEFENDER_FOR_CLOUD_CLIENT_ID` |
| Client secret | `client_secret` | `DEFENDER_FOR_CLOUD_CLIENT_SECRET` |
| Subscription ID | `subscription_id` | `DEFENDER_FOR_CLOUD_SUBSCRIPTION_ID` |
