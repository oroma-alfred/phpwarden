# phpwarden for WHMCS

A WHMCS provisioning (server) module that gives each hosting service its own
phpwarden project. WHMCS creates, suspends, unsuspends and removes the project
along with the service, and the customer sees a security summary of their site
in the client area.

**Requirements**

- A phpwarden **Team plan** partner key. Create one in the phpwarden dashboard
  under **Settings → Partner API**. It starts with `pwp_`.
- WHMCS 7.10 or later, PHP 7.4 or later with the cURL extension.
- Outbound HTTPS from the WHMCS server to `app.phpwarden.io`.

## Install

1. **Copy the module.** Copy `modules/servers/phpwarden/` from this directory
   into your WHMCS installation so that you end up with
   `<whmcs>/modules/servers/phpwarden/phpwarden.php`.

2. **Create the server.** In *System Settings → Servers → Add New Server*:
   - Module: **phpwarden**
   - Hostname: `app.phpwarden.io`
   - Password: your partner key
   - Leave Username empty, then click **Test Connection**.

   The key is read from the **Access Hash** field if that is filled in,
   otherwise from **Password**. Use Password: WHMCS encrypts it at rest, while
   Access Hash is stored as plain text. Fill in only one of the two.

3. **Create the product.** In *System Settings → Products/Services*, create a
   product (type "Other" works), and on the **Module Settings** tab choose
   module **phpwarden** and the server (or server group) from step 2.
   "API base URL" can stay at `https://app.phpwarden.io`.
   Pick when to provision, for example "as soon as the first payment is
   received".

4. **Add two custom fields** on the product's **Custom Fields** tab. The names
   must match exactly:

   | Field name | Type | Settings |
   |---|---|---|
   | `phpwarden Project ID` | Text Box | tick **Admin Only** |
   | `phpwarden Token` | Text Box | leave Admin Only unticked, so the customer can see it; do not tick "Show on Order Form" |

   The module fills both in. Without them it still creates the project, but it
   has nowhere to keep the token, so the customer cannot connect their site.

To sell phpwarden as an add-on to hosting plans rather than a product of its
own, attach the same module to a product add-on or bundle it as you would any
other provisioned product.

## What each action does

| WHMCS action | What happens in phpwarden |
|---|---|
| Create | Creates a project named after the service's domain (or `service-<id>` when there is none) with external id `whmcs-<service id>`. Saves the project id and the site token into the custom fields. Running Create again is safe: it finds the same project instead of making a second one, and only issues a new token if the Token field is empty. |
| Suspend | Suspends the project. The site's reports are rejected until it is unsuspended; existing data is kept. |
| Unsuspend | Lifts the suspension. |
| Terminate | Deletes the project and its data, and clears the two custom fields. Succeeds if the project is already gone. |
| Rotate token (admin button) | Issues a new site token and saves it in the Token field. The old token stops working at once, so the customer has to update their site. |

The admin service page also shows the project id, whether it is suspended, the
time of the last report, and the number of findings and known-exploited (KEV)
findings.

If the Project ID field is empty, the module finds the project by its external
id (`whmcs-<service id>`), so actions keep working for services whose field was
cleared by hand.

## Client area

On the product details page the customer sees:

- the phpwarden summary for their site (status, top findings, time of the last
  report) in a sandboxed frame. The link behind it is signed, tied to that one
  project and valid for one hour; a new one is made on each page view.
- how to connect the site, with their token:
  - install the phpwarden WordPress plugin (https://phpwarden.io/docs#wp-plugin) and paste the token, or
  - run `phpwarden wordpress /path --report-to https://app.phpwarden.io/v1/reports --report-token <token>`.

If the summary cannot be loaded, the customer sees a short "not available right
now" message and the rest of the page still works.

## Troubleshooting

Every API call is recorded in *System Logs → Module Log* (switch logging on
there first). The partner key, site tokens and widget links are masked.

| Message | Cause and fix |
|---|---|
| "No partner key set on the phpwarden server" | Password and Access Hash are both empty on the server record, or the product has no server assigned. |
| "phpwarden rejected the partner key" | The key is wrong or was revoked. Create a new one under Settings → Partner API and update the server record. |
| "phpwarden plan limit reached" | Your plan's project allowance is used up. Upgrade, or terminate unused services. |
| "phpwarden project not found" | The stored project id no longer exists in your account (deleted in the dashboard, or the key belongs to another account). Clear the Project ID field and run Create. |
| "No phpwarden project exists for this service; run Create first" | The service was never provisioned. Use the Create module command. |
| "Could not save the phpwarden custom fields in WHMCS" | WHMCS refused the update; check the two custom fields exist on this product. |
| "Custom field "phpwarden Token" is missing…" | Add the custom field (step 4), then use Rotate token. |
| "API base URL must be an https:// address" | The module refuses to send the key over plain HTTP. |
| "Could not reach phpwarden: …" | Network, DNS or TLS problem between WHMCS and phpwarden. Requests time out after 15 seconds. |
| Customer has no token | The Token field did not exist when the service was created. Add it and run Create again (or Rotate token). |
| Summary frame is empty | Nothing has been reported yet; it fills in after the site's first report. |

## Tests

```
php integrations/whmcs/tests/test_module.php
```

No WHMCS installation or network access is needed; the tests replace the HTTP
layer and the WHMCS functions with fakes.
