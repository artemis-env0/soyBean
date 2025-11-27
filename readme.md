<h3 align="center">
  <img width="128" height="128" alt="image" src="https://github.com/user-attachments/assets/e2ca24e2-8289-4001-879f-81c40a8a4df9" />
</h3>

EnvZero SoyBean Migrator
----
### env0 Terraform → OpenTofu Bulk Migrator
#### Version :

````git
Version = v1.0.0.1
````
----
### ⚠️⚠️⚠️ **IRREVERSIBLE ACTION AHEAD** ⚠️⚠️⚠️  
> **ONCE YOU RUN THIS SCRIPT IN APPLY MODE, YOUR TEMPLATES WILL BE SWITCHED TO OPENTOFU.  
> THERE IS NO GOING BACK FROM THIS OPERATION.**
----

## Disclaimer of Warranty and Limitation of Liability

> **IMPORTANT – READ BEFORE USE**

By downloading, copying, modifying, or using this repository (the “Software”), you acknowledge and agree to the following terms. If you do not agree, do not use the Software.

1. **No Warranty**

   The Software is provided **“AS IS” and “AS AVAILABLE”**, with **no representations or warranties of any kind**, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, title, and non-infringement.  
   You are solely responsible for determining whether the Software is suitable for your intended use.

2. **Test in a Non-Production / Temporary Environment First**

   You agree **not** to use this Software directly in production without prior testing.  
   Specifically, you agree to:
   - First test the Software in a **temporary or non-production env0 organization** with a **single, non-critical project**, and  
   - Validate that the behavior and resulting changes are acceptable before applying it to any production or business-critical environment.

3. **Backup Requirement**

   Before using the Software in any environment (including non-production), you agree to:
   - **Backup all relevant files, configurations, and env0 settings**, including but not limited to templates, environments, variables, and policies.
   - Ensure you have a **verified restore process** in case of misconfiguration, data loss, or unintended changes.

4. **No Liability (env0 / envzero)**

   To the maximum extent permitted by applicable law, **env0 / envzero, its owners, contributors, employees, and affiliates (collectively, “envzero”) shall not be liable** for any direct, indirect, incidental, special, consequential, exemplary, or punitive damages, or any loss of data, revenue, profits, use, or other economic advantage, arising out of or in connection with:
   - The use or inability to use the Software,  
   - Any changes made to your env0 organization, projects, templates, or environments, or  
   - Any migration, configuration, or operational decisions you make based on the Software or its documentation,  
   even if envzero has been advised of the possibility of such damages.

5. **User Responsibility**

   You understand and agree that **you** are solely responsible for:
   - All configuration changes triggered by or related to the Software;  
   - Verifying the accuracy, completeness, and suitability of the Software for your environment;  
   - Reviewing all plans, diffs, and logs prior to applying changes, especially in production.

6. **Indemnification**

   You agree to **defend, indemnify, and hold harmless envzero** from and against any and all claims, damages, losses, liabilities, costs, and expenses (including reasonable attorneys’ fees) arising out of or related to:
   - Your use or misuse of the Software,  
   - Your failure to follow best practices, including testing in a non-production environment and backing up configurations, or  
   - Your violation of any applicable law, rule, or regulation in connection with your use of the Software.

7. **Acceptance**

   By cloning this repository, running the scripts, or otherwise using the Software, you acknowledge that:
   - You have read and understood this disclaimer;  
   - You accept it as **legally binding** to the fullest extent permitted by applicable law; and  
   - You agree that these terms apply to all uses of the Software, whether in test, staging, or production environments.

If any provision of this disclaimer is held to be unenforceable, the remaining provisions shall remain in full force and effect.


----
This repository contains a small Python utility to **mass-update env0 Templates (blueprints)** so that their IaC tool is switched from **Terraform** to **OpenTofu**.

It is designed for users who:

- Already run their infrastructure through **env0** using **Terraform**
- Want to migrate to **OpenTofu** without rewriting their HCL
- Prefer to flip many Templates at once via the env0 API instead of clicking through the UI

What it won't do:
- Will NOT migrate you from OpenTofu > Terraform
- Will NOT work with OpenTofu, Terragrunt, or Pulumi
---
### Download and Run:

- [<img width="14" height="14" alt="image" src="https://github.com/user-attachments/assets/e2ca24e2-8289-4001-879f-81c40a8a4df9"/> **Download soyBean v1.0.0.1 Default Package**](https://github.com/artemis-env0/env.ZT/releases/download/v1.0.0.1/env0_soyBean_migrate_run_v1001.zip)
- [<img width="14" height="14" alt="image" src="https://github.com/user-attachments/assets/e2ca24e2-8289-4001-879f-81c40a8a4df9"/> **Download soyBean v1.0.0.0 Portable**](https://github.com/artemis-env0/env.ZT/releases/download/v1.0.0.1/env0_soyBean_migrate_full_v1000.py)

---

### How It Works

There are **two Python modules**:

#### `env0_connect.py`

Reusable helper that:

- Reads env0 configuration from environment variables
- Builds the `Authorization: Basic <token>` header for the env0 API
- Returns:
  - `base_url` (env0 API URL)
  - `org_id` (env0 organization id)
  - `headers` (with auth & JSON headers)

Example usage:
````python
    from env0_connect import get_env0_config

    BASE_URL, ORG_ID, HEADERS = get_env0_config()
````
---

#### `env0_soyBean_migrate.py`

Main script that:

1. Calls `get_env0_config()` to get API URL, org id, and auth headers  
2. Fetches **all templates (blueprints)** for the org via `GET /blueprints`  
3. Filters to those where the IaC tool field currently equals `"terraform"`  
4. In **DRY-RUN** mode, prints what *would* change (no API updates)  
5. In **APPLY** mode, sends `PUT /blueprints/{id}` to set that field to `"opentofu"`

The script does **not** change your HCL or state — it only updates the configuration field that tells env0 which binary to run (`terraform` vs `tofu`).

---

## Repository Layout

    .
    ├── bin                                  # shared env0 auth helper
         ├── env0_soyBean_migrate_full.py    # main bulk migration script w/ env0_connect
         └── readme.md                       # Readme Markdown for Folder
    ├── env0_connect.py                      # shared env0 auth helper
    ├── env0_soyBean_migrate.py              # main bulk migration script
    └── README.md                            # this file

---

### File Contents

#### 'env0_connect.py'
````python

    #!/usr/bin/env python3
    import os
    import base64


    def get_env0_config():
        """
        Read env0-related environment variables and return:
        - base_url
        - org_id
        - headers (with Basic auth)
        """
        base_url = os.environ.get("ENV0_API_URL", "https://api.env0.com")
        org_id = os.environ["ENV0_ORGANIZATION_ID"]
        api_key = os.environ["ENV0_API_KEY"]
        api_secret = os.environ["ENV0_API_SECRET"]

        token = base64.b64encode(f"{api_key}:{api_secret}".encode("utf-8")).decode("ascii")
        headers = {
            "Authorization": f"Basic {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        return base_url, org_id, headers
````
---
#### 'env0_soyBean_migrate.py'
````python
#!/usr/bin/env python3

import requests
import os
import sys
import urllib3
import base64 as b64
from env0_connect import get_env0_config

# ---------- env0 config (from shared auth lib) ----------
BASE_URL, ORG_ID, HEADERS = get_env0_config()

# ------------------------ config ------------------------
DRY_RUN = True  # set to False to actually update
TERRAFORM_TOOL_FIELD = "terraformTools"  # replace with real field name from GET /blueprints/{id} [Endpoint]
TARGET_TOOL = "opentofu"                 # desired value; valid values: 'opentofu', 'terraform'


def env0_get_all_templates():
    """
    Fetch all templates (blueprints) for the organization.
    The exact pagination keys may vary; if your org is small this might just return a flat list.
    """
    templates = []
    page = 0

    while True:
        resp = requests.get(
            f"{BASE_URL}/blueprints",
            headers=HEADERS,
            params={
                "organizationId": ORG_ID,
                "page": page,
                "limit": 100,
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()

        # Some env0 endpoints wrap results; others just return a list.
        if isinstance(data, list):
            docs = data
        else:
            docs = data.get("documents", data)

        if not isinstance(docs, list) or not docs:
            break

        templates.extend(docs)
        if len(docs) < 100:
            break
        page += 1

    return templates


def env0_update_template_tool(template, new_tool):
    """
    Update a single template's Terraform/OpenTofu tool.

    NOTE: If the API requires a full object instead of a partial update,
    you may need to send back all fields from `template`, just with the tool field changed.
    """
    tpl_id = template["id"]
    name = template.get("name")
    current = template.get(TERRAFORM_TOOL_FIELD)

    print(f"Updating template '{name}' ({tpl_id}): {current} -> {new_tool}")

    body = {
        # minimal payload: only change the tool field
        TERRAFORM_TOOL_FIELD: new_tool
    }

    resp = requests.put(
        f"{BASE_URL}/blueprints/{tpl_id}",
        headers=HEADERS,
        json=body,
        timeout=30,
    )
    resp.raise_for_status()


def env0_ignite():
    templates = env0_get_all_templates()
    print(f"Found {len(templates)} templates in org {ORG_ID}")

    to_change = [
        t for t in templates
        if t.get(TERRAFORM_TOOL_FIELD) == "terraform"
    ]

    print(f"{len(to_change)} templates currently using Terraform (will switch to {TARGET_TOOL})")

    for t in to_change:
        name = t.get("name")
        tpl_id = t.get("id")
        current = t.get(TERRAFORM_TOOL_FIELD)

        prefix = "[DRY-RUN]" if DRY_RUN else "[APPLY]"
        print(f"{prefix} {name} ({tpl_id}): {current} -> {TARGET_TOOL}")

        if not DRY_RUN:
            env0_update_template_tool(t, TARGET_TOOL)


if __name__ == "__main__":
    env0_ignite()

````
---

### Prerequisites

- **Python** 3.8+ (or any reasonably recent Python 3)
- Network access to your env0 API endpoint (default: `https://api.env0.com`)
- An env0 **Organization ID**
- An env0 **API key & secret** with permission to:
  - Read blueprints (`GET /blueprints`)
  - Update blueprints (`PUT /blueprints/{id}`)

#### Python dependencies

Install the `requests` library:
````pip
    pip install requests
````
(You can also add `requests` to a `requirements.txt` if desired.)

---

### Configuration (Environment Variables)

The scripts rely on the following environment variables:

- `ENV0_API_URL` (optional, default: `https://api.env0.com`)
- `ENV0_ORGANIZATION_ID` (required)
- `ENV0_API_KEY` (required)
- `ENV0_API_SECRET` (required)

Example (macOS / Linux / WSL):
````bash
    export ENV0_API_URL="https://api.env0.com"
    export ENV0_ORGANIZATION_ID="org-xxxxxxxx"
    export ENV0_API_KEY="your-api-key"
    export ENV0_API_SECRET="your-api-secret"
````
----
Example (Windows PowerShell):
````powershell
    $env:ENV0_API_URL = "https://api.env0.com"
    $env:ENV0_ORGANIZATION_ID = "org-xxxxxxxx"
    $env:ENV0_API_KEY = "your-api-key"
    $env:ENV0_API_SECRET = "your-api-secret"
````
---

### IMPORTANT: Set the Tool Field Name

Inside `env0_soyBean_migrate.py` you’ll see:
````python
    DRY_RUN = True  # set to False to actually update
    TERRAFORM_TOOL_FIELD = "terraformTools"  # <-- replace with real field name
    TARGET_TOOL = "opentofu"
````
----
`TERRAFORM_TOOL_FIELD` is the **JSON field** in the env0 blueprint object that stores which IaC tool is used for that Template (e.g. `"terraform"` vs `"opentofu"`).

Because the exact field name can differ between environments, you should:

1. Pick a template in env0 that you know is using Terraform.  
2. Get its ID (from the env0 UI or from listing blueprints).  
3. Call the env0 API manually (example):
````bash
       curl -H "Authorization: Basic <BASE64(API_KEY:API_SECRET)>" \
            "https://api.env0.com/blueprints/<TEMPLATE_ID>"
````
4. Inspect the JSON response and look for the field that:
   - Exists on that blueprint object, and  
   - Has the value `"terraform"` for this template  

5. Take that field name (for example, `iacType`, `templateType`, etc.) and set:

       TERRAFORM_TOOL_FIELD = "<that-field-name>"

Once that’s correct, the script knows where to look and what to update.

---

### Where to Execute the Script

You can run this script from any environment that has:

- Python + `requests` installed  
- Network connectivity to the env0 API endpoint  
- The required env0 environment variables set  

Typical options:

- A **local laptop / workstation**  
- A **bastion host** with Internet / env0 access  
- A **CI job** (GitHub Actions, GitLab CI, Jenkins, etc.) as a one-off migration step  

The script does not store any local state; everything is done through the env0 API.

---

### Usage Examples

#### 1. Clone the Repository
````bash
    git clone <your-repo-url> env0-opentofu-migration
    cd env0-opentofu-migration
````
(Optional but recommended) create and activate a virtual environment:
````python
    python -m venv .venv
    source .venv/bin/activate   # Windows: .venv\Scripts\activate
    pip install requests
````
#### 2. Configure Environment Variables

Set `ENV0_API_URL`, `ENV0_ORGANIZATION_ID`, `ENV0_API_KEY`, and `ENV0_API_SECRET` as shown above.

#### 3. Verify `TERRAFORM_TOOL_FIELD`

Edit `env0_soyBean_migrate.py` and set the correct field name:
````python
    TERRAFORM_TOOL_FIELD = "iacType"  # example – replace with your real field name
````
#### 4. Run a DRY RUN (Recommended First)

Confirm `DRY_RUN` is set to `True`:

    DRY_RUN = True

Run the script:
```bash
    python env0_soyBean_migrate.py
````
Example DRY-RUN output:

    Found 27 templates in org org-xxxxxxxx
    15 templates currently using Terraform (will switch to opentofu)
    [DRY-RUN] nonprod-network (tpl-abc123): terraform -> opentofu
    [DRY-RUN] prod-app (tpl-def456): terraform -> opentofu
    [DRY-RUN] sandbox-lab (tpl-ghi789): terraform -> opentofu
    ...

At this stage, **no** changes are made in env0; the script only prints what it **would** update.

#### 5. Apply Changes (Switch to OpenTofu)

Once you’re satisfied with the DRY RUN:

1. Edit `env0_soyBean_migrate.py`  
2. Change:

       DRY_RUN = True

   to:

       DRY_RUN = False

3. Run the script again:

       python env0_soyBean_migrate.py

Example APPLY output:

    Found 27 templates in org org-xxxxxxxx
    15 templates currently using Terraform (will switch to opentofu)
    [APPLY] nonprod-network (tpl-abc123): terraform -> opentofu
    Updating template 'nonprod-network' (tpl-abc123): terraform -> opentofu
    [APPLY] prod-app (tpl-def456): terraform -> opentofu
    Updating template 'prod-app' (tpl-def456): terraform -> opentofu
    ...

Each `[APPLY]` line corresponds to a `PUT /blueprints/{id}` call that updates that template’s IaC tool to `"opentofu"`.

---

### What Exactly Gets Changed?

For every template whose tool field currently equals `"terraform"`, the script:

- Builds a minimal JSON body:

      {
        "<TERRAFORM_TOOL_FIELD>": "opentofu"
      }

- Sends it via:

      PUT /blueprints/{id}

No other fields are touched. Specifically, the script does **not** modify:

- Git repository URLs  
- Variables or variable sets  
- Policies  
- State configuration  
- Triggers / schedules  

The only change is which binary env0 uses to run that template’s plans/applies.

---

### Common Customizations

Some easy tweaks you can make:

- **Switch back to Terraform** (for rollback or testing):

      TARGET_TOOL = "terraform"

- **Limit to a subset of templates**, e.g. only those whose names start with `nonprod-`:

      to_change = [
          t for t in templates
          if t.get(TERRAFORM_TOOL_FIELD) == "terraform"
             and t.get("name", "").startswith("nonprod-")
      ]

- **Add logging or tagging** as needed for internal auditing.

---

### Safety Tips

- Always run with `DRY_RUN = True` first.  
- Start with **non-production** templates and verify:
  - env0 shows them as OpenTofu templates afterward  
  - OpenTofu `plan` results match previous Terraform plans (no unexpected diffs)  
- Consider running this through a pull request / code review if this is executed from a shared or automated environment.  

---

### License

    Copyright (c) 2025 EnvZero (env0)
    Author: artem@env0
    All rights reserved.
