# Keel validator

## keel.sh
[Keel](https://keel.sh) is a very simple Kubernetes Operator to automate Helm, DaemonSet, StatefulSet & Deployment updates.
It will track your installations and, when an update is published on their repository, it will update the images.

One interesting feature of keel is that it can wait for an external approval. When an update is ready to be deployed, a new
approval request is created. A human supervisor, or a different software, have to vouch the update in order to be performed.

If you have enabled the web panel, you can check for update approvals using a browser or you can use the rest interface to interact with them. We are going to exploit that for image authentication.

## Image authentication

Keel approval phase is the perfect moment to plug in image authentication. Image is approved only if it is trusted to run.

This simple deployment is polling keel to see if there are pending approvals. If there are, it tries to authenticate
using `vcn` tool from CodeNotary.

If the image authenticates, that means it was notarized and signed as trusted, so the update is approved.

## Installation

Fill in the values for credentials in `keel-validator.yaml` file:
```yaml
---
apiVersion: v1
kind: Secret
metadata:
  name: keel-validator-secrets
type: Opaque 
data: 
  tc-api-key: <TrustCenter_api_key_here>
  tc-signer-id: <trusted_signer_id>
  keel-username: <keel_web_panel_username>
  keel-password: <keel_web_panel_password>
  registry-json-key: |
    if_your_registry_needs_json_authentication
    (like_gcr)_enter_here_your_json_key
```

then `kubectl deploy -n keel -f keel-validator.yaml`.

