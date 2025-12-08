# Policies for use in the File Attestation plugin

## Testing

```shell
opa test policies
```

## Bundling

Policies are built into bundle to make distribution easier.

You can easily build the policies by running

```shell
make build
```

## Writing policies.

Policies are written in the [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) language.

Take a look on policies written under `policies` to see general format.

You must use valid inputs provided by `file-attestation` plugin.

