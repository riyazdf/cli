---
title: "trust sign"
description: "The sign command description and usage"
keywords: "sign, notary, trust"
---

<!-- This file is maintained within the docker/cli Github
     repository at https://github.com/docker/cli/. Make all
     pull requests against that repo. If you see this file in
     another repository, consider it read-only there, as it will
     periodically be overwritten by the definitive file. Pull
     requests which include edits to this file in other repositories
     will be rejected.
-->

# trust sign

```markdown
Usage:  docker trust sign [OPTIONS] IMAGE:TAG

Sign an image

```

## Description

Docker trust sign adds signatures to tags to create signed repositories.

## Examples

### Sign a tag

For an image like so:

```bash
$ docker trust inspect example/trust-demo
SIGNED TAG          DIGEST                                                             SIGNERS
v1                  c24134c079c35e698060beabe110bb83ab285d0d978de7d92fed2c8c83570a41   (Repo Admin)

Administrative keys for example/trust-demo:
Repository Key:	36d4c3601102fa7c5712a343c03b94469e5835fb27c191b529c06fd19c14a942
Root Key:	246d360f7c53a9021ee7d4259e3c5692f3f1f7ad4737b1ea8c7b8da741ad980b
```

We can sign a new tag with `docker trust sign`:

```bash
$ docker trust sign example/trust-demo:v2
Signing and pushing trust metadata for example/trust-demo:v2
The push refers to a repository [docker.io/example/trust-demo]
eed4e566104a: Layer already exists
77edfb6d1e3c: Layer already exists
c69f806905c2: Layer already exists
582f327616f1: Layer already exists
a3fbb648f0bd: Layer already exists
5eac2de68a97: Layer already exists
8d4d1ab5ff74: Layer already exists
v2: digest: sha256:8f6f460abf0436922df7eb06d28b3cdf733d2cac1a185456c26debbff0839c56 size: 1787
Signing and pushing trust metadata
Enter passphrase for repository key with ID 36d4c36:
Successfully signed "docker.io/example/trust-demo":v2
```
`docker trust inspect` should now list the new signature:

```bash
$ docker trust inspect example/trust-demo
SIGNED TAG          DIGEST                                                             SIGNERS
v1                  c24134c079c35e698060beabe110bb83ab285d0d978de7d92fed2c8c83570a41   (Repo Admin)
v2                  8f6f460abf0436922df7eb06d28b3cdf733d2cac1a185456c26debbff0839c56   (Repo Admin)

Administrative keys for example/trust-demo:
Repository Key:	36d4c3601102fa7c5712a343c03b94469e5835fb27c191b529c06fd19c14a942
Root Key:	246d360f7c53a9021ee7d4259e3c5692f3f1f7ad4737b1ea8c7b8da741ad980b
```

