---
title: "trust revoke"
description: "The revoke command description and usage"
keywords: "revoke, notary, trust"
---

<!-- This file is maintained within the docker/cli Github
     repository at https://github.com/docker/cli/. Make all
     pull requests against that repo. If you see this file in
     another repository, consider it read-only there, as it will
     periodically be overwritten by the definitive file. Pull
     requests which include edits to this file in other repositories
     will be rejected.
-->

# trust revoke

```markdown
Usage:  docker trust revoke [OPTIONS] IMAGE[:TAG]

Remove trust for an image

```

## Description

Docker trust revoke removes signatures from tags in a notary repositories.

## Examples

### Revoke the signature on a tag

```bash
$ docker trust revoke alpine:latest
```

### Revoke the signatures on all tags in a repository

```bash
$ docker trust inspect alpine
```

