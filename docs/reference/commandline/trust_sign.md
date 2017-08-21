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

```bash
$ docker trust sign alpine:latest
```

