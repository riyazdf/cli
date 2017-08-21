---
title: "trust inspect"
description: "The inspect command description and usage"
keywords: "inspect, notary, trust"
---

<!-- This file is maintained within the docker/cli Github
     repository at https://github.com/docker/cli/. Make all
     pull requests against that repo. If you see this file in
     another repository, consider it read-only there, as it will
     periodically be overwritten by the definitive file. Pull
     requests which include edits to this file in other repositories
     will be rejected.
-->

# trust inspect

```markdown
Usage:  docker trust inspect [OPTIONS] IMAGE[:TAG]

Display detailed information about keys and signatures

```

## Description

Docker trust inspect provides detailed information on signed repositories.
This includes all image tags that are signed, who signed them, and who can sign
new tags.

By default, `docker trust inspect` will render results in a table.


## Examples

### Get details about signatures for a single image tag


```bash
$ docker trust inspect alpine:latest
```

### Get details about signatures for all image tags in a repository

```bash
$ docker trust inspect alpine
```

