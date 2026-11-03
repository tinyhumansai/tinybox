# TinyBox contract 2.3

Contract 2.3 adds two things to `ai.tinyhumans.tinybox.Box`, without changing
any 2.2 request or reply shape:

| Addition | What a host may rely on |
| --- | --- |
| `RunNativeShell` | The module runs a native shell through completion, or until the requested yield point, and cleans up when the caller abandons it. |
| `openshell` backend | `Create { backend: "openshell", .. }` places the box in an NVIDIA OpenShell sandbox behind the configured gateway. `Capabilities` lists `openshell` in the create and exec backends. |

A host that needs either one requires `contract_version >= (2, 3)`. Modules
that report 2.1 or 2.2 answer an `openshell` create with `UnsupportedBackend`.
