
<p align="center">
  <img width="500" height="500" src="https://raw.githubusercontent.com/daddycocoaman/dumpscan/main/docs/dumpscan.png?token=GHSAT0AAAAAABN6UDXH5XLMIBAQYW66323MYVRI3CA">
</p>

**Dumpscan** is a command-line tool designed to extract secrets from kernel and Windows Minidump formats. Kernel-dump parsing is provided by [volatility3](https://github.com/volatilityfoundation/volatility3).

### Features

- x509 Public and Private key (PKCS #8/PKCS #1) parsing
- [Symcrypt](https://github.com/microsoft/SymCrypt) parsing
  - Supported structures
    - **SYMCRYPT_RSAKEY** - Determines if the key structure also has a private key
  - Matching to public certificates found in the same process
  - More Symcrypt structures to come
- Environment variables
- Command line arguments

**Note**: Testing has only been performed on Windows 10 and 11 64-bit hosts and processes. Feel free to file an issue for additional versions. Linux testing TBD.

### Installation

As a command-line tool, installation is recommended using [pipx](https://github.com/pypa/pipx). This allows for easy updates and well and ensuring it is installed in its own virtual environment.

`pipx install dumpscan`

### Usage

```
 Usage: dumpscan [OPTIONS] COMMAND [ARGS]...

 Scan memory dumps for secrets and keys

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                                  │
│  --help         Show this message and exit.                                                      │
│                                                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                                  │
│  kernel     Scan kernel dump using volatility                                                    │
│  minidump   Scan a user-mode minidump                                                            │
│                                                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
```

#### Kernel Mode

As mentioned, kernel analysis is performed by Volatility3. `cmdline`, `envar`, and `pslist` are direct calls to the Volatility3 plugins, while `symcrypt` and `x509` are custom plugins.

```
 Usage: dumpscan kernel [OPTIONS] COMMAND [ARGS]...

 Scan kernel dump using volatility

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                                  │
│  --help         Show this message and exit.                                                      │
│                                                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                                  │
│  cmdline    List command line for processes (Only for Windows)                                   │
│  envar      List process environment variables (Only for Windows)                                │
│  pslist     List all the processes and their command line arguments                              │
│  symcrypt   Scan a kernel-mode dump for symcrypt objects                                         │
│  x509       Scan a kernel-mode dump for x509 certificates                                        │
│                                                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### Minidump Mode

Supports Windows Minidump format.

**Note**: This has only been tested on 64-bit processes on Windows 10+. 32-bit processes requires additional work but isn't a priority.


```
 Usage: dumpscan minidump [OPTIONS] COMMAND [ARGS]...

 Scan a user-mode minidump

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                                  │
│  --help         Show this message and exit.                                                      │
│                                                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                                  │
│  cmdline    Dump the command line string                                                         │
│  envar      Dump the environment variables in a minidump                                         │
│  symcrypt   Scan a minidump for symcrypt objects                                                 │
│  x509       Scan a minidump for x509 objects                                                     │
│                                                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
```