# Ethereum Private Key Brute Force Attacker

A simple, pure-python package to generate private keys and compare the
resulting ETH addresses with a list of known values.
The Strength of each guess is measured by the number of leading hexadecimal digits that match (other digits may match, but we don't count those yet).

While running, the script shows its guesses WarGames-style.
The script also opens up a port for prometheus style metrics scraping.

## Usage

```
Usage: brute_force_app.py [OPTIONS] [ETH_ADDRESS]...

Options:
  --quiet                         Skip the animation
  --strategy [trie|nearest|bisect]
                                  Choose a lookup strategy for eth addresses
  --no-port                       Disable monitoring port.
  --port INTEGER                  Monitoring port for runtime metrics.
  --addresses FILENAME            Filename for yaml file containing target
                                  addresses.
  --max-guesses INTEGER           If set to a positive integer, stop trying
                                  after this many attempts.
  --timeout INTEGER               If set to a positive integer, stop trying
                                  after this many seconds.
  --fps INTEGER                   Use this many frames per second when showing
                                  guesses.  Use non-positive number to go as
                                  fast as possible.
  --help                          Show this message and exit.
```

Thanks to [@vkobel/ethereum-generate-wallet](https://github.com/vkobel/ethereum-generate-wallet) for the pure-python implementation of ETH key generation.

## Why?

I wanted a more tangible understanding of how hard it is to guess a
private key before using it to store any non-trivial value.
I mean, _how hard could it be to guess someone else's key, **right**_?
As this script tries to show, it's basically impossible to collide with an already existing key.

How many leading digits can you match?  ;)

Note: having a 39 digit match of the address means you're no closer to
unlocking anything.

### Seriously, no chance

How impossible is this?  Assuming [45,000,000 addresses](https://etherscan.io/chart/address),
you have a 45000000 / 115792089237316195423570985008687907853269984665640564039457584007913129639936
or 3.8862758497925e-70 chance of randomly guessing a private key associated with a public
address.

If you made O(1000) random guesses per second, it would take you on roughly 1 trillion trillion trillion trillion years to guess one address (on average).
Clearly a short-cut is needed, but that's for another project. :wink:

## Python dependencies

This script uses python3.
Its dependencies are listed in `requirements.txt`.
Use `virtualenv` to install and execute this script without affecting your system's python3 distribution:

```shell
$ virtualenv -p python3 venv
$ . ./venv/bin/activate
$ pip install -r requirements.txt
$ ./brute_force_app.py --timeout 5
Loaded 10000 addresses

duration     attempts private-key                                                      str address
00000.000006 00000001 0d5a730468b5ed565a89b03cf8f6228a4b4d8c75c7fbd1d31b4ef9f003d5660c   3 e0a                                     
00000.277911 00000005 100276e5d5f35d065c9a925b08785c55a8c1497f1dbad970b16d9adbf7e670a0   3 ff1                                     
00000.972975 0000000f c6b40ef08f92ffb8b3b36fa5f65de72daddd0a05da82943deadfa3a63813779f   4 00fb                                    
00001.666908 00000019 911dea430f2b8403f9cbb2f4dcae2e5ea6943b05916d4a3ec9e3ed68927cbc86   4 d301                                    
00004.998683 00000049 8fa41f3e7fb335e0fa6435d2d905eb996c251f2ff98c5fa7719ad88030c59c2c   2 78                                      

Total guesses: 73
Seconds      : 5.068186
Guess / sec  : 14.403575559381602
Num targets  : 10000

Best Guess
Private key  : 911dea430f2b8403f9cbb2f4dcae2e5ea6943b05916d4a3ec9e3ed68927cbc86
Public key   : af71d473026d92073ed27de65b04d523ffa897d59b965ba5aeaa4e29a535f3e3e7dac768a6c3b2ed88d00415472d30fb39ed0a825d54c8070f896fc23d3e67e8
Address      : 0xd301b4bf0ab57e50c2aa5451df29d58e89538ed0
Strength     : 4 of 40 digits (10.00%)

$ deactivate
```

### Don't pollute your development environment

Not recommended: you can skip the `virtualenv` steps and install the
necessary dependencies to your system's python3 distribution:

```bash
$ pip install -r requirements.txt
$ python3 ./brute_force_app.py
...
```

### Run it in a container

You can also run this toy in a docker container.

1. First, pull the docker container:
```bash
$ docker pull evilegg/ethereum-private-key-attack
```

2. If you want to run it as is:
```bash
$ docker run evilegg/ethereum-private-key-attack
```

3. Or you can copy a yaml file containing the ETH addresses you wish to target:
```bash
$ docker run -it -v "$(PWD):/usr/src/app" evilegg/ethereum-private-key-attack python3 brute_force_app.py --addresses YOUR_YAML_FILE
```

4. Or you can pass the YAML data via stdin:
```bash
$ cat YOUR_YAML_FILE | docker run -i evilegg/ethereum-private-key-attack ./brute_force_app.py --addresses /dev/stdin
```

5. You can also forward the monitoring port to `localhost:80` for remote monitoring:
```bash
$ cat YOUR_YAML_FILE | docker run -i -p 80:8120 evilegg/ethereum-private-key-attack ./brute_force_app.py --addresses /dev/stdin
```

6. You can also skip the animations, but what fun is that?
```bash
$ docker run evilegg/ethereum-private-key-attack ./brute_force_app.py --quiet
```

## Strategies

Currently, there are three strategies for looking up private key guesses against the known list of public addresses.

## Monitoring

If you specify a `--port` command line argument, the app listens on that port
for HTTP GETs and will return some basic run-time statistics.

## Validity

You can confirm address generation using [this link](https://www.rfctools.com/ethereum-address-test-tool/).
Copy and paste the `private-key` and compare against `address`:

```
» ./brute_force_app.py
Loading known public ETH addresses375276 found.

web-server on: ('', 8120)
duration     attempts private-key                                                      str address
00000.000187 00000001 d88d5d4dc45ce8e392908758e36f0b6c3def14b065d87565176fa574329eeb6e   4 720a519a2ffcf4109661a3a6de4aec66db1340f3
```

## Troubleshooting

1. libyaml is not found

   ```
   #include <yaml.h>
                    ^
   compilation terminated.

   libyaml is not found or a compiler error: forcing --without-libyaml
   (if libyaml is installed correctly, you may need to
   specify the option --include-dirs or uncomment and
   modify the parameter include_dirs in setup.cfg)
	 ```

   Your python development environment is missing a few components.  Ensure you have `libyaml-dev`, `libpython3-dev`, and `python3-dev` installed.

   ```bash
   sudo apt-get install libyaml-dev libpython3-dev python3-dev
   ```

2. Click wants UTF-8 but your python install was configured for ASCII

    ```bash
    $ python ./brute_force_app.py
    Traceback (most recent call last):
      File "./brute_force_app.py", line 177, in <module>
        main()
      File "/home/cabox/workspace/venv/lib/python3.4/site-packages/click/core.py", line 722, in __call__
        return self.main(*args, **kwargs)
      File "/home/cabox/workspace/venv/lib/python3.4/site-packages/click/core.py", line 676, in main
        _verify_python3_env()
      File "/home/cabox/workspace/venv/lib/python3.4/site-packages/click/_unicodefun.py", line 118, in _verify_python3_env
        'for mitigation steps.' + extra)
    RuntimeError: Click will abort further execution because Python 3 was configured to use ASCII as encoding for the environment.  Consult http://click.pocoo.org/python3/for mitigation steps.

    This system supports the C.UTF-8 locale which is recommended.
    You might be able to resolve your issue by exporting the
    following environment variables:

        export LC_ALL=C.UTF-8
        export LANG=C.UTF-8
    ```

    Export the recommended locale information to make click happy.

    ```bash
    export LC_ALL=C.UTF-8
    export LANG=C.UTF-8
    ```

3. `pytest` is failing.

   From https://stackoverflow.com/a/54597424:

   > 1. activate your venv : source venv/bin/activate
   > 2. install pytest : pip install pytest
   > 3. re-activate your venv: deactivate && source venv/bin/activate
   >
   > The reason is that the path to pytest is set by the sourceing the activate file only after pytest is actually installed in the venv.
   > You can't set the path to something before it is installed.
