#!/usr/bin/env python3
"""Brute force well-known ETH addresses, WarGames-style.

Warning: this is utterly futile.  I've only done this to get a feel
for how secure private keys are against brute-force attacks.
"""

import codecs
import os
import sys
import threading
import time

import click
import ecdsa
import sha3
import sortedcollections
import yaml

import monitoring
import targets
import trie

keccak = sha3.keccak_256()


ETH_ADDRESS_LENGTH = 40
def format_eth_public_address(bin_addr):
    return '%040x' % bin_addr


class SigningKey(ecdsa.SigningKey):

    @staticmethod
    def _hexlify(val):
        return codecs.encode(val, 'hex').decode('utf-8')

    def hexlify_private(self):
        return self._hexlify(self.to_string())

    def hexlify_public(self):
        return self._hexlify(self.get_verifying_key().to_string())


def GetResourcePath(*path_fragments):
    """Return a path to a local resource (relative to this script)"""
    try:
        base_dir = os.path.dirname(__file__)
    except NameError:
        # __file__ is not defined in some case, use the current path
        base_dir = os.getcwd()

    return os.path.join(base_dir, 'data', *path_fragments)


def EchoLine(duration, attempts, private_key, strength, address, newline=False):
    """Write a guess to the console."""
    click.secho('\r%012.6f %08x %s % 3d ' % (duration,
                                             attempts,
                                             private_key,
                                             strength),
                nl=False)
    click.secho(address[:strength], nl=False, bold=True)
    click.secho(address[strength:], nl=newline)


def EchoHeader():
    """Write the names of the columns in our output to the console."""
    click.secho('%-12s %-8s %-64s %-3s %-3s' % ('duration',
                                                'attempts',
                                                'private-key',
                                                'str',
                                                'address'))

@click.option('--fps',
              default=60,
              help='Use this many frames per second when showing guesses.  '
                   'Use non-positive number to go as fast as possible.')
@click.option('--timeout',
              default=-1,
              help='If set to a positive integer, stop trying after this many '
                   'seconds.')
@click.option('--addresses',
              type=click.File('r'),
              default=GetResourcePath('addresses.yaml'),
              help='Filename for yaml file containing target addresses.')
@click.option('--port',
              default=8120,
              help='Monitoring port for runtime metrics.')
@click.option('--no-port',
              is_flag=True,
              default=False,
              help='Disable monitoring port.')
@click.option('--quiet',
              default=False,
              is_flag=True,
              help='Skip the animation')
@click.argument('eth_address', nargs=-1)
@click.command()
def main(fps, timeout, addresses, port, no_port, quiet, eth_address):
    if eth_address:
        click.echo('Attacking specific ETH addresses: ', nl=False)
        addresses = [address.lower() for address in eth_address]
    else:
        click.echo('Loading known public ETH addresses: ', nl=False)
    #target_addresses = trie.EthereumAddressTrie(targets.targets(addresses))
    target_addresses = sortedcollections.NearestDict({int(addr, 16): True for addr in targets.targets(addresses)})
    click.echo('%d found.\n' % (len(target_addresses)))

    httpd = monitoring.Server()
    varz = httpd.Start('', 0 if no_port else port)

    varz.fps = fps
    varz.timeout = timeout if timeout > 0 else 'forever'

    # score is tuple of number of matching leading hex digits and that
    # portion of the resulting public key: (count, address[:count])
    varz.best_score = (0, '')
    varz.difficulty = httpd.DefineComputedStat(
        lambda m:
            '%d of %d digits (%3.2f%%)' % (
                 m.best_score[0],
                 ETH_ADDRESS_LENGTH,
                 100.0 * m.best_score[0] / ETH_ADDRESS_LENGTH)
    )

    # count the number of private keys generated
    varz.num_tries = 0
    varz.guess_rate = httpd.DefineComputedStat(
        lambda m:
             float(m.num_tries) / m.elapsed_time, units='guesses/sec'
    )

    # calculate the fps
    fps = 1.0 / float(fps) if fps > 0 else fps
    last_frame = 0

    varz.start_time = time.asctime(time.localtime())
    start_time = time.perf_counter()

    if not quiet:
        EchoHeader()
    try:
        while varz.best_score[0] < ETH_ADDRESS_LENGTH:
            now = time.perf_counter()
            varz.elapsed_time = now - start_time
            if (timeout > 0) and (start_time + timeout < now):
                break

            varz.num_tries += 1

            priv = SigningKey.generate(curve=ecdsa.SECP256k1)
            pub = priv.get_verifying_key().to_string()

            keccak.update(pub)
            address = keccak.hexdigest()[24:]

            bin_addr = int(address, 16)
            nearest_match = target_addresses.nearest_key(bin_addr)
            closest = format_eth_public_address(nearest_match)

            strength = trie.calc_strength(address, closest)
            current = strength, address, closest

            if last_frame + fps < now:
                if not quiet:
                    EchoLine(now - start_time,
                             varz.num_tries,
                             priv.hexlify_private(),
                             strength,
                             address)
                last_frame = now

            # the current guess was as close or closer to a valid ETH address
            # show it and update our best guess counter
            if current >= varz.best_score:
                if not quiet:
                    EchoLine(now - start_time,
                             varz.num_tries,
                             priv.hexlify_private(),
                             strength,
                             address,
                             newline=True)
                varz.best_score = current
                varz.best_guess = {
                        'private-key': priv.hexlify_private(),
                        'public-key': priv.hexlify_public(),
                        'address': address,
                        'url': 'https://etherscan.io/address/0x%s' % (address,),
                        'closest-address': closest,
                        'closest-url': 'https://etherscan.io/address/0x%s' % (closest,),
                    }

    except KeyboardInterrupt:
        pass

    varz.elapsed_time = time.perf_counter() - start_time
    click.echo('')
    click.echo('Summary')
    click.echo('-------')
    click.echo('%-20s: %s' % ('Total guesses', varz.num_tries))
    click.echo('%-20s: %s' % ('Seconds', varz.elapsed_time))
    click.echo('%-20s: %s' % ('Guess / sec', float(varz.num_tries) / varz.elapsed_time))
    click.echo('%-20s: %s' % ('Num targets', len(target_addresses)))
    click.echo('')
    click.echo('Best Guess')
    click.echo('----------')
    for key, val in sorted(varz.best_guess.items()):
        click.echo('%-20s: %s' % (key, val))
    click.echo('%-20s: %s' % ('Strength', varz.difficulty))

    httpd.Stop()


if '__main__' == __name__:
    main()
