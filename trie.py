"""
Simple implementation of a trie-like data structure to store target
ETH addresses.
"""


import sys


import sortedcollections


class EthereumAddressTrie(object):
    """Convert a list of target addresses into a trie.

    Encoding the the target addresses as the prefixes in the trie allows
    use to quickly find how close the guess is to any of the target addresses.

    Each node in the trie corresponds to a prefix in one of the possible
    target addresses.  If there is no path from a node, then there is
    no matching target address.

    For example; given the targets [ abcde, abbcd, abcdf, acdef ], the
    resulting trie would look like:

    a -> b -> b -> c -> d
          \-> c -> d -> e
                    \-> f
         c -> d -> e -> f
    """
    def __init__(self, list_of_addresses=None):
        self._size = 0
        self._value = {}
        self.Extend(list_of_addresses or [])

    def __len__(self):
        return self._size

    def sizeof(self):
        return sys.getsizeof(self._value)

    def Extend(self, list_of_addresses):
        for target in [t.lower() for t in list_of_addresses]:
            self._size += 1
            ptr = self._value
            for digit in target:
                if digit not in ptr:
                    ptr[digit] = {}
                ptr = ptr[digit]
        return self._value

    def FindClosestMatch(self, hex_address):
        """Traverse the trie, matching as far as we can.

        Args: a potential ETH address

        Returns: a tuple of (count, address), where `count` is the
            number of of leading hex digits that match a target address
            and `address` is the corresponding best match.
        """
        rest = []
        trie = self._value
        for count, char in enumerate(address):
            if char not in trie:
                break
            trie = trie[char]
            
        # return the lowest numbered match
        nearest_match = None
        
        return count, address, nearest_match


class EthereumAddressNearestDict(object):
    """Similar to EthereumAddressTrie, but use a NearestDict instead."""
    def __init__(self, list_of_addresses=None):
        self._size = 0
        self._value = sortedcollections.NearestDict(
                {int(addr, 16): True for addr in list_of_addresses})

    def __len__(self):
        return len(self._value)

    def sizeof(self):
        return sys.getsizeof(self._value)

    def Extend(self, list_of_addresses):
        for addr in [t.lower() for t in list_of_addresses]:
            self._value[int(addr, 16)] = True

    def FindClosestMatch(self, hex_address):
        bin_addr = int(hex_address, 16)
        nearest_match = '%040x' % self._value.nearest_key(bin_addr)
        
        strength = 0
        for lhs, rhs in zip(hex_address, nearest_match):
            strength += 1 if lhs == rhs else 0
            
        return strength, hex_address, nearest_match
        
