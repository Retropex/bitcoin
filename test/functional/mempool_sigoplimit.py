#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test sigop limit mempool policy (`-bytespersigop` parameter)"""
from copy import deepcopy
from decimal import Decimal
from math import ceil

from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    MAX_OP_RETURN_RELAY,
    WITNESS_SCALE_FACTOR,
    tx_from_hex,
)
from test_framework.script import (
    CScript,
    OP_1,
    OP_2DUP,
    OP_CHECKMULTISIG,
    OP_CHECKSIG,
    OP_DROP,
    OP_ENDIF,
    OP_FALSE,
    OP_IF,
    OP_NOT,
    OP_RETURN,
    OP_TRUE,
)
from test_framework.script_util import (
    keys_to_multisig_script,
    script_to_p2wsh_script,
    script_to_p2sh_script,
    MAX_STD_LEGACY_SIGOPS,
    MAX_STD_P2SH_SIGOPS,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import generate_keypair

DEFAULT_BYTES_PER_SIGOP = 20  # default setting
MAX_PUBKEYS_PER_MULTISIG = 20

class BytesPerSigOpTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        # allow large datacarrier output to pad transactions
        self.extra_args = [['-datacarriersize=100000']]

    def create_p2wsh_spending_tx(self, witness_script, output_script):
        """Create a 1-input-1-output P2WSH spending transaction with only the
           witness script in the witness stack and the given output script."""
        # create P2WSH address and fund it via MiniWallet first
        fund = self.wallet.send_to(
            from_node=self.nodes[0],
            scriptPubKey=script_to_p2wsh_script(witness_script),
            amount=1000000,
        )

        # create spending transaction
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(fund["txid"], 16), fund["sent_vout"]))]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(witness_script)]
        tx.vout = [CTxOut(500000, output_script)]
        return tx

    def test_sigops_limit(self, bytes_per_sigop, num_sigops):
        sigop_equivalent_vsize = ceil(num_sigops * bytes_per_sigop / WITNESS_SCALE_FACTOR)
        self.log.info(f"- {num_sigops} sigops (equivalent size of {sigop_equivalent_vsize} vbytes)")

        # create a template tx with the specified sigop cost in the witness script
        # (note that the sigops count even though being in a branch that's not executed)
        num_multisigops = num_sigops // 20
        num_singlesigops = num_sigops % 20
        witness_script = CScript(
            [OP_FALSE, OP_IF] +
            [OP_CHECKMULTISIG]*num_multisigops +
            [OP_CHECKSIG]*num_singlesigops +
            [OP_ENDIF, OP_TRUE]
        )

        # Create transaction ONCE with a small output
        # This creates ONE funding transaction in the mempool
        tx = self.create_p2wsh_spending_tx(witness_script, CScript([OP_RETURN, b'test123']))

        # Helper function to pad transaction to target vsize using multiple OP_RETURN outputs
        def pad_tx_to_vsize(tx, target_vsize):
            """Adjust transaction size by adding/removing multiple OP_RETURN outputs"""
            # Keep only the first output, remove all padding outputs
            while len(tx.vout) > 1:
                tx.vout.pop()

            # MAX_OP_RETURN_RELAY = 83, so max script is: OP_RETURN + 82 bytes data
            max_script_size = MAX_OP_RETURN_RELAY

            # Iteratively add outputs until we reach or slightly exceed the target
            while True:
                current_vsize = tx.get_vsize()
                if current_vsize >= target_vsize:
                    break

                vsize_needed = target_vsize - current_vsize

                # CTxOut serialization: nValue (8) + compact_size(script_len) + script
                # For script_len <= 252: compact_size = 1 byte
                # So total = 8 + 1 + script_len = 9 + script_len

                # Maximum output: 8 + 1 + 83 = 92 vbytes
                if vsize_needed >= 92:
                    # Add a max-size output
                    tx.vout.append(CTxOut(nValue=0, scriptPubKey=CScript([OP_RETURN] + [OP_1] * (max_script_size - 1))))
                elif vsize_needed >= 10:
                    # Need to add exactly vsize_needed bytes
                    # 8 + 1 + script_len = vsize_needed
                    # script_len = vsize_needed - 9
                    script_len = vsize_needed - 9
                    # Script is [OP_RETURN] + data, so len = 1 + data_len
                    # data_len = script_len - 1
                    data_len = script_len - 1
                    if data_len >= 0:
                        tx.vout.append(CTxOut(nValue=0, scriptPubKey=CScript([OP_RETURN] + [OP_1] * data_len)))
                    else:
                        # Just add the minimum and overshoot slightly
                        tx.vout.append(CTxOut(nValue=0, scriptPubKey=CScript([OP_RETURN])))
                        break
                else:
                    # vsize_needed < 10, can't add a new output
                    # Instead, adjust the first output's size by adding to its script
                    if vsize_needed > 0 and len(tx.vout[0].scriptPubKey) < max_script_size:
                        # Extend the first output's script
                        current_script = tx.vout[0].scriptPubKey
                        # Add vsize_needed more bytes to the script
                        new_script = bytes(current_script) + bytes([1] * vsize_needed)
                        # But cap at max_script_size
                        if len(new_script) <= max_script_size:
                            tx.vout[0].scriptPubKey = CScript(new_script)
                    break

            # If we overshot, try to trim the last output
            if tx.get_vsize() > target_vsize and len(tx.vout) > 1:
                tx.vout.pop()
                # Try again with a smaller output
                current_vsize = tx.get_vsize()
                vsize_needed = target_vsize - current_vsize
                if vsize_needed >= 10:
                    script_len = vsize_needed - 9
                    data_len = script_len - 1
                    if data_len >= 0:
                        tx.vout.append(CTxOut(nValue=0, scriptPubKey=CScript([OP_RETURN] + [OP_1] * data_len)))

        # Pad to reach sigop-limit equivalent size
        pad_tx_to_vsize(tx, sigop_equivalent_vsize)
        if tx.get_vsize() != sigop_equivalent_vsize:
            self.log.error(f"Padding failed: got {tx.get_vsize()}, expected {sigop_equivalent_vsize}")
            self.log.error(f"Number of outputs: {len(tx.vout)}")
            for i, out in enumerate(tx.vout):
                self.log.error(f"Output {i}: scriptPubKey len={len(out.scriptPubKey)}, vout entry size={8 + 1 + len(out.scriptPubKey)}")
        assert_equal(tx.get_vsize(), sigop_equivalent_vsize)

        res = self.nodes[0].testmempoolaccept([tx.serialize().hex()])[0]
        assert_equal(res['allowed'], True)
        assert_equal(res['vsize'], sigop_equivalent_vsize)

        # Increase tx's vsize to be right above the sigop-limit equivalent size
        # => tx's vsize in mempool should also grow accordingly
        pad_tx_to_vsize(tx, sigop_equivalent_vsize + 1)
        res = self.nodes[0].testmempoolaccept([tx.serialize().hex()])[0]
        assert_equal(res['allowed'], True)
        assert_equal(res['vsize'], sigop_equivalent_vsize + 1)

        # Decrease tx's vsize to be right below the sigop-limit equivalent size
        # => tx's vsize in mempool should stick at the sigop-limit equivalent
        # bytes level, as it is higher than the tx's serialized vsize
        # (the maximum of both is taken)
        pad_tx_to_vsize(tx, sigop_equivalent_vsize - 1)
        res = self.nodes[0].testmempoolaccept([tx.serialize().hex()])[0]
        assert_equal(res['allowed'], True)
        assert_equal(res['vsize'], sigop_equivalent_vsize)

        # check that the ancestor and descendant size calculations in the mempool
        # also use the same max(sigop_equivalent_vsize, serialized_vsize) logic
        # (to keep it simple, we only test the case here where the sigop vsize
        # is much larger than the serialized vsize, i.e. we create a small child
        # tx by getting rid of the large padding outputs)
        while len(tx.vout) > 1:
            tx.vout.pop()
        tx.vout[0].scriptPubKey = CScript([OP_RETURN, b'test123'])
        assert_greater_than(sigop_equivalent_vsize, tx.get_vsize())
        self.nodes[0].sendrawtransaction(hexstring=tx.serialize().hex(), maxburnamount='1.0')

        # fetch parent tx (funding tx), which doesn't contain any sigops
        parent_txid = tx.vin[0].prevout.hash.to_bytes(32, 'big').hex()
        parent_tx = tx_from_hex(self.nodes[0].getrawtransaction(txid=parent_txid))

        entry_child = self.nodes[0].getmempoolentry(tx.rehash())
        assert_equal(entry_child['descendantcount'], 1)
        assert_equal(entry_child['descendantsize'], sigop_equivalent_vsize)
        assert_equal(entry_child['ancestorcount'], 2)
        assert_equal(entry_child['ancestorsize'], sigop_equivalent_vsize + parent_tx.get_vsize())

        entry_parent = self.nodes[0].getmempoolentry(parent_tx.rehash())
        assert_equal(entry_parent['ancestorcount'], 1)
        assert_equal(entry_parent['ancestorsize'], parent_tx.get_vsize())
        assert_equal(entry_parent['descendantcount'], 2)
        assert_equal(entry_parent['descendantsize'], parent_tx.get_vsize() + sigop_equivalent_vsize)

    def test_sigops_package(self):
        """Test sigops package limits using P2WSH spending.

        Note: The original upstream test used bare multisig outputs (37 bytes) which
        exceed MAX_OUTPUT_SCRIPT_SIZE=34. With REDUCED_DATA, the output size limit is
        enforced unconditionally in mempool acceptance (validation.cpp:990), so bare
        multisig cannot be tested in the mempool. This test uses P2WSH spending instead,
        which properly counts sigops in the witness script while staying within the
        34-byte output size limit.
        """
        self.log.info("Test sigops package limits using P2WSH spending")
        # P2WSH outputs are 34 bytes (compliant with MAX_OUTPUT_SCRIPT_SIZE=34)
        self.restart_node(0, extra_args=["-bytespersigop=5000"] + self.extra_args[0])

        # Create P2WSH outputs with high-sigop witness scripts that will be spent
        # Using witness script with OP_CHECKMULTISIG = 20 sigops
        # 20 sigops * 5000 bytes/sigop / 4 (witness scale) = 25000 vbytes
        num_sigops = MAX_PUBKEYS_PER_MULTISIG  # 20 sigops
        max_sigops_vsize = num_sigops * 5000 // WITNESS_SCALE_FACTOR  # 25000 vbytes

        # Create a witness script with 20 sigops (OP_CHECKMULTISIG counts as 20)
        witness_script = CScript([OP_FALSE, OP_IF, OP_CHECKMULTISIG, OP_ENDIF, OP_TRUE])

        # Fund P2WSH outputs that we'll spend
        p2wsh_script = script_to_p2wsh_script(witness_script)

        fund_parent = self.wallet.send_to(
            from_node=self.nodes[0],
            scriptPubKey=p2wsh_script,
            amount=2000000,  # 0.02 BTC
        )

        # Mine the funding transaction
        self.generate(self.nodes[0], 1)

        # Create parent tx spending the P2WSH output, creating another P2WSH output for child
        tx_parent = CTransaction()
        tx_parent.vin = [CTxIn(COutPoint(int(fund_parent["txid"], 16), fund_parent["sent_vout"]))]
        tx_parent.wit.vtxinwit = [CTxInWitness()]
        tx_parent.wit.vtxinwit[0].scriptWitness.stack = [bytes(witness_script)]
        tx_parent.vout = [CTxOut(1900000, p2wsh_script)]  # Output P2WSH for child to spend

        # Create child tx spending from parent's P2WSH output with high sigops witness
        tx_child = CTransaction()
        tx_child.vin = [CTxIn(COutPoint(int(tx_parent.rehash(), 16), 0))]
        tx_child.wit.vtxinwit = [CTxInWitness()]
        tx_child.wit.vtxinwit[0].scriptWitness.stack = [bytes(witness_script)]
        tx_child.vout = [CTxOut(1800000, p2wsh_script)]  # Output to P2WSH (not OP_RETURN to avoid maxburnamount)

        # Separately, the parent tx is ok
        parent_individual_testres = self.nodes[0].testmempoolaccept([tx_parent.serialize().hex()])[0]
        assert parent_individual_testres["allowed"], f"Parent tx rejected: {parent_individual_testres}"
        assert_equal(parent_individual_testres["vsize"], max_sigops_vsize)

        # Together as a package, verify sigops-adjusted vsize is used
        packet_test = self.nodes[0].testmempoolaccept([tx_parent.serialize().hex(), tx_child.serialize().hex()])

        # Both should be allowed (2 * 25000 = 50000 < 101000 ancestor limit)
        assert packet_test[0]["allowed"], f"Parent tx in package rejected: {packet_test[0]}"
        assert packet_test[1]["allowed"], f"Child tx in package rejected: {packet_test[1]}"

        # Submit the package and verify mempool entries have correct sigops-adjusted vsize
        self.nodes[0].submitpackage([tx_parent.serialize().hex(), tx_child.serialize().hex()])

        parent_entry = self.nodes[0].getmempoolentry(tx_parent.rehash())
        child_entry = self.nodes[0].getmempoolentry(tx_child.rehash())

        # Verify sigops-adjusted vsize is used in mempool accounting
        assert_equal(parent_entry["vsize"], max_sigops_vsize)
        assert_equal(child_entry["vsize"], max_sigops_vsize)
        assert_equal(child_entry["ancestorsize"], 2 * max_sigops_vsize)

        # Transactions are tiny in actual weight (the sigops inflation is for mempool accounting)
        assert_greater_than(2000, tx_parent.get_weight())
        assert_greater_than(2000, tx_child.get_weight())

    def test_legacy_sigops_stdness(self):
        self.log.info("Test a transaction with too many legacy sigops in its inputs is non-standard.")

        # Restart with the test settings
        self.restart_node(0, extra_args=[f'-maxtxlegacysigops={MAX_STD_LEGACY_SIGOPS}'])

        # Create a P2SH script with 15 sigops.
        _, dummy_pubkey = generate_keypair()
        packed_redeem_script = [dummy_pubkey]
        for _ in range(MAX_STD_P2SH_SIGOPS - 1):
            packed_redeem_script += [OP_2DUP, OP_CHECKSIG, OP_DROP]
        packed_redeem_script = CScript(packed_redeem_script + [OP_CHECKSIG, OP_NOT])
        packed_p2sh_script = script_to_p2sh_script(packed_redeem_script)

        # Create enough outputs to reach the sigops limit when spending them all at once.
        outpoints = []
        for _ in range(int(MAX_STD_LEGACY_SIGOPS / MAX_STD_P2SH_SIGOPS) + 1):
            res = self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=packed_p2sh_script, amount=1_000)
            txid = int.from_bytes(bytes.fromhex(res["txid"]), byteorder="big")
            outpoints.append(COutPoint(txid, res["sent_vout"]))
        self.generate(self.nodes[0], 1)

        # Spending all these outputs at once accounts for 2505 legacy sigops and is non-standard.
        nonstd_tx = CTransaction()
        nonstd_tx.vin = [CTxIn(op, CScript([b"", packed_redeem_script])) for op in outpoints]
        nonstd_tx.vout = [CTxOut(0, CScript([OP_RETURN, b""]))]
        assert_raises_rpc_error(-26, "bad-txns-input-sigops-toomany-overall", self.nodes[0].sendrawtransaction, nonstd_tx.serialize().hex())

        # Spending one less accounts for 2490 legacy sigops and is standard.
        std_tx = deepcopy(nonstd_tx)
        std_tx.vin.pop()
        self.nodes[0].sendrawtransaction(std_tx.serialize().hex())

        # Make sure the original, non-standard, transaction can be mined.
        self.generateblock(self.nodes[0], output="raw(42)", transactions=[nonstd_tx.serialize().hex()])

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        for bytes_per_sigop in (DEFAULT_BYTES_PER_SIGOP, 43, 81, 165, 327, 649, 1072):
            if bytes_per_sigop == DEFAULT_BYTES_PER_SIGOP:
                self.log.info(f"Test default sigops limit setting ({bytes_per_sigop} bytes per sigop)...")
            else:
                bytespersigop_parameter = f"-bytespersigop={bytes_per_sigop}"
                self.log.info(f"Test sigops limit setting {bytespersigop_parameter}...")
                self.restart_node(0, extra_args=[bytespersigop_parameter] + self.extra_args[0])

            for num_sigops in (69, 101, 142, 183, 222):
                self.test_sigops_limit(bytes_per_sigop, num_sigops)

            self.generate(self.wallet, 1)

        self.test_sigops_package()
        self.test_legacy_sigops_stdness()


if __name__ == '__main__':
    BytesPerSigOpTest(__file__).main()
