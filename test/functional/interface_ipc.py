#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the IPC (multiprocess) interface."""
import asyncio
import copy
import errno
from io import BytesIO
from pathlib import Path
import shutil
import socket
from test_framework.messages import (CBlock, CTransaction, ser_uint256, COIN, MAX_BLOCK_WEIGHT, MINIMUM_BLOCK_RESERVED_WEIGHT)
from test_framework.test_framework import (BitcoinTestFramework, assert_equal)
from test_framework.wallet import MiniWallet

# Test may be skipped and not have capnp installed
try:
    import capnp  # type: ignore[import] # noqa: F401
except ImportError:
    pass


async def connect_unix_socket(path, timeout):
    """Return a connected socket, waiting for space in a full Unix accept queue."""
    async def connect():
        loop = asyncio.get_running_loop()
        while True:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.setblocking(False)
            connected = False
            try:
                await loop.sock_connect(sock, str(path))
                # asyncio can report success after EAGAIN on a full Unix queue.
                # Verify the connection before handing the socket to a transport.
                sock.getpeername()
                connected = True
                return sock
            except OSError as error:
                if error.errno != errno.ENOTCONN:
                    raise
            finally:
                if not connected:
                    sock.close()
            await asyncio.sleep(0.01)

    return await asyncio.wait_for(connect(), timeout)


class IPCInterfaceTest(BitcoinTestFramework):

    def skip_test_if_missing_module(self):
        self.skip_if_no_ipc()
        self.skip_if_no_py_capnp()

    def load_capnp_modules(self):
        if capnp_bin := shutil.which("capnp"):
            # Add the system cap'nproto path so include/capnp/c++.capnp can be found.
            capnp_dir = Path(capnp_bin).parent.parent / "include"
        else:
            # If there is no system cap'nproto, the pycapnp module should have its own "bundled"
            # includes at this location. If pycapnp was installed with bundled capnp,
            # capnp/c++.capnp can be found here.
            capnp_dir = Path(capnp.__path__[0]).parent
        src_dir = Path(self.config['environment']['SRCDIR']) / "src"
        mp_dir = src_dir / "ipc" / "libmultiprocess" / "include"
        # List of import directories. Note: it is important for mp_dir to be
        # listed first, in case there are other libmultiprocess installations on
        # the system, to ensure that `import "/mp/proxy.capnp"` lines load the
        # same file as capnp.load() loads directly below, and there are not
        # "failed: Duplicate ID @0xcc316e3f71a040fb" errors.
        imports = [str(mp_dir), str(capnp_dir), str(src_dir)]
        return {
            "proxy": capnp.load(str(mp_dir / "mp" / "proxy.capnp"), imports=imports),
            "init": capnp.load(str(src_dir / "ipc" / "capnp" / "init.capnp"), imports=imports),
            "echo": capnp.load(str(src_dir / "ipc" / "capnp" / "echo.capnp"), imports=imports),
            "mining": capnp.load(str(src_dir / "ipc" / "capnp" / "mining.capnp"), imports=imports),
        }

    def set_test_params(self):
        self.num_nodes = 1

    def setup_nodes(self):
        self.extra_init = [{"ipcbind": True}]
        super().setup_nodes()
        # Use this function to also load the capnp modules (we cannot use set_test_params for this,
        # as it is being called before knowing whether capnp is available).
        self.capnp_modules = self.load_capnp_modules()

    async def make_capnp_init_ctx(self):
        node = self.nodes[0]
        # Establish a connection, and create Init proxy object.
        sock = await connect_unix_socket(node.ipc_socket_path, 60 * self.options.timeout_factor)
        try:
            connection = await capnp.AsyncIoStream.create_unix_connection(sock=sock)
        except BaseException:
            sock.close()
            raise
        client = capnp.TwoPartyClient(connection)
        init = client.bootstrap().cast_as(self.capnp_modules['init'].Init)
        # Create a remote thread on the server for the IPC calls to be executed in.
        threadmap = init.construct().threadMap
        thread = threadmap.makeThread("pythread").result
        ctx = self.capnp_modules['proxy'].Context()
        ctx.thread = thread
        # Return both.
        return ctx, init

    async def parse_and_deserialize_block(self, block_template, ctx):
        block_data = BytesIO((await block_template.result.getBlock(ctx)).result)
        block = CBlock()
        block.deserialize(block_data)
        return block

    async def parse_and_deserialize_coinbase_tx(self, block_template, ctx):
        coinbase_data = BytesIO((await block_template.result.getCoinbaseTx(ctx)).result)
        tx = CTransaction()
        tx.deserialize(coinbase_data)
        return tx

    def run_echo_test(self):
        self.log.info("Running echo test")
        async def async_routine():
            ctx, init = await self.make_capnp_init_ctx()
            self.log.debug("Create Echo proxy object")
            echo = init.makeEcho(ctx).result
            self.log.debug("Test a few invocations of echo")
            for s in ["hallo", "", "haha"]:
                result_eval = (await echo.echo(ctx, s)).result
                assert_equal(s, result_eval)
            self.log.debug("Destroy the Echo object")
            echo.destroy(ctx)
        asyncio.run(capnp.run(async_routine()))

    def run_mining_test(self):
        self.log.info("Running mining test")
        block_hash_size = 32
        block_header_size = 80
        timeout = 1000.0 # 1000 milliseconds
        miniwallet = MiniWallet(self.nodes[0])

        async def async_routine():
            ctx, init = await self.make_capnp_init_ctx()
            self.log.debug("Create Mining proxy object")
            mining = init.makeMining(ctx)
            self.log.debug("Test simple inspectors")
            assert (await mining.result.isTestChain(ctx)).result
            assert_equal((await mining.result.isInitialBlockDownload(ctx)).result, self.nodes[0].getblockchaininfo()["initialblockdownload"])
            blockref = await mining.result.getTip(ctx)
            assert blockref.hasResult
            assert_equal(len(blockref.result.hash), block_hash_size)
            current_block_height = self.nodes[0].getchaintips()[0]["height"]
            assert blockref.result.height == current_block_height
            self.log.debug("Mine a block")
            wait = mining.result.waitTipChanged(ctx, blockref.result.hash, )
            self.generate(self.nodes[0], 1)
            newblockref = await wait
            assert_equal(len(newblockref.result.hash), block_hash_size)
            assert_equal(newblockref.result.height, current_block_height + 1)
            self.log.debug("Wait for timeout")
            wait = mining.result.waitTipChanged(ctx, newblockref.result.hash, timeout)
            oldblockref = await wait
            assert_equal(len(newblockref.result.hash), block_hash_size)
            assert_equal(oldblockref.result.hash, newblockref.result.hash)
            assert_equal(oldblockref.result.height, newblockref.result.height)

            self.log.debug("Create a template")
            opts = self.capnp_modules['mining'].BlockCreateOptions()
            opts.useMempool = True
            opts.blockReservedWeight = 4000
            opts.coinbaseOutputMaxAdditionalSigops = 0
            template = mining.result.createNewBlock(opts)
            self.log.debug("Test some inspectors of Template")
            header = await template.result.getBlockHeader(ctx)
            assert_equal(len(header.result), block_header_size)
            block = await self.parse_and_deserialize_block(template, ctx)
            assert_equal(ser_uint256(block.hashPrevBlock), newblockref.result.hash)
            assert len(block.vtx) >= 1
            txfees = await template.result.getTxFees(ctx)
            assert_equal(len(txfees.result), 0)
            txsigops = await template.result.getTxSigops(ctx)
            assert_equal(len(txsigops.result), 0)
            coinbase_data = BytesIO((await template.result.getCoinbaseTx(ctx)).result)
            coinbase = CTransaction()
            coinbase.deserialize(coinbase_data)
            assert_equal(coinbase.vin[0].prevout.hash, 0)
            self.log.debug("Wait for a new template")
            waitoptions = self.capnp_modules['mining'].BlockWaitOptions()
            waitoptions.timeout = timeout
            waitoptions.feeThreshold = 1
            waitnext = template.result.waitNext(ctx, waitoptions)
            self.generate(self.nodes[0], 1)
            template2 = await waitnext
            block2 = await self.parse_and_deserialize_block(template2, ctx)
            assert_equal(len(block2.vtx), 1)
            self.log.debug("Wait for another, but time out")
            template3 = await template2.result.waitNext(ctx, waitoptions)
            assert_equal(template3.to_dict(), {})
            self.log.debug("Wait for another, get one after increase in fees in the mempool")
            waitnext = template2.result.waitNext(ctx, waitoptions)
            miniwallet.send_self_transfer(fee_rate=10, from_node=self.nodes[0])
            template4 = await waitnext
            block3 = await self.parse_and_deserialize_block(template4, ctx)
            assert_equal(len(block3.vtx), 2)
            self.log.debug("Wait again, this should return the same template, since the fee threshold is zero")
            waitoptions.feeThreshold = 0
            template5 = await template4.result.waitNext(ctx, waitoptions)
            block4 = await self.parse_and_deserialize_block(template5, ctx)
            assert_equal(len(block4.vtx), 2)
            waitoptions.feeThreshold = 1
            self.log.debug("Wait for another, get one after increase in fees in the mempool")
            waitnext = template5.result.waitNext(ctx, waitoptions)
            miniwallet.send_self_transfer(fee_rate=10, from_node=self.nodes[0])
            template6 = await waitnext
            block4 = await self.parse_and_deserialize_block(template6, ctx)
            assert_equal(len(block4.vtx), 3)
            self.log.debug("Wait for another, but time out, since the fee threshold is set now")
            template7 = await template6.result.waitNext(ctx, waitoptions)
            assert_equal(template7.to_dict(), {})

            self.log.debug("Interrupt a pending wait, then reuse the same template")
            waitoptions.timeout = 60000.0
            waitoptions.feeThreshold = 1
            async def wait_for_template():
                return await template6.result.waitNext(ctx, waitoptions)
            wait_task = asyncio.create_task(wait_for_template())
            await asyncio.sleep(0.1)
            assert not wait_task.done()
            await template6.result.interruptWait()
            interrupted = await asyncio.wait_for(wait_task, timeout=10)
            assert_equal(interrupted.to_dict(), {})
            # Queued repeated interrupts coalesce into one interruption.
            await template6.result.interruptWait()
            await template6.result.interruptWait()
            waitoptions.timeout = 0.0
            waitoptions.feeThreshold = 0
            assert_equal((await template6.result.waitNext(ctx, waitoptions)).to_dict(), {})
            resumed = await template6.result.waitNext(ctx, waitoptions)
            assert_equal(len((await self.parse_and_deserialize_block(resumed, ctx)).vtx), 3)
            await resumed.result.destroy(ctx)

            current_block_height = self.nodes[0].getchaintips()[0]["height"]
            check_opts = self.capnp_modules['mining'].BlockCheckOptions()
            template = await mining.result.createNewBlock(opts)
            block = await self.parse_and_deserialize_block(template, ctx)
            coinbase = await self.parse_and_deserialize_coinbase_tx(template, ctx)
            balance = miniwallet.get_balance()
            coinbase.vout[0].scriptPubKey = miniwallet.get_output_script()
            coinbase.vout[0].nValue = COIN
            block.vtx[0] = coinbase
            block.hashMerkleRoot = block.calc_merkle_root()
            original_version = block.nVersion
            self.log.debug("Submit a block with a bad version")
            block.nVersion = 0
            block.solve()
            res = await mining.result.checkBlock(block.serialize(), check_opts)
            assert_equal(res.result, False)
            assert_equal(res.reason, "bad-version(0x00000000)")
            res = await template.result.submitSolution(ctx, block.nVersion, block.nTime, block.nNonce, coinbase.serialize())
            assert_equal(res.result, False)
            self.log.debug("Reject a changed coinbase with an invalid witness commitment")
            block.nVersion = original_version
            invalid_coinbase = copy.deepcopy(coinbase)
            assert invalid_coinbase.wit.vtxinwit[0].scriptWitness.stack
            invalid_coinbase.wit.vtxinwit[0].scriptWitness.stack[0] = b'\xff' * 32
            block.solve()
            res = await template.result.submitSolution(ctx, block.nVersion, block.nTime, block.nNonce, invalid_coinbase.serialize())
            assert_equal(res.result, False)
            assert_equal(self.nodes[0].getblockcount(), current_block_height)

            self.log.debug("Submit a valid block")
            block.nVersion = original_version
            block.solve()
            res = await mining.result.checkBlock(block.serialize(), check_opts)
            assert_equal(res.result, True)
            res = await template.result.submitSolution(ctx, block.nVersion, block.nTime, block.nNonce, coinbase.serialize())
            assert_equal(res.result, True)
            assert_equal(self.nodes[0].getchaintips()[0]["height"], current_block_height + 1)
            miniwallet.rescan_utxos()
            assert_equal(miniwallet.get_balance(), balance + 1)
            self.log.debug("Check block should fail now, since it is a duplicate")
            res = await mining.result.checkBlock(block.serialize(), check_opts)
            assert_equal(res.result, False)
            assert_equal(res.reason, "inconclusive-not-best-prevblk")

            self.log.debug("Destroy template objects")
            template.result.destroy(ctx)
            template2.result.destroy(ctx)
            template3.result.destroy(ctx)
            template4.result.destroy(ctx)
            template5.result.destroy(ctx)
            template6.result.destroy(ctx)
            template7.result.destroy(ctx)
        asyncio.run(capnp.run(async_routine()))

    def run_option_test(self):
        self.log.info("Test IPC option precedence and runtime validation")
        node = self.nodes[0]
        wallet = MiniWallet(node)
        tx = wallet.send_self_transfer(from_node=node)
        self.restart_node(0, extra_args=[f"-blockreservedweight={MAX_BLOCK_WEIGHT}"])
        assert_equal(len(node.getblocktemplate({"rules": ["segwit"]})["transactions"]), 0)

        async def async_routine():
            ctx, init = await self.make_capnp_init_ctx()
            mining = init.makeMining(ctx).result
            opts = self.capnp_modules['mining'].BlockCreateOptions()
            opts.useMempool = True
            opts.blockReservedWeight = MINIMUM_BLOCK_RESERVED_WEIGHT
            template = await mining.createNewBlock(opts)
            block = await self.parse_and_deserialize_block(template, ctx)
            assert_equal(len(block.vtx), 2)
            assert_equal(block.vtx[1].txid_hex, tx["txid"])
            await template.result.destroy(ctx)
            for weight, message in [
                (0, "lower than minimum safety value"),
                (MINIMUM_BLOCK_RESERVED_WEIGHT - 1, "lower than minimum safety value"),
                (MAX_BLOCK_WEIGHT + 1, "exceeds consensus maximum block weight"),
                (2**64 - 1, "exceeds consensus maximum block weight"),
            ]:
                opts.blockReservedWeight = weight
                try:
                    await mining.createNewBlock(opts)
                    raise AssertionError("invalid reserved weight accepted")
                except capnp.lib.capnp.KjException as error:
                    assert message in error.description
                    assert_equal(error.type, "FAILED")
            opts.blockReservedWeight = MINIMUM_BLOCK_RESERVED_WEIGHT
            opts.coinbaseOutputMaxAdditionalSigops = 80001
            try:
                await mining.createNewBlock(opts)
                raise AssertionError("invalid sigops accepted")
            except capnp.lib.capnp.KjException as error:
                assert "exceeds consensus maximum block sigops cost" in error.description
            opts.coinbaseOutputMaxAdditionalSigops = 80000
            opts.blockReservedWeight = MAX_BLOCK_WEIGHT
            template = await mining.createNewBlock(opts)
            assert_equal(len((await self.parse_and_deserialize_block(template, ctx)).vtx), 1)
            await template.result.destroy(ctx)
        asyncio.run(capnp.run(async_routine()))
        self.restart_node(0)

    def run_early_startup_test(self):
        self.log.info("Request mining immediately when the startup IPC socket opens")
        node = self.nodes[0]
        self.stop_node(0)
        node.start()
        async def async_routine():
            async def connect_and_create():
                while True:
                    try:
                        ctx, init = await self.make_capnp_init_ctx()
                        break
                    except (ConnectionRefusedError, FileNotFoundError):
                        await asyncio.sleep(0.005)
                mining = init.makeMining(ctx).result
                assert (await mining.getTip(ctx)).hasResult
                opts = self.capnp_modules['mining'].BlockCreateOptions()
                opts.blockReservedWeight = 4000
                template = await mining.createNewBlock(opts)
                assert_equal(len((await self.parse_and_deserialize_block(template, ctx)).vtx), 1)
                await template.result.destroy(ctx)
            await asyncio.wait_for(connect_and_create(), timeout=60 * self.options.timeout_factor)
        asyncio.run(capnp.run(async_routine()))
        node.wait_for_rpc_connection()

    def run_aborted_connection_test(self):
        self.log.info("IPC listener survives clients disconnecting immediately")
        for _ in range(32):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(self.nodes[0].ipc_socket_path))
        self.run_echo_test()

    def run_test(self):
        self.run_echo_test()
        self.run_mining_test()
        self.run_option_test()
        self.run_early_startup_test()
        self.run_aborted_connection_test()

if __name__ == '__main__':
    IPCInterfaceTest(__file__).main()
