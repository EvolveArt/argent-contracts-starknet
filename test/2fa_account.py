import pytest
import asyncio
import logging
from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.business_logic.state.state import BlockInfo
from utils.Signer import Signer
from utils.utilities import deploy, assert_revert, str_to_felt, assert_event_emmited
from utils.TransactionSender import TransactionSender, from_call_to_call_array

LOGGER = logging.getLogger(__name__)

signer = Signer(123456789987654321)
guardian = Signer(456789987654321123)
guardian_backup = Signer(354523164513454)

wrong_signer = Signer(666666666666666666)
wrong_guardian = Signer(6767676767)

DEFAULT_TIMESTAMP = 1640991600
ESCAPE_SECURITY_PERIOD = 24*7*60*60

VERSION = str_to_felt('0.1.0')

IACCOUNT_ID = 0xf10dbd44

ESCAPE_TYPE_GUARDIAN = 0
ESCAPE_TYPE_SIGNER = 1

@pytest.fixture(scope='module')
def event_loop():
    return asyncio.new_event_loop()

@pytest.fixture(scope='module')
async def get_starknet():
    starknet = await Starknet.empty()
    return starknet

def update_starknet_block(starknet, block_number=1, block_timestamp=DEFAULT_TIMESTAMP):
    starknet.state.state.block_info = BlockInfo(block_number=block_number, block_timestamp=block_timestamp, gas_price=0)

def reset_starknet_block(starknet):
    update_starknet_block(starknet=starknet)

@pytest.fixture
async def account_factory(get_starknet):
    starknet = get_starknet
    account = await deploy(starknet, "contracts/2FAccount.cairo", [signer.public_key])
    return account

@pytest.fixture
async def dapp_factory(get_starknet):
    starknet = get_starknet
    dapp = await deploy(starknet, "contracts/test/TestDapp.cairo")
    return dapp

@pytest.mark.asyncio
async def test_initializer(account_factory):
    account = account_factory
    # should be configured correctly
    assert (await account.get_version().call()).result.version == VERSION
    assert (await account.supportsInterface(IACCOUNT_ID).call()).result.success == 1

@pytest.mark.asyncio
async def test_submit_transaction(account_factory, dapp_factory):
    account = account_factory
    dapp = dapp_factory
    sender = TransactionSender(account)

    calls = [(dapp.contract_address, 'set_number', [47])]
    call_array, calldata = from_call_to_call_array(calls)
    execute_calldata = [
        len(call_array),
        *[x for t in call_array for x in t],
        len(calldata),
        *calldata,
        1]

    await sender.send_transaction([(account.contract_address, 'submit_transaction', execute_calldata)], [signer], nonce=0)
    