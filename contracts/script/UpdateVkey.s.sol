// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {stdJson} from "forge-std/StdJson.sol";
import {SP1Vector} from "../src/SP1Vector.sol";
import {BaseScript} from "./Base.s.sol";

// Required environment variables:
// - CHAINS (comma separated list of chain names)
// - CONTRACT_ADDRESS_{CHAIN_ID}

contract UpdateVkeyScript is BaseScript {
    using stdJson for string;

    function setUp() public {}

    string internal constant KEY = "UpdateVkey";

    /// Reads CONTRACT_ADDRESS_<CHAIN_ID> from the environment variables and updates the SP1 Verifier and program vkey.
    function run() external multichain(KEY) broadcaster {
        string memory contractAddressKey = string.concat("CONTRACT_ADDRESS_", vm.toString(block.chainid));
        address existingProxyAddress = vm.envAddress(contractAddressKey);

        SP1Vector sp1Vector = SP1Vector(address(existingProxyAddress));

        // v4 program vkey
        sp1Vector.updateVectorXProgramVkey(0x00d5f987ed01b099560084af2744a848f00a7f84703d07aecf3a68720f4223d4);
    }
}
