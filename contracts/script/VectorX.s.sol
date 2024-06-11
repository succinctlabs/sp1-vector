// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/console.sol";
import {Script} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {SP1Verifier} from "@sp1-contracts/SP1Verifier.sol";
import {VectorX} from "../src/VectorX.sol";

contract VectorXScript is Script {
    using stdJson for string;

    VectorX public vectorx;

    function setUp() public {}

    function run() public returns (address) {
        vm.startBroadcast();

        // Read trusted initialization parameters from .env
        address guardian = msg.sender;
        uint32 height = uint32(vm.envUint("GENESIS_HEIGHT"));
        bytes32 header = bytes32(vm.envBytes32("GENESIS_HEADER"));
        uint64 authoritySetId = uint64(vm.envUint("GENESIS_AUTHORITY_SET_ID"));
        bytes32 authoritySetHash = bytes32(vm.envBytes32("GENESIS_AUTHORITY_SET_HASH"));
        uint32 headerRangeCommitmentTreeSize = uint32(vm.envUint("HEADER_RANGE_COMMITMENT_TREE_SIZE"));
        bytes32 vectorXProgramVkey = bytes32(vm.envBytes32("VECTORX_PROGRAM_VKEY"));
        SP1Verifier verifier = new SP1Verifier();

        vectorx = new VectorX();
        vectorx.initialize(VectorX.InitParameters(
            guardian, height, header, authoritySetId, authoritySetHash, headerRangeCommitmentTreeSize, vectorXProgramVkey, address(verifier)
        ));

        vm.stopBroadcast();

        return address(vectorx);
    }
}