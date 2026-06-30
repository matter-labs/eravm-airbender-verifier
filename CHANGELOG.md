# Changelog

## [29.8.0](https://github.com/matter-labs/eravm-airbender-verifier/compare/v29.7.1...v29.8.0) (2026-06-19)


### Features

* CPU-only SNARK prover via optional gpu_fri feature ([#55](https://github.com/matter-labs/eravm-airbender-verifier/issues/55)) ([c09bf3d](https://github.com/matter-labs/eravm-airbender-verifier/commit/c09bf3ddcd12de0f8fa2d998ad5d1d0cb2b00602))
* Implement public output ([#4](https://github.com/matter-labs/eravm-airbender-verifier/issues/4)) ([bda698c](https://github.com/matter-labs/eravm-airbender-verifier/commit/bda698caec22f6614bac8b1588922f7d62b8253d))
* Initial implementation ([#2](https://github.com/matter-labs/eravm-airbender-verifier/issues/2)) ([dcb0b56](https://github.com/matter-labs/eravm-airbender-verifier/commit/dcb0b560b5c1924aa39c850d6a272ee5e168453e))
* Integrate updated wrapper ([#7](https://github.com/matter-labs/eravm-airbender-verifier/issues/7)) ([b58bd77](https://github.com/matter-labs/eravm-airbender-verifier/commit/b58bd7781a3bb54695188c204f9631bd5407fd05))
* **server:** bump airbender to v0.2.3, wire GpuProverConfig ([#54](https://github.com/matter-labs/eravm-airbender-verifier/issues/54)) ([18e6607](https://github.com/matter-labs/eravm-airbender-verifier/commit/18e6607107da1377ed9f928ca2619396e28fcb51))
* **server:** load FRI and SNARK VKs from disk, add vks/ + CI guards ([#22](https://github.com/matter-labs/eravm-airbender-verifier/issues/22)) ([f67b533](https://github.com/matter-labs/eravm-airbender-verifier/commit/f67b53370be3f69d5deb7928f677ccce72439b6f))
* **server:** report errors and panics to Sentry ([#46](https://github.com/matter-labs/eravm-airbender-verifier/issues/46)) ([0d3cf76](https://github.com/matter-labs/eravm-airbender-verifier/commit/0d3cf76ab151136b293256232ff870c6f657bebd))
* **server:** Use prover as a server ([#3](https://github.com/matter-labs/eravm-airbender-verifier/issues/3)) ([0e57505](https://github.com/matter-labs/eravm-airbender-verifier/commit/0e575052bafe898b2ba264e6e253e03eedbb19e3))


### Bug Fixes

* **ci:** grant update-vks dispatcher pull-requests: write ([#24](https://github.com/matter-labs/eravm-airbender-verifier/issues/24)) ([ccb2b4e](https://github.com/matter-labs/eravm-airbender-verifier/commit/ccb2b4e072aef6046e51cf9f1e9094b8b132b411))
* **ci:** set GH_REPO so update-vks gh calls work without a checkout ([#25](https://github.com/matter-labs/eravm-airbender-verifier/issues/25)) ([9a7582e](https://github.com/matter-labs/eravm-airbender-verifier/commit/9a7582e425f6e26a07b4a934e965f1225387c87a))
* harden verifier witness validation and VM rollback ([#45](https://github.com/matter-labs/eravm-airbender-verifier/issues/45)) ([9881acb](https://github.com/matter-labs/eravm-airbender-verifier/commit/9881acbdcd19ddbc881524d08a218f523994abaf))
* **host:** wire security level into the GPU prover ([#13](https://github.com/matter-labs/eravm-airbender-verifier/issues/13)) ([75e3051](https://github.com/matter-labs/eravm-airbender-verifier/commit/75e30513778546675d773e66ac92e2011a92090a))
* **server:** catch prover panics and report them as failed proofs ([#56](https://github.com/matter-labs/eravm-airbender-verifier/issues/56)) ([063da52](https://github.com/matter-labs/eravm-airbender-verifier/commit/063da529d57a9e3ae793e19eb571b418eedbf4d1))
* **server:** deserialize FRI input as flat struct from zksync-era ([#30](https://github.com/matter-labs/eravm-airbender-verifier/issues/30)) ([6f2d8bc](https://github.com/matter-labs/eravm-airbender-verifier/commit/6f2d8bca06da853de219618de8e36b9a70496f47))
