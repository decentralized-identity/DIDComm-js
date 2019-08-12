# Overview of DIDComm

At a high level, DIDComm encompasses multiple layer in order to exchange verifiable, symantically coherent data between one or many parties. From a architecture standpoint there's multiple layers that go into building DIDComm.

## Architecture

![](/docs/img/architecture_overview.png)

This library focuses on the cryptographic layer of DIDComm which handles encryption and signing of an arbitrary message. It does so using a JWE like structure for encryption and a compact JWS for non-repudiable signatures. 

To learn more about the data model used for encryption check [here](encryption-spec.md). 

To learn more about non-repudiable versus repudiable reference [here](https://github.com/hyperledger/aries-rfcs/tree/master/concepts/0049-repudiation).

To learn more about non-repudiable signatures check [here](/docs/signing-spec.md).

All of these documents have been moved from the [Aries-RFC](https://github.com/hyperledger/aries-rfcs) repository. To learn more about the broader aspects of DIDComm it would be best to check there.