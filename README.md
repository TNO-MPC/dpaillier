# TNO MPC Lab - Distributed Paillier

The TNO MPC lab consists of generic software components, procedures, and functionalities developed and maintained on a regular basis to facilitate and aid in the development of MPC solutions. The lab is a cross-project initiative allowing us to integrate and reuse previously developed MPC functionalities to boost the development of new protocols and solutions.

The package dpaillier is part of the TNO Go Toolbox.

*Limitations in (end-)use: the content of this repository may solely be used for applications that comply with international export control laws.*

## Distributed key generation and decryption for the Paillier cryptosystem

This package provides an implementation of a [distributed key generation algorithm for the Paillier cryptosystem](https://eprint.iacr.org/2019/1136.pdf).
It can be used to share a private key among multiple parties, so that a ciphertext can only be decrypted if they work together.

## Usage

This key generation algorithm is meant to be used by a set of parties communicating over a network.
Therefore, it is expressed as a number of stages, and to get from one stage to the next, the parties have to exchange a message with one another.

To start, agree externally on values for the parameters in `KeyGenerationParameters`.
These can be validated using their `Validate` method to make sure they are suitable.
Note that each participant should be assigned a distinct `ParticipantIndex`.

The parties can use a validated instance of the key generation parameters to start their protocol using `NewKeyGenerationProtocol`.
This results in a state struct and a set of messages to send to the other parties, or a possible error.
The state struct should be saved until all messages have been exchanged, after which each party calls the `Advance` method on the struct, supplying it with the messages received from the other parties.
This results in a new state struct and new outgoing messages.

The distributed Paillier key generation protocol is probabilistic, and has a high chance of failure.
Implementations should check for errors and restart the protcol if they occur.

The `Advance` method on `KeyGenerationStage6` results in a `PrivateKeyShare` if successful.
The private key share contains a regular `paillier.PublicKey`, for which we refer to that package's documentation.
To decrypt a ciphertext, owners of the private key shares should call their `PartiallyDecrypt` method on the ciphertext.
This results in a set of partial decryptions.
Anyone with a private key share can call its `Decrypt` method on this set to recover the plaintext.

We refer to Godoc (or the code comments) for detailed documentation.
