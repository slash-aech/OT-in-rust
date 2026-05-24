# oblivious-transfer-in-rust
A production grade library for facilitiating 1-out-of-2 oblivious transfer protocol among two parties

## Cryptographic Protocol Specification

This library implements the Bellare-Micali 1-out-of-2 Oblivious Transfer (OT) protocol over an abstract prime-order elliptic curve group $\mathbb{G}$ with generator $G$. 

### Protocol Walkthrough

Given a Sender holding two payloads $(m_0, m_1)$ and a Receiver holding a selection bit $b \in \{0, 1\}$:

#### 1. Setup Phase (Sender)
The sender samples a random scalar $c \leftarrow \mathbb{Z}_q$ and computes the global session constant:
$$C = c \cdot G$$

#### 2. Key Selection Phase (Receiver)
The receiver samples a private scalar $x \leftarrow \mathbb{Z}_q$. Depending on their choice bit $b$, they construct a public key pair $(PK_0, PK_1)$ such that their chosen index maps directly to a public key where they know the corresponding discrete logarithm:

$$\text{If } b = 0: \quad PK_0 = x \cdot G, \quad PK_1 = C - PK_0$$
$$\text{If } b = 1: \quad PK_1 = x \cdot G, \quad PK_0 = C - PK_1$$

The Receiver transmits $PK_0$ to the Sender. $PK_1$ is implicitly computed by the Sender via subtraction.

#### 3. Transmission Phase (Sender)
The Sender derives two symmetric encryption keys $(K_0, K_1)$ using their secret session scalar $c$:
$$K_0 = \text{HKDF}(c \cdot PK_0)$$
$$K_1 = \text{HKDF}(c \cdot PK_1)$$

The messages are encrypted into ciphertexts $(ct_0, ct_1)$ using an authenticated cipher (AEAD) driven by these keys, then sent to the Receiver.

#### 4. Decryption Phase (Receiver)
The Receiver derives their targeted decryption key $K_R$ using their original private scalar $x$:
$$K_R = \text{HKDF}(x \cdot C)$$

### The Mathematical Invariant

The protocol guarantees security because the underlying Diffie-Hellman keys match perfectly at the chosen index:

$$\text{If } b = 0: \quad c \cdot PK_0 = c \cdot (x \cdot G) = x \cdot (c \cdot G) = x \cdot C$$
$$\text{If } b = 1: \quad c \cdot PK_1 = c \cdot (x \cdot G) = x \cdot (c \cdot G) = x \cdot C$$

At the unchosen index, computing the symmetric key requires solving the **Computational Diffie-Hellman (CDH)** problem over $\mathbb{G}$, which is hard. Because the Sender only receives a single point $PK_0$ that appears uniformly random, they gain zero information about $b$.


## Project Structure
```
OT-in-rust/
├── Cargo.toml
└── src/
    ├── lib.rs              # Crate entry point, clean type re-exports, and integration tests
    ├── errors.rs           # Strict domain-specific protocol error definitions
    ├── crypto.rs           # Core cryptographic primitives (HKDF, Curve Math Wrapper, AEAD)
    └── states/
        ├── mod.rs          # State glue module
        ├── sender.rs       # Sender state machine (Setup -> Transmit)
        └── receiver.rs     # Receiver state machine (Keys -> Decryption)

```

## Dependencies(Cargo.toml)
```
chacha20poly1305 = "0.10.1"
generic-ec = {version = "0.5.0", features=["all-curves"]}
hkdf = "0.13.0"
rand = { version = "0.8.5", features = ["std", "getrandom"] }
sha2 = "0.11.0"
zeroize = "1.8.2"
```
