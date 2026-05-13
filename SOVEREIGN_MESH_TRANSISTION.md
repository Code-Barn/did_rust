# Executive Summary: The Sovereign Mesh Transition

## 1. Project Overview

The Omni-Social Ecosystem is a decentralized platform designed to return data ownership to the user. It is built on the **Omni-Social Mandate**: *"Identity is portable, Data is content-addressed, and Governance is verifiable."*

The core architecture bridges a high-performance **Rust/Tauri** desktop vault with a **Django-based** web interface, using **OpenID Connect (OIDC)** and **Nostr** protocols to ensure cryptographic sovereignty.


## 2. Key Achievements Reached

During this intensive integration phase, the following milestones were achieved:

- **The Sovereign Bridge**: Successfully implemented an OIDC authentication flow where the **iYou Home** (Desktop Signer) acts as the source of truth for the **iYou IdP** (Identity Provider).

- **Cryptographic User Mapping**: Developed a custom Django backend that maps decentralized identifiers (**DIDs**) to local User objects. This allows a user to "own" their database records across different ports and services using a single private key.

- **Protocol Handshake Stability**: Resolved "Integration Bog" issues including RSA key generation for token signing, OIDC claim gatekeeping (DID vs. Email), and complex local networking (127.0.0.1/localhost alignment).

- **Session Persistence Mastery**: Overcame modern browser security restrictions (SameSite, Secure flags, and Cookie Domain conflicts) by implementing **Unique Session Naming (`wun\_sessionid`)**, ensuring stable logins on Intel Mac development environments.

- **Live Proof-of-Concept**: Achieved the first live rendering of the **Nostr Social Feed**, successfully pulling and verifying signed events based on the user's desktop-vault identity.


## 3. Current Technical State

- **IdP (Port 8000)**: Fully functional OIDC provider capable of issuing signed tokens via RSA keys.

- **WUN (Port 8001)**: Successfully authenticates via OIDC, maintains persistent sovereign sessions, and renders decentralized feeds.

- **Desktop Signer (iYou Home)**: Acts as the local "Soul" of the project, handling WebSockets and signature challenges without exposing private keys to the web.


## 4. Strategic Goals & Roadmap

With the "Identity Bridge" locked, the project now moves into the **Protocol Expansion** phase:

### Phase I: The Storage Layer (Blossom & IPFS)

- **Goal**: Move from centralized database storage to content-addressed storage.

- **Task**: Implement the **Blossom BUD-01** protocol to allow users to host their own media hubs, indexed via Nostr Kind 1063 metadata.

### Phase II: Unified Messaging (XMPP & Nostr)

- **Goal**: Real-time, E2EE (End-to-End Encrypted) communications.

- **Task**: Integrate **Prosody (XMPP)** for instant messaging and the **Nostr Publisher** for global microblogging, all signed by the same root DID.

### Phase III: Auditable Governance (Polling Protocol)

- **Goal**: Verifiable collective decision-making.

- **Task**: Protocolize the **Polly Django** app to create auditable voting schemas where every vote is a cryptographically signed event.

### Phase IV: Progressive Sovereignty (Onboarding)

- **Goal**: Reduce the "Newb" friction.

- **Task**: Implement **Passkey (WebAuthn)** support as a Level 1 entry point, allowing users to "graduate" to full Desktop Hub sovereignty as they become more comfortable.


## 5. Final Technical Mandate

Future development teams must adhere to the **Address Alignment Rule**: To maintain session integrity on local and mesh networks, all internal server-to-server calls must use standardized IP strings (e.g., `127.0.0.1`) to satisfy OIDC Issuer verification, while the UI must utilize unique cookie naming to prevent cross-app session pollution.

