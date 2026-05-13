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


SECONDARY (next) REPORT:

Strategic Report: The Sovereign Mesh Realized
1. Executive Summary: The Vision at 19 Years
The Omni-Social Ecosystem has transitioned from a conceptual framework to a living, rendering reality. We have successfully implemented the "Sovereign Bridge": a multi-layered architecture where a user’s identity is held in a local desktop vault (iYou Home) and project-wide permissions are handled via a decentralized OIDC provider (iYou IdP), all manifesting in a unified web interface (iYou WUN).

The Core Mandate: "Identity is portable, Data is content-addressed, and Governance is verifiable."

2. Historic Achievements
During this sprint, we defeated the "Integration Bog" of modern web security and local networking to achieve the following:

A. The Sovereign Handshake (Tauri ↔ Web)
Protocol: Developed a custom WebSocket Bridge (ws://127.0.0.1:9001) that allows the browser to request cryptographic signatures from the Rust-based desktop vault.

Dual-Mode Signing: The vault now handles both OIDC Challenges (for authentication) and Nostr Events (for social activity) using a discriminated union pattern in React/TypeScript and a match-arm pipe in Rust.

Sovereign User Mapping: Built a custom Django auth backend that extracts DIDs (Decentralized Identifiers) from identity tokens and maps them to local database users, ensuring a user's data follows their key, not their account.

B. Session Persistence & Browser "Glue"
The Groundhog Victory: Overcame Intel Mac/Brave security restrictions regarding SameSite and Secure flags on non-HTTPS localhost.

Isolation Architecture: Implemented Unique Session Naming (wun_sessionid vs idp_sessionid) to prevent cookie collisions between services running on the same IP but different ports (8000/8001).

C. Live Social Integration
Nostr "Kind 1" Mastery: Achieved the first successful broadcast of a text note to global relays (wss://nos.lol, wss://relay.damus.io), signed entirely within the user's local hardware enclave.

Template Refinement: Fixed "Formatting Bog" issues in the Django feed, enabling a clean, responsive rendering of verified decentralized data.

3. Current Technical Stack
The Soul (iyou_home): Rust/Tauri vault. Manages Ed25519 keys; computes SHA256 Nostr event IDs; handles WebSocket signature requests.

The Source (iyou_idp): Django OIDC Provider. Issues identity tokens associated with DIDs; utilizes RSA key-signing.

The Face (iyou_wun): Django Web App. Orchestrates the Nostr feed; manages sovereign sessions; acts as the primary user interface.

4. Strategic Goals & Next Steps
With the "Front Door" now wide open, the next phase of development centers on the Storage and Interaction Layers:

Goal 1: Content-Addressed Storage (Blossom/IPFS)
Task: Implement the BUD-01 (Blossom) protocol to allow users to host their own media hubs.

Integration: Use Nostr Kind 1063 (File Metadata) to index locally-hosted media on the global feed.

Goal 2: Interaction Dynamics (Nostr Kind 7)
Task: Implement "Likes" and "Replies."

Challenge: Every interaction must be a signed event. We must refine the UX to ensure the Tauri "Signing Popup" is seamless and non-intrusive.

Goal 3: Auditable Governance (Polly Django)
Task: Finalize the integration of the Polly polling protocol, allowing the feed to display cryptographically verifiable voting events.

Goal 4: Progressive Sovereignty (Onboarding)
Task: Introduce Passkey (WebAuthn) as a Level 1 entry point for users who do not yet have a desktop vault, allowing them to "graduate" to full sovereignty later.

5. Maintenance Mandates for Future Teams
The 127.0.0.1 Rule: To satisfy OIDC Issuer verification on Mac development environments, all internal back-channel URLs must remain standardized to the IP address, not "localhost."

The Async Signing Rule: Never block the main WebSocket thread in the Rust backend. Always spawn a task to pipe signature requests to the UI to prevent protocol deadlocks.

Unique Cookies: All new ecosystem apps must utilize unique SESSION_COOKIE_NAME strings to maintain session integrity across the mesh.

Status: ALL SYSTEMS GO. THE BRIDGE IS OPEN. 🚀
