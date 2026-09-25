import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { PUBLIC_PAGE_PATHS, SITE_ORIGIN, SITE_SCHEMA } from '../shared/site-pages.mjs';

const publicDir = fileURLToPath(new URL('../public/', import.meta.url));
const updated = '2026-09-25';
const sourceUrl = 'https://github.com/reivenio/reiven-io';
const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (character) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[character]);
const actions = (primary = 'Share a file', href = '/share') => `<div class="page-actions"><a class="cta-btn" href="${href}">${primary}</a><a class="text-link" href="/receive">Open a received share</a></div>`;
const pages = {
  '/': {
    title: 'Reiven.io — Encrypted File & Note Sharing',
    description: 'Share encrypted files and private notes with Reiven.io. Encrypt in your browser, send a link or QR code, and use temporary storage without creating an account.',
    heading: 'Encrypted file and note sharing',
    eyebrow: 'Zero-knowledge encryption',
    intro: 'Reiven encrypts files and notes in your browser before upload. Share a link or QR code without creating an account. Encrypted uploads are held temporarily in server memory.',
    body: `${actions()}
      <section class="content-section"><h2>Two ways to share something private</h2>
        <div class="feature-grid">
          <article class="feature-card"><h3><a href="/encrypted-file-sharing">Encrypted file sharing</a></h3><p>Send a document or another file with a password-protected link. Your recipient opens it in their browser and decrypts it on their device.</p><a class="text-link" href="/share">Choose a file →</a></article>
          <article class="feature-card"><h3><a href="/encrypted-notes">Private notes</a></h3><p>Write a message, handover instruction, or private snippet. Reiven encrypts the text before uploading it, just as it does a file.</p><a class="text-link" href="/share#note">Write a note →</a></article>
        </div>
      </section>
      <section class="content-section"><h2>How it works</h2>
        <ol class="steps"><li><h3>Choose your content</h3><p>Select a file or write a note. Choose a strong password, or let QR Mode generate a random key in your browser.</p></li><li><h3>Encrypt and share</h3><p>Encryption happens on your device. Send the download link or access code, and share a manually chosen password separately. A QR link includes its key, so anyone with that link can open the content.</p></li><li><h3>Open before expiry</h3><p>The recipient decrypts in their browser. Uploads expire after 24 hours, or disappear earlier if deleted or the server restarts. Receiver deletion is enabled by default.</p></li></ol>
      </section>
      <section class="content-section"><h2>Encryption with a clear storage policy</h2><p>Reiven combines AES-256-GCM payload encryption with Argon2id password processing and an ML-KEM-768 post-quantum key-wrapping layer. Password strength and device security still matter.</p><p>The application keeps encrypted uploads in RAM, without writing them to application-managed disk files. Temporary sharing is not a backup: keep your own copy until the recipient has saved theirs.</p><p><a href="/security">Read the security model</a> and <a href="/privacy">what information the service processes</a>.</p></section>
      <section class="content-section"><h2>Before you send</h2><div class="faq-list">
        <details><summary>Do I need an account?</summary><p>No account is required to share or receive through the website. For terminal use, there is also a <a href="/cli">command-line client</a>.</p></details>
        <details><summary>How large can an upload be?</summary><p>The hosted service accepts an encrypted upload of up to 512 MiB, including encryption overhead. Choose an original file slightly below that limit. Text notes have a 10 MiB limit. Available server memory and your browser can impose further limits.</p></details>
        <details><summary>Does reading a note delete it?</summary><p>No. Notes remain available until expiry, explicit deletion, or a server restart. If receiver deletion is enabled, the recipient can delete the share after reading it.</p></details>
        <details><summary>Can a lost password be recovered?</summary><p>Reiven has no password recovery. Ask the sender for the password or another copy. Keep a QR link private: it contains the key needed to decrypt that share.</p></details>
      </div></section>`,
  },
  '/encrypted-file-sharing': {
    title: 'Encrypted File Sharing Without an Account — Reiven.io',
    description: 'Send password-protected files with Reiven.io. Browser encryption, temporary RAM storage, access codes, and optional QR sharing. No account required.',
    heading: 'Encrypted file sharing without an account',
    intro: 'Send a document or file through a link while keeping payload encryption on your device. Reiven receives the encrypted bytes; the recipient decrypts them in their browser.',
    body: `${actions()}
      <section class="content-section"><h2>Send a password-protected file</h2><ol class="steps"><li>Open the sharing workspace and select or drop a file.</li><li>Choose a strong password. The Standard profile is the default; Paranoid increases password-processing cost and can be slower on small devices.</li><li>Select Encrypt &amp; Upload. Wait for the upload-complete screen before closing the tab.</li><li>Send the download link or 8-digit access code. Send the password through a separate channel where practical.</li></ol><p>The recipient enters the password in their browser. Reiven does not recover forgotten passwords, so retain the original until the recipient has received it.</p></section>
      <section class="content-section"><h2>Links, access codes, and QR Mode</h2><p>A download link opens the share directly. An access code can be entered on the <a href="/receive">receive page</a>; it identifies the share and is not the decryption password.</p><p>For convenient device-to-device sharing, QR Mode generates a random 256-bit key and includes it in a QR link. Scanning that link starts browser decryption and download. Anyone with the complete link can decrypt it. <a href="/guides/encrypted-qr-sharing">Learn how QR sharing works</a>.</p></section>
      <section class="content-section"><h2>Size, expiry, and deletion</h2><p>The hosted encrypted-upload limit is 512 MiB including encryption overhead. Use an original file below this limit. Upload capacity also depends on free server memory; large downloads need enough memory on the recipient's device.</p><p>Shares expire 24 hours after upload initialization. The sender receives a deletion link. Receiver deletion is enabled by default and can be switched off before upload. Downloading does not itself delete a file.</p><p>Encrypted uploads live in server memory and can disappear earlier after a restart or crash. This is temporary transfer, not long-term storage. <a href="/guides/memory-only-storage">Understand memory-only storage</a>.</p></section>
      <section class="content-section"><h2>What encryption covers</h2><p>The file's contents are encrypted before upload using AES-256-GCM. The bundled clients encrypt original filenames and send the placeholder encrypted.bin. Other operational metadata remains visible to the service; custom clients may expose their chosen upload name. Use the <a href="/security">security page</a> for the full model, or follow our <a href="/guides/share-password-protected-files">step-by-step sharing guide</a>.</p><p>Only sharing a short message? <a href="/encrypted-notes">Create an encrypted note instead</a>.</p></section>`,
  },
  '/encrypted-notes': {
    title: 'Share Encrypted Private Notes — Reiven.io',
    description: 'Write and share an encrypted private note without an account. Encrypt text in your browser, share a password-protected link, and delete it after use.',
    heading: 'Share a private note with browser encryption',
    intro: 'Use Reiven to send a short private message, setup instruction, or confidential handover. The note is encrypted on your device before it reaches the server.',
    body: `${actions('Write a private note', '/share#note')}
      <section class="content-section"><h2>From text to an encrypted link</h2><ol class="steps"><li>Open note sharing and write your text in the payload box.</li><li>Choose a strong password or enable QR Mode for a random browser-generated key.</li><li>Encrypt and upload, then send the resulting link or access code.</li><li>The recipient opens the link, decrypts locally, and can read the note or save it as a text file.</li></ol><p>For a manually chosen password, use a different communication channel from the link when practical. The service cannot recover a lost password.</p></section>
      <section class="content-section"><h2>Temporary notes with explicit deletion</h2><p>Notes expire after 24 hours and can be removed earlier with the deletion link. Receiver deletion is enabled by default. A recipient can delete the server copy once it is no longer needed.</p><p>Notes are not automatically destroyed on first reading. A person who can read a note can also copy or save it, and server deletion cannot remove copies they already hold.</p><p>The encrypted note is held in RAM. A server restart or crash can make it unavailable before the scheduled expiry. Keep any information you need in your own records.</p></section>
      <section class="content-section"><h2>Limits and privacy</h2><p>A note can contain up to 10 MiB of encoded text; short messages are easier to use on mobile devices. It is stored as an encrypted note payload with the placeholder upload name <code>encrypted.bin</code>; the encrypted original name is <code>note.txt</code>.</p><p>Encryption protects the content, not a compromised browser or a link shared with the wrong person. QR links contain their own decryption key and should be treated as the secret itself.</p><p>Read <a href="/security">the security model</a>, <a href="/privacy">the privacy information</a>, or use <a href="/encrypted-file-sharing">file sharing</a> for an existing document.</p></section>`,
  },
  '/security': {
    title: 'Security & Encryption Model — Reiven.io',
    description: 'How Reiven encrypts notes and files: AES-256-GCM, Argon2id, ML-KEM-768 key wrapping, temporary memory storage, and the limits of the security model.',
    heading: 'How Reiven protects shared content',
    intro: 'Reiven is designed to encrypt payload contents before upload and decrypt them on the recipient’s device. This page describes the implementation and its boundaries.',
    body: `<section class="content-section"><h2>Encryption on your device</h2><p>The browser generates a random 256-bit data encryption key and encrypts payloads with AES-256-GCM. Large files are encrypted in chunks with separate nonces. Passwords are processed with Argon2id to derive a seed for a deterministic ML-KEM-768 keypair. HKDF-SHA-256 derives an AES-GCM wrapping key from the ML-KEM shared secret. Version 6 authenticates envelope parameters, metadata, total length, chunk positions and final-chunk status. Receivers reject incomplete or altered streams and older v4/v5 formats; ask the sender to recreate legacy shares.</p><p>The Standard profile uses Argon2id with 4 iterations, 64 MiB memory, and parallelism 1. Paranoid uses 6 iterations and 128 MiB. Both use PIM 100 as an input parameter, not an iteration multiplier. New passwords must contain at least 32 characters; use a password manager rather than predictable text. The <a href="/cli">CLI</a> shares the encryption configuration with the browser.</p><p>ML-KEM-768 supplies a post-quantum key-wrapping layer. This does not make weak passwords safe: someone holding ciphertext can attempt offline password guesses. Choose a long, randomly generated password or QR Mode's random key.</p></section>
      <section class="content-section"><h2>What the server receives</h2><p>Normal application requests send encrypted payloads rather than plaintext contents or decryption passwords. The server also receives operational metadata, including the upload filename, encrypted size, file identifier, expiry, deletion token, receiver-deletion setting, note flag, access-code hash, and download count. Connections reveal network information such as IP addresses.</p><p>Bundled clients encrypt the original filename and submit encrypted.bin as the upload name. Custom clients can reveal their chosen upload names. Temporary, process-salted network hashes enforce abuse quotas; shared networks share those quotas. “Zero knowledge” here describes the intended payload-encryption design; it does not mean the service sees no metadata. See <a href="/privacy">privacy and logging details</a>.</p></section>
      <section class="content-section"><h2>Temporary storage in memory</h2><p>The application holds ciphertext and share metadata in process memory and does not write them to application-managed disk files. The hosted service disables swap use for the process and core dumps. Operational logs are separate and can be stored on disk.</p><p>Expiration and deletion remove the server's live records and buffers. Restarting the service removes all shares. This is not a promise of forensic memory erasure, and it cannot revoke a recipient's saved copy. <a href="/guides/memory-only-storage">Read the storage guide</a>.</p></section>
      <section class="content-section"><h2>QR links and access</h2><p>QR Mode puts its randomly generated key in the URL fragment, after <code>#</code>. Fragments are not sent as part of ordinary HTTP requests, but the full link remains a secret. It can be exposed in browser history, copied messages, screenshots, or software on a recipient's device.</p><p>A file link or access code identifies a share; the password or QR key decrypts it. A deletion link grants deletion access. When receiver deletion is enabled, anyone with the share link or code can obtain that capability without the password. Share these according to what you want the other person to be able to do.</p></section>
      <section class="content-section"><h2>Browser and server trust</h2><p>Browser encryption still depends on the JavaScript served by the website and on your device. A compromised server could deliver altered code; a compromised browser can read what you type or decrypt. The sharing, receiving, download, and deletion pages do not load Google Analytics or other third-party scripts. Public information pages use Google Analytics.</p><p>The implementation is available in the <a href="${sourceUrl}">Reiven source repository</a>. This description is not an independent security certification. For support, use the project's public issue tracker without posting passwords, private links, or confidential content.</p></section>`,
  },
  '/privacy': {
    title: 'Privacy, Metadata & Logging — Reiven.io',
    description: 'Understand Reiven’s temporary encrypted storage, visible metadata, operational logs, browser storage, and Google Analytics on public information pages.',
    heading: 'Privacy, metadata, and logging',
    intro: 'No account is needed to use Reiven. Payload contents are encrypted on your device, but operating a sharing service still involves metadata and network information.',
    body: `<section class="content-section"><h2>Uploads and share metadata</h2><p>The application receives encrypted content and metadata needed to deliver a share: its filename, encrypted size, identifier, expiry, deletion token, receiver-deletion setting, note flag, access-code hash, and download count. Bundled clients send the placeholder encrypted.bin and encrypt original filenames; custom API clients can expose upload names. Process-salted network hashes for storage/rate quotas are retained only in RAM. Passwords and decryption keys are not submitted by the normal upload or download flow.</p><p>Encrypted payloads and their live share records are held in server process memory. Shares expire after 24 hours from upload initialization, can be deleted earlier, and disappear if the service restarts. Upload sessions expire after five minutes of inactivity or 30 minutes overall; cleanup runs periodically. Cleanup runs periodically; deletion removes the live record but is not a guarantee of immediate forensic erasure from RAM.</p><p>These settings describe the hosted service. A self-hosted deployment can configure different limits. Read <a href="/guides/memory-only-storage">the storage guide</a>.</p></section>
      <section class="content-section"><h2>Operational and network logs</h2><p>The server and its hosting infrastructure receive client IP addresses to handle connections. Routine successful web requests and successful upload completions are not currently written to a dedicated access log. Application errors, reverse-proxy errors, and operating-system events may be logged.</p><p>Application error records contain method/status, not request URLs. The supplied reverse-proxy configuration removes request and URI fields from error records. Operating-system and hosting logs may still contain network metadata. They are separate from the RAM-only upload store and may persist on disk across restarts. There is currently no application-enforced fixed retention period for these operational logs. Reiven therefore does not claim to keep “no logs”.</p></section>
      <section class="content-section"><h2>Analytics on public information pages</h2><p>The homepage, product information, documentation, and guides use Google Analytics to understand visits. Google receives network information and may use analytics cookies or browser identifiers. The local initializer supplies the canonical public page URL and an empty referrer, disables Google Signals and advertising-personalization signals, and does not intentionally report share identifiers or content.</p><p>Google Analytics is not loaded on the sharing workspace, receive-by-code page, private download pages, or deletion pages. It is also skipped on public-page requests containing a query or fragment. No custom upload-completion events are sent. Browser privacy tools can block analytics requests.</p><p>Read <a href="https://policies.google.com/privacy">Google's privacy policy</a> for how Google handles its services. The remote analytics script remains third-party code on the public pages where it loads.</p></section>
      <section class="content-section"><h2>Information on your device</h2><p>The sharing tool caches an Argon2 performance estimate in local storage so later visits can prepare encryption more quickly. This cache does not contain a password or payload. Your browser may retain downloaded files, history, QR links, or data copied to the clipboard independently of Reiven's server.</p><p>Clear site data through your browser to remove local storage and cookies. Anyone who receives and decrypts content may keep a copy; deleting the server share cannot erase those copies.</p></section>
      <section class="content-section"><h2>Questions and project information</h2><p>Reiven is maintained through the <a href="${sourceUrl}">Reiven.io project repository</a>. You can raise general privacy questions in its <a href="${sourceUrl}/issues">public issue tracker</a>; do not include private links, passwords, IP addresses, or confidential files.</p><p>Read the <a href="/security">security model</a> for encryption details and limitations.</p></section>`,
  },
  '/about': {
    title: 'About Reiven.io — Private File & Note Sharing',
    description: 'Reiven.io is a browser-first encrypted file and note sharing project with no accounts, temporary memory storage, QR links, and a command-line client.',
    heading: 'About Reiven.io',
    intro: 'Reiven.io is a browser-first project for sending encrypted files and private notes without creating an account. It is built for temporary handovers rather than a permanent online archive.',
    body: `<section class="content-section"><h2>A small tool for a specific job</h2><p>Sometimes you need to send one document, hand over a private instruction, or move a file to another device. Reiven lets you encrypt that content locally, upload the encrypted bytes, and share a link or access code.</p><p>The server uses process memory for the encrypted upload and its live metadata. A share can expire, be deleted, or disappear when the server restarts. Keep an original copy until the handover is complete.</p></section>
      <section class="content-section"><h2>The Reiven.io project</h2><p>The project is maintained in the <a href="${sourceUrl}">reivenio/reiven-io repository on GitHub</a>. The repository contains the browser application, direct server, encryption configuration, and command-line client, along with installation and deployment instructions.</p><p>For bugs, feature suggestions, and general questions, use <a href="${sourceUrl}/issues">the project's issue tracker</a>. It is public: include a minimal example and omit actual secrets and private links.</p></section>
      <section class="content-section"><h2>Choose the right sharing flow</h2><ul><li><a href="/encrypted-file-sharing">Encrypted files</a> for an existing document or other file.</li><li><a href="/encrypted-notes">Private notes</a> for text you want to write directly in the browser.</li><li><a href="/cli">The CLI</a> for terminal-based uploads and downloads.</li></ul><p>Read <a href="/security">how encryption works</a> and <a href="/privacy">what information is processed</a> before deciding whether the service fits your needs.</p></section>`,
  },
  '/cli': {
    title: 'Reiven CLI — Encrypted File Transfer from Your Terminal',
    description: 'Install the Reiven command-line client from source. Encrypt and upload files locally, or download and decrypt a share using its access code or file ID.',
    heading: 'Encrypted file transfer from your terminal',
    intro: 'The Reiven CLI encrypts files before upload and decrypts downloaded shares on your computer. It uses the shared encryption configuration from the Reiven project.',
    body: `<section class="content-section"><h2>Install from source</h2><p>Install Git, a currently supported Node.js release, and npm first. Clone the whole repository so the CLI can load its shared configuration. The CLI is installed locally from source, not from a published Reiven npm package.</p><pre class="guide-code"><code>git clone https://github.com/reivenio/reiven-io.git
cd reiven-io/reiven-cli
npm install
npm link
reiven --help</code></pre></section>
      <section class="content-section"><h2>Upload an encrypted file</h2><pre class="guide-code"><code>reiven put ./report.pdf</code></pre><p>The client prompts for a password and confirmation, encrypts locally, uploads the encrypted payload, and prints an access code, download link, deletion link, and expiry. Keep the password separate from the link when sharing.</p></section>
      <section class="content-section"><h2>Download and decrypt</h2><pre class="guide-code"><code>reiven get 12-34-56-78 --out ./downloads</code></pre><p>Replace the example code with the sender's real access code. A file ID is also accepted. The client prompts for a password, checks it against the encrypted header, and decrypts the download into the selected output directory.</p><p>For another Reiven deployment, pass <code>--base https://your-reiven-host.example</code> or set <code>REIVEN_BASE_URL</code>. The default service is <code>https://reiven.io</code>.</p></section>
      <section class="content-section"><h2>The same limits and expiry apply</h2><p>The hosted service accepts encrypted uploads up to 512 MiB including overhead. Shares expire after 24 hours and may disappear sooner on a server restart. The CLI does not provide a backup or password recovery.</p><p>Read the <a href="${sourceUrl}/tree/main/reiven-cli">CLI documentation and source</a>, the <a href="/security">security model</a>, or the <a href="/guides/share-password-protected-files">file-sharing guide</a>.</p></section>`,
  },
  '/guides': {
    title: 'Encrypted Sharing Guides — Reiven.io',
    description: 'Practical guides to password-protected file sharing, temporary server-memory storage, and encrypted QR links with Reiven.io.',
    heading: 'Practical guides to encrypted sharing',
    intro: 'Understand the complete handover: what to send, what to keep private, and what happens to a share after upload.',
    body: `<section class="content-section"><div class="feature-grid">
      <article class="feature-card"><h2><a href="/guides/share-password-protected-files">Share a password-protected file</a></h2><p>Prepare the file, choose a password, send the link, and help the recipient open it.</p></article>
      <article class="feature-card"><h2><a href="/guides/memory-only-storage">What memory-only storage means</a></h2><p>How temporary RAM storage affects availability, deletion, and the copies you should keep.</p></article>
      <article class="feature-card"><h2><a href="/guides/encrypted-qr-sharing">How encrypted QR links work</a></h2><p>Use a randomly generated key to transfer a share between devices, and understand who can access it.</p></article>
      </div></section><section class="content-section"><h2>Choose your tool</h2><p>Use <a href="/encrypted-file-sharing">file sharing</a> for documents, <a href="/encrypted-notes">encrypted notes</a> for text, or the <a href="/cli">CLI</a> for your terminal. The <a href="/security">security model</a> and <a href="/privacy">privacy page</a> describe what these tools do and what they do not protect.</p></section>`,
  },
  '/guides/share-password-protected-files': {
    title: 'How to Share a Password-Protected File — Reiven.io',
    description: 'A practical guide to sharing an encrypted file without an account: choose a password, send the link, help the recipient, and delete the temporary share.',
    heading: 'How to share a password-protected file without an account',
    intro: 'For a one-off handover, a browser-encrypted share can avoid creating another account. Here is the complete Reiven workflow, from preparing a file to removing the server copy.',
    body: `<section class="content-section"><h2>1. Prepare the file and password</h2><p>Keep your original file. Reiven's hosted limit is 512 MiB of encrypted data including overhead, so leave room below that limit. Bundled clients encrypt the original filename and upload with the placeholder encrypted.bin; custom clients may expose their chosen upload name.</p><p>Use a password manager to generate a long random password rather than a predictable phrase or a reused account password. Encryption cannot make a weak password resistant to offline guessing.</p></section>
      <section class="content-section"><h2>2. Encrypt and upload</h2><p>Open <a href="/share">the sharing workspace</a>, choose the file, and enter the password. Standard is the default encryption profile; Paranoid raises the Argon2 cost and may take longer.</p><p>Leave receiver deletion enabled if you want the recipient to remove the server copy after receiving it. Select Encrypt &amp; Upload and wait for the completion screen.</p></section>
      <section class="content-section"><h2>3. Send the link and password</h2><p>Send the download link, or give the recipient the 8-digit code to enter at <a href="/receive">the receive page</a>. An access code identifies a share; it does not replace the password.</p><p>Where practical, send the password through a different channel from the link. Someone who gains access to both can decrypt the file. Keep the sender's deletion link separate unless you intend to give someone deletion access.</p></section>
      <section class="content-section"><h2>4. Confirm receipt and delete when finished</h2><p>The recipient opens the share, enters the password, and saves the browser-decrypted file. If they cannot open it, check the code, password, and expiry before re-uploading.</p><p>Uploads expire after 24 hours and may disappear earlier if the service restarts. After receipt, either use your deletion link or let the recipient delete it if enabled. This removes the live server copy; it cannot erase files already saved elsewhere.</p><p>For device-to-device convenience, read <a href="/guides/encrypted-qr-sharing">the QR sharing guide</a>. For more on availability, read <a href="/guides/memory-only-storage">what memory-only storage means</a>.</p></section>${actions()}`,
  },
  '/guides/memory-only-storage': {
    title: 'What Memory-Only File Storage Means — Reiven.io',
    description: 'Reiven keeps encrypted uploads in server RAM. Learn what that means for expiry, deletion, restarts, logs, and the original copies you should keep.',
    heading: 'What memory-only storage means for your files',
    intro: 'Reiven uses the server’s process memory as a temporary place to hold encrypted uploads. This has a direct effect on how long a link can remain available.',
    body: `<section class="content-section"><h2>Where an upload goes</h2><p>Your browser encrypts the content before uploading. The server holds the resulting encrypted byte buffers in RAM along with the information needed to deliver the share. The application does not save those payloads to application-managed files or a disk database.</p><p>For the hosted service, process swapping and core dumps are disabled. These host settings matter because an operating system can otherwise persist memory outside the application's own storage logic.</p></section>
      <section class="content-section"><h2>Why a share may disappear early</h2><p>Shares have a 24-hour expiry measured from upload initialization. That is an upper availability window, not a durability promise. A service restart, deployment, crash, or machine reboot clears all stored shares immediately.</p><p>If you upload a file in the morning and the service restarts in the afternoon, the link will stop working even though its scheduled expiry is still in the future. You will need to create a new share.</p></section>
      <section class="content-section"><h2>Deletion and copies</h2><p>Using a deletion link removes the live metadata record and encrypted buffers from the application's store. Memory is subsequently managed by the runtime and operating system; logical deletion is not the same as certified physical memory erasure.</p><p>Deleting a share cannot remove the sender's original, a recipient's saved download, clipboard contents, or screenshots. Memory-only server storage also does not mean there are no operational logs. The <a href="/privacy">privacy page</a> describes those separately.</p></section>
      <section class="content-section"><h2>When this model is useful</h2><p>Use Reiven for an active handover where you can confirm receipt, such as sending a document to a colleague or moving a file to another device. Keep your original until the recipient has saved their copy.</p><p>Use a suitable backup or durable storage system for anything you need to recover later. Reiven provides temporary <a href="/encrypted-file-sharing">file sharing</a> and <a href="/encrypted-notes">private notes</a>, not archival storage.</p></section>`,
  },
  '/guides/encrypted-qr-sharing': {
    title: 'How Encrypted QR Sharing Links Work — Reiven.io',
    description: 'Reiven QR Mode generates a random key in your browser and includes it in a QR link. Learn how to share, scan, decrypt, and handle the link privately.',
    heading: 'How encrypted QR sharing links work',
    intro: 'QR Mode packages the share location and a randomly generated decryption key into one link. It is useful when you want to open a share on another device without typing a password.',
    body: `<section class="content-section"><h2>Create and scan a QR share</h2><ol class="steps"><li>Open <a href="/share">file sharing</a> or <a href="/share#note">note sharing</a> and choose your content.</li><li>Enable QR Mode. Reiven generates a random 256-bit key in the browser instead of asking you to choose a password.</li><li>Encrypt and upload. Keep the resulting QR code visible only to the intended recipient.</li><li>Scan the code on the receiving device. The browser uses the included key to decrypt; a file download starts, or a note appears in the page.</li></ol><p>Your device may require you to approve opening the link or saving a download. If scanning is unavailable, the complete QR link can be copied instead.</p></section>
      <section class="content-section"><h2>Why the link is itself a secret</h2><p>The key is stored in the URL fragment, the part after <code>#</code>. Browsers do not include this fragment in ordinary HTTP requests to the server. The download page reads it locally.</p><p>That separation does not make the full link safe to publish. Anyone who obtains it can decrypt while the share exists. Browser history, copied messages, screenshots, and software that reads links can expose it. Avoid posting QR links to public channels or showing the code on a public screen.</p></section>
      <section class="content-section"><h2>Choose QR Mode or a separate password</h2><p>QR Mode is convenient for a nearby device or an intended recipient you can give the full link to. Manual password mode lets you send the link and password separately. Both rely on the recipient's device and browser being trustworthy.</p><p>Expiration and deletion are the same in either mode: up to 24 hours, with earlier loss possible on a server restart. Receiver deletion is enabled by default. Learn more about <a href="/guides/memory-only-storage">the storage model</a> and <a href="/security">encryption boundaries</a>.</p></section>${actions('Create a QR share')}`,
  },
};

const navLinks = [
  ['/encrypted-file-sharing', 'Files'], ['/encrypted-notes', 'Notes'],
  ['/security', 'Security'], ['/guides', 'Guides'], ['/cli', 'CLI'],
];
const footerLinks = [...navLinks, ['/privacy', 'Privacy'], ['/about', 'About'], [sourceUrl, 'Source code']];
const renderLinks = (links, current) => links.map(([href, label]) => `<a href="${href}"${href === current ? ' aria-current="page"' : ''}>${label}</a>`).join('');

for (const pathname of PUBLIC_PAGE_PATHS) {
  const page = pages[pathname];
  if (!page) throw new Error(`Missing page content: ${pathname}`);
  const canonical = `${SITE_ORIGIN}${pathname}`;
  const filePath = path.join(publicDir, pathname === '/' ? 'index.html' : `${pathname.slice(1)}.html`);
  const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${escapeHtml(page.title)}</title>
    <meta name="description" content="${escapeHtml(page.description)}" />
    <meta name="robots" content="index, follow" />
    <link rel="canonical" href="${canonical}" />
    <meta property="og:type" content="website" />
    <meta property="og:site_name" content="Reiven.io" />
    <meta property="og:url" content="${canonical}" />
    <meta property="og:title" content="${escapeHtml(page.title)}" />
    <meta property="og:description" content="${escapeHtml(page.description)}" />
    <meta property="og:image" content="${SITE_ORIGIN}/social-preview.png" />
    <meta property="og:image:width" content="1200" />
    <meta property="og:image:height" content="630" />
    <meta property="og:image:alt" content="Reiven.io — encrypted file and note sharing" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="${escapeHtml(page.title)}" />
    <meta name="twitter:description" content="${escapeHtml(page.description)}" />
    <meta name="twitter:image" content="${SITE_ORIGIN}/social-preview.png" />
    <meta name="theme-color" content="#080c0e" />
    <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
    <link rel="stylesheet" href="/styles.css" />
    ${pathname === '/' ? `<script type="application/ld+json">${SITE_SCHEMA}</script>\n    <script src="/navigation.js" defer></script>\n    ` : ''}<script src="/analytics.js" defer></script>
  </head>
  <body class="public-page">
    <a class="skip-link" href="#content">Skip to content</a>
    <div class="app-shell">
      <header class="site-header"><a class="brand-mark" href="/">reiven.io</a><nav class="site-nav" aria-label="Primary">${renderLinks(navLinks, pathname)}<a class="nav-action" href="/share">Share</a></nav></header>
      <main id="content" class="content-page${pathname === '/' ? ' landing-page' : ''}">
        ${pathname !== '/' ? '<a class="back-link" href="/">← Reiven.io</a>\n        ' : ''}<header class="content-intro">${page.eyebrow ? `<p class="eyebrow">${page.eyebrow}</p>` : ''}<h1>${escapeHtml(page.heading)}</h1><p class="lead">${escapeHtml(page.intro)}</p></header>
        ${page.body}
      </main>
      <footer class="footer-note"><p>Encrypted in your browser · Temporary server-memory storage · No accounts</p><nav class="footer-links" aria-label="Project">${renderLinks(footerLinks, pathname)}</nav></footer>
    </div>
  </body>
</html>
`;
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, html);
}

await writeFile(path.join(publicDir, 'sitemap.xml'), `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${PUBLIC_PAGE_PATHS.map((pathname) => `  <url><loc>${SITE_ORIGIN}${pathname}</loc><lastmod>${updated}</lastmod></url>`).join('\n')}
</urlset>
`);
console.log(`Built ${PUBLIC_PAGE_PATHS.length} public pages and sitemap.`);
