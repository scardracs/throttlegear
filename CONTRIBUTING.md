# Contributing to ThrottleGear

Thank you for your interest in contributing to ThrottleGear! This project aims to maintain high-quality, secure, and maintainable tooling for managing ASUS ThrottleGear XML configurations and generating corresponding quirk patches for the Linux kernel.

To maintain a clean and reviewable history, please follow the guidelines below when proposing changes.

---

## Core Principles

As in the Linux Kernel, we follow the principles of correctness and simplicity and prefer boring code over clever code.

1. **Correctness** is prioritized over speed.
2. **Simplicity** is preferred over complex, clever abstractions.
3. **Preserve backwards compatibility** for existing CLI usage and XML formats.
4. **Minimize scope**: Solve exactly the reported issue, avoiding unrelated cleanups or feature creep in the same patch.
5. **No direct master commits**: Never commit directly to the `master` branch. Always use short-lived feature branches.
6. **AI Usage**: You are free to use any AI/LLM of your liking but you are ultimately the one pushing it. You **must** always know what yuour code do.
7. **AI Report**: If you are going to use AI report it using the flag Assisted-by: IDE:AI-model.

---

## Development Workflow

1. **Create a Feature Branch**:
   Check out a new branch from `master` before writing any code:
   ```bash
   git checkout master
   git pull origin master
   git checkout -b feat/your-feature-name
   ```

2. **Implement and Test**:
   - Write clean, idiomatic Rust code conforming to standard `rustfmt` guidelines.
   - Ensure safety when working with FFI bindings to system dynamic libraries.
   - Refactor helper routines to raise standard Rust error types (e.g. `Result` / `Err`) rather than panicking or calling `std::process::exit(1)` directly.
   - Verify that your changes compile and execute correctly using your XML file.

3. **Format and Document Your Patch**:
   Format your patch as a unified diff with clear sections:
   - **Problem Analysis**: Description of the issue and root cause.
   - **Proposed Solution**: Design rationale and alternatives considered.
   - **Patch**: Unified diff of the changes.
   - **Validation**: Describe build verification and test results.
   - **Risk Assessment**: Classify the change (Low, Medium, High Risk) with justification.

---

## Commit Message Guidelines

Commit messages must follow the format:

```
<Detailed explanation of what was wrong, why it occurred,
and how this change resolves the issue. Mention any potential 
side effects or design tradeoffs.>

Signed-off-by: Your Real Name <your.email@example.com>
```

### Commit Guidelines
- Use the **imperative mood** (e.g., "fix array limits", not "fixed array limits" or "fixes array limits").
- Explain the **rationale** for the change, not just what lines were altered.
- Include both required trailers:
  - `Signed-off-by: Your Real Name <your.email@example.com>` (matching git author credentials).

---

## Testing Requirements

Before considering your changes complete, verify:
- Code parsing succeeds with all flags combinations (e.g., `-c`, `-P`, `-n`, `-g`).
- XML decryption/encryption roundtrips match base64 formats.
- Rust unit tests pass successfully (`cargo test`).
- No untracked cache directories or debugging files (like `target/` or temporary XMLs) are left in the repository.
