# Contributing to AegisDNS

We welcome contributions, bug reports, and pull requests!

## How to Contribute
1. **Fork the Repository** on GitHub.
2. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/awesome-feature
   ```
3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Run the Test Suite**:
   ```bash
   python test_aegis.py
   ```
5. **Commit your Changes**:
   ```bash
   git commit -m "feat: Add new upstream DNS provider"
   ```
6. **Push to your Fork and Open a Pull Request**.

## Code Guidelines
- Keep asynchronous methods non-blocking.
- Maintain typing annotations.
- Include unit/integration tests in `test_aegis.py` for new core features.
