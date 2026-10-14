# Contributing

Thanks for helping! A few rules keep Uniwatch reliable:

1. **Real formats only.** Parsers and API clients are written against real device output. Add an *anonymised* sample to
   `samples/` (no client names, people, public IPs of clients, MACs or serials) and a test that reads it.
2. **Tests first.** `docker compose --profile test run --rm tests` must pass (PostgreSQL + TimescaleDB in Docker).
3. **Read-only towards devices.** Uniwatch never changes a firewall, switch or console unless a feature is explicitly
   designed and reviewed for it.
4. **Tenant isolation.** Every client-owned table carries `client_id` and gets row-level security for the web role;
   add it to the tests in `tests/test_tenancy.py`.
5. By contributing you agree that your contribution is licensed under the AGPL-3.0, and that the copyright holder (ARE19) may
   also use it in separately licensed add-ons such as report packs.
