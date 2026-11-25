# provemewrong

This project is a tool to perform a set of tests and record metrics in data files.
It runs as a daemon.
Specifically, it will:

- perform a TCP connection towards one or more endpoints
  for each connection success/attempt it will record:
- Test start time
- Hostname
- DNS resolution taken (ms)
- TCP connection taken (ms) (excludes DNS time)
- TLS handshake time.
- Close connection taken (ms).
- Total time
- Additional data as required to troubleshoot connectivity and performance problems (random latency etc)

# Technical details

- Language: Go
  - Single binary. Easy to deploy. This is a key consideration.
  - No config file, or config optional. Everything should be parameters. Prefer a nice easy library for that (Kong?)
- We _always_ write tests.
- Use Arrow if it makes sense for in-memory data. The idea is we want to be able to emit CSV/PArquet etc.
- Manage RAM. This will run in production servers, flush to disk as approriate.
- never handle GIT (commits etc). This is the developers job to review and commit
