# tmux-fuzzer-advanced

Follow this to start the fuzzer

---

## Prerequisites

* Docker
* Terminal
* Sufficient disk space for `fuzz_output` and build artifacts

---

## Make scripts executable

Before running the scripts, give them execute permission:

```sh
chmod +x build_all_fuzzers.sh run_parallel_fuzz.sh
```

---

## Build & run in Docker

This is the recommended, reproducible way to build and run the fuzzers:

1. Build the Docker image:

```sh
docker build -f Dockerfile.fuzz -t tmux-fuzzer-advanced .
```

For arm:
```sh
docker buildx build --platform linux/amd64 -f Dockerfile.fuzz -t tmux-fuzzer-advanced .
```

2. Run a container, mount a local `fuzz_output` directory and start an interactive shell inside the container:

```sh
mkdir -p fuzz_output
docker run -it --rm -v $(pwd)/fuzz_output:/tmux/fuzz_output tmux-fuzzer-advanced /bin/bash
```

For arm:
```sh
mkdir -p fuzz_output
docker run --platform linux/amd64 -it --rm -v $(pwd)/fuzz_output:/tmux/fuzz_output tmux-fuzzer-advanced /bin/bash
```


3. Inside the container, build and run the fuzzers:

```sh
./build_all_fuzzers.sh
./run_parallel_fuzz.sh
```

When the container exits, `fuzz_output/` on your host will contain the results.
