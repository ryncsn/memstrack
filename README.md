# memstrack
A memory allocation trace, like a hot spot analyzer for memory allocation, it can help analyze overall memory usage, peak memory usage, kernel module memory usage. Userspace memory trace is planned and not yet implemented.

# Quick start
TO use this tool, you can just clone the repo and compile it.

```sh
# First Make sure you have gcc git make ncurses-devel installed
# Then clone it
git clone https://github.com/ryncsn/memstrack.git

# Build it
cd memstrack
make

# Run it, a TUI will show up:
./memstrack

# Print help info:
./memstrack --help

# Another Example, run memtrack without TUI and generate report to file "report.result"
./memstrack --notui --report task_top --output report.result
```

# Install
```sh
make
make install
```

# Install and use as dracut module
memstrack could be used to track the memory usage during boot progress, and it's simple to setup.
First, install it as a dracut module:
```sh
make dracut-module-install
```

Then append "rd.memstrack=<level>", replace <level> accordingly by how verbose you want memstrack be.
With rd.memstrack=1, only simple summary will be printed to console during boot.
With rd.memstrack=2, summary will be printed to console, and also prints the top stacks which consumes most memories.
With rd.memstrack=3, memstrack will print everything, use with caution as this will likely to flood your console.

# Note
For for Linux kernel using ORC unwinder and have version below 5.2, it have a bug with tracepoints that unable to generate stack trace properly using perf, so you might empty stack trace data using perf backend. To avoid such problem, please update your kernel to latest version, or use ftrace backend as a workaround (with performance downgrade).
