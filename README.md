# Memstrack
A memory allocation trace, like a hot spot analyzer for memory allocation, it can help analyze overall memory usage, peak memory usage, kernel module memory usage. Userspace memory trace is planned and not yet implemented.

# Usage
It have a TUI showing current memory allocation status:
![alt text](https://ryncsn.github.io/latest-memstrack-screenshot.png "Screenshot of TUI")

And can generate report of memory allocation and usage of a long period, example report:
```sh
======== Report format module_summary: ========
Module squashfs using 26.8MB (6868 pages), peak allocation 35.1MB (8976 pages)
Module virtio_console using 1.5MB (377 pages), peak allocation 1.5MB (377 pages)
Module overlay using 1.5MB (372 pages), peak allocation 2.2MB (568 pages)
Module virtio_blk using 0.9MB (241 pages), peak allocation 0.9MB (241 pages)
Module virtio_net using 0.5MB (129 pages), peak allocation 0.5MB (129 pages)
Module sunrpc using 0.1MB (15 pages), peak allocation 0.1MB (15 pages)
Module qemu_fw_cfg using 0.0MB (4 pages), peak allocation 0.0MB (4 pages)
======== Report format module_summary END ========
======== Report format module_top: ========
Top stack usage of module squashfs:
  (null) Pages: 6868 (peak: 8976)
    (null) Pages: 6868 (peak: 8976)
      async_page_fault (0xffffffff81c0137e) Pages: 4643 (peak: 6264)
        do_page_fault (0xffffffff81075861) Pages: 4643 (peak: 6264)
          do_user_addr_fault (0xffffffff81075109) Pages: 4643 (peak: 6264)
            handle_mm_fault (0xffffffff81298074) Pages: 4643 (peak: 6264)
              __handle_mm_fault (0xffffffff81297ac8) Pages: 3770 (peak: 5391)
                __do_fault (0xffffffff8128f3b6) Pages: 3770 (peak: 5391)
                  filemap_fault (0xffffffff81255dce) Pages: 3674 (peak: 5234)
                    __do_page_cache_readahead (0xffffffff812611fa) Pages: 3151 (peak: 4522)
                      read_pages (0xffffffff81260fb2) Pages: 3151 (peak: 4522)
                        squashfs_readpage squashfs (0xffffffffc0025064) Pages: 2973 (peak: 4342)
                          squashfs_readpage_block squashfs (0xffffffffc0027289) Pages: 2132 (peak: 3185)
                            squashfs_copy_cache squashfs (0xffffffffc0024a99) Pages: 2132 (peak: 3185)
                              pagecache_get_page (0xffffffff81254b33) Pages: 2132 (peak: 3185)
                                __alloc_pages_nodemask (0xffffffff812b6443) Pages: 2132 (peak: 3185)
                                  __alloc_pages_nodemask (0xffffffff812b6443) Pages: 4264 (peak: 6370)
Top stack usage of module virtio_console:
  (null) Pages: 377 (peak: 377)
    (null) Pages: 266 (peak: 266)
      ret_from_fork (0xffffffff81c00215) Pages: 266 (peak: 266)
        kthread (0xffffffff81106c59) Pages: 266 (peak: 266)
          worker_thread (0xffffffff811008f0) Pages: 266 (peak: 266)
            process_one_work (0xffffffff811006f5) Pages: 266 (peak: 266)
              control_work_handler virtio_console (0xffffffffc0159496) Pages: 265 (peak: 265)
                add_port virtio_console (0xffffffffc0159198) Pages: 254 (peak: 254)
                  fill_queue virtio_console (0xffffffffc0158faa) Pages: 254 (peak: 254)
                  ... snip ...
```

# Quick start
To use this tool, you can just clone the repo and compile it.

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
