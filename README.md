# memory-tracer
A memory allocation trace, like a hot spot analyzer for memory allocation

Usage: memory-tracer [OPTION]...
    --debug		Print debug messages.
    --ftrace  Use ftrace for tracing, poor performance but should always work.
    --perf		Use binary perf for tracing, great performance, require CONFIG_FRAME_POINTER enabled.
    --page		Collect page usage statistic.
    --slab		Collect slab cache usage statistic.
    --json		Format result as json.
    --help 		Print this message.
    
WIP options:
    --ebpf [DIR]	Use ebpf for tracing, poor performance but should always work.
    --trace-base [DIR]	Use a different tracing mount path.
    --human-readable	Print sizes in a human reable way, eg bytes_alloc: 1048576 => 1M
    --throttle-output [PERCENTAGE]
    			Only print callsites consuming [PERCENTAGE] percent of total memory consumed.
    			expect a number between 0 to 100. Useful to filter minor noises.
