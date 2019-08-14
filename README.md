# memory-tracer
A memory allocation trace, like a hot spot analyzer for memory allocation

Usage: memory-tracer [OPTION]...<br>
&nbsp;&nbsp;--debug		Print debug messages.<br>
&nbsp;&nbsp;--ftrace		Use ftrace for tracing, poor performance but should always work.<br>
&nbsp;&nbsp;--perf		Use binary perf for tracing, may require CONFIG_FRAME_POINTER enabled on older kernel (before 5.1).<br>
&nbsp;&nbsp;--page		Collect page usage statistic.<br>
&nbsp;&nbsp;--slab		Collect slab cache usage statistic.<br>
&nbsp;&nbsp;--json		Format result as json.<br>
&nbsp;&nbsp;--help 		Print this message.<br>
&nbsp;&nbsp;--human-readable	Print sizes in a human reable way, eg bytes_alloc: 1048576 => 1M<br>

WIP options:<br>
&nbsp;&nbsp;--trace-base [DIR]	Use a different tracing mount path.<br>
&nbsp;&nbsp;--throttle-output [PERCENTAGE]<br>
&nbsp;&nbsp;&nbsp;&nbsp;Only print callsites consuming [PERCENTAGE] percent of total memory consumed.<br>
&nbsp;&nbsp;&nbsp;&nbsp;expect a number between 0 to 100. Useful to filter minor noises.<br>

# Install
> make<br>
> make install<br>
# Install as dracut module
> make dracut-module-install<br>
> (The debug result will be avaiable in the initramfs as /memory-debug, still need to copy that to where you want to dump it manually)<br>

# Note
For for Linux kernel using ORC unwinder and version below 5.2, it have a bug with tracepoints that unable to generate stack trace properly using perf, so you might empty stack trace data using --perf.  To avoid such problem, please update your kernel to latest version.
