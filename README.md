# memory-tracer
A memory allocation trace, like a hot spot analyzer for memory allocation

Usage: memory-tracer [OPTION]...
&nbsp;&nbsp;&nbsp;&nbsp;--debug		Print debug messages.  
&nbsp;&nbsp;&nbsp;&nbsp;--ftrace  Use ftrace for tracing, poor performance but should always work.  
&nbsp;&nbsp;&nbsp;&nbsp;--perf		Use binary perf for tracing, great performance, require CONFIG_FRAME_POINTER enabled.  
&nbsp;&nbsp;&nbsp;&nbsp;--page		Collect page usage statistic.  
&nbsp;&nbsp;&nbsp;&nbsp;--slab		Collect slab cache usage statistic.  
&nbsp;&nbsp;&nbsp;&nbsp;--json		Format result as json.  
&nbsp;&nbsp;&nbsp;&nbsp;--help 		Print this message.  
    
WIP options:  
&nbsp;&nbsp;&nbsp;&nbsp;--ebpf [DIR]	Use ebpf for tracing, poor performance but should always work.  
&nbsp;&nbsp;&nbsp;&nbsp;--trace-base [DIR]	Use a different tracing mount path.  
&nbsp;&nbsp;&nbsp;&nbsp;--human-readable	Print sizes in a human reable way, eg bytes_alloc: 1048576 => 1M  
&nbsp;&nbsp;&nbsp;&nbsp;--throttle-output [PERCENTAGE]  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Only print callsites consuming [PERCENTAGE] percent of total memory consumed.  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;expect a number between 0 to 100. Useful to filter minor noises.  
