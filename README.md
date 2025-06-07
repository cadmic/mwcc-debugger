# MWCC debugger

A Python script to dump internal state from MWCC compiler runs for help with matching
decompilation. It runs the compiler using [retrowin32](https://github.com/evmar/retrowin32)
and uses `gdb` to set breakpoints and inspect the compiler's memory.

Currently the following MWCC versions are supported:
* GC/1.1 (usually good enough for GC/1.0 - GC/1.2.5)
* GC/2.6 (usually good enough for GC/1.3.2 - GC/2.7)

## Installation (Linux or macOS)

First, ensure `gdb`, `cmake`, and [Rust](https://rustup.rs/) are installed.

Next, this project depends on @encounter's branch of `retrowin32` with GDB support.
To build the fork:
```bash
$ git clone https://github.com/encounter/retrowin32.git
$ cd retrowin32
$ git checkout gdb-stub
$ cargo build -p retrowin32 -F x86-unicorn --profile lto
```
The built binary will appear in `target/lto/retrowin32`.

Finally, download `mwcc_debugger.py` from this repo (or clone this repo).

## Usage

Run it as
```
$ ./mwcc_debugger.py -e path/to/retrowin32 -a 'mwcc command line' function_name optional_output_dir
```
e.g.
```
$ ./mwcc_debugger.py -e ../target/lto/retrowin32 -a 'build/compilers/GC/1.1/mwcceppc.exe -O4,p -c source_file.cpp' myfunc__9MyClassFv
```

To find your compiler command line, you can run `ninja -t commands | grep source_file.cpp`.
We want the `mwcceppc.exe` command line only, i.e without `wibo`, `sjiswrap`, or
`transform_dep.py`. You can also place `retrowin32` on your `PATH` instead of passing it in manually.

You may need to use a different-but-similar MWCC version if your version isn't
supported yet. Adding `-sym on` is useful too so that line numbers can appear in
the output.

The script will run the compiler and print its internal state to files in the
output directory. See below for more detail on what these files are.

## Compiler internals

Broadly, MWCC consists of a "frontend" and a "backend". The frontend parses C
code, inlines functions, and performs some optimizations using an intermediate
language. The backend translates this to PowerPC code, performs more
optimizations, allocates registers and stack space, and generates the final
assembly.

For deeper dives, [Ninji's MWCC decomp](https://git.wuffs.org/MWCC/tree/?h=main)
is a great resource.

### Frontend passes

The frontend parses C/C++ code into an abstract syntax tree, which is dumped as
`frontend-00-ast-initial-code.txt`. If optimizations are enabled, the frontend
transforms this into an intermediate representation (creatively called "IR") and
performs optimizations on that. These optimizations include:
* Some loop unrolling, including replacing "induction variables" (for example,
  replacing `i * 2` with a new variable which is incremented by 2 every
  iteration).
* Common subexpression elimination, where repeated expressions are replaced with new variables.
* Range splitting, where reuses of the same local variable are replaced with new variables.

Debugging the frontend optimizations is not currently supported (but will be
soon).

After optimizations, the code is transformed back into an abstract syntax tree
(dumped as `ast-final-code`) before being handed off to the backend.

### Backend passes

The backend uses a PowerPC-like representation called "PCode". To represent
variables and temps, it uses "virtual" register numbers above 32 (e.g. `r35` or
`f35`); these are replaced with real registers during register allocation. These
virtual registers could be local variables in the source code, named temps
created by the frontend, or unnamed temps created by the backend for
intermediate values (although the backend can create named variables sometimes
too).

The backend optimizations include:
* More loop unrolling. This is not as sophisticated as the frontend's loop
  unrolling and just blindly repeats the code, so often you can tell if a loop
  has been unrolled by the backend if loop variables are incremented more than
  once per iteration. Sometimes loops are unrolled by both the frontend and the
  backend (e.g. 8x by the frontend, and 2x by the backend, for a total of 16x).
* Replacing local structs or arrays with new variables for each element.
* Peephole optimizations, which try to optimize one instruction at a time
  without considering the entire code (e.g. combining a pointer `addi` and a
  `lwz` into a single `lwz` with an offset). The infamous
  `mr r3,r4 -> addi r3,r4,0` replacement is also a peephole "optimization".
* Scheduling, which reorders instructions so that instructions that depend on
  each other are farther apart. This is done both before and after register
  allocation.

The debugger script will dump the PCode at various points between backend passes,
as e.g. `backend-00-initial-code.txt` in the output directory.

### Register allocation

MWCC implements "Chaitin's algorithm" for register allocation. See
[these slides](https://web.cecs.pdx.edu/~mperkows/temp/register-allocation.pdf) for
an overview.

Variables are represented by "virtual register numbers" above 32 (e.g. `r35`),
and two variables are called "neighbors" if there is some point in the code
where they are both live (meaning they can't be assigned to the same machine
register). Variables are also marked as neighbors of machine registers if that
machine register can't be used for the variable (since `r0-r12` can't be used
across function calls, and `r0` can't be used for the address in a `lwz`, etc).

The allocation algorithm has two phases:

* In the first phase, the algorithm builds a list of all variables, ordered by
  "priority". This list is built in reverse order, where the lowest-priority
  variables are added first and the highest-priority variables are added last.

  First, the algorithm loops through all variables in order. If a variable's
  number of remaining neighbors is less than the number of free registers, that
  variable is added to the priority list, and no longer considered a neighbor of
  other variables. Usually there are 29 free registers since `r1`, `r2`, and
  `r13` are reserved, so a variable will be added if it has 28 remaining
  neighbors or less. (The idea is that this variable is low priority since after
  all of its neighbors are assigned registers, there is still guaranteed to be a
  free register available for this variable.)

  After going through all the variables, the algorithm will do it all again
  starting from the first variable. So, the regalloc priority order often looks
  like a series of "levels", where each level contains a bunch of variables in
  (reverse) numerical order, and the order wraps around between levels. Often
  you can influence regalloc by reordering variables (e.g. using a compiler temp
  instead of a real local variable), or adding/removing neighbors so a variable
  gets bumped into a higher or lower "level".

  If the algorithm has gone through all variables and they all have too many
  neighbors, the algorithm will choose the variable with the lowest "adjusted
  cost" (i.e. the variable that is least painful to spill), add that to the
  list, and then start looping through all the variables again.

* In the second phase, the algorithm goes through variables from highest
  priority to lowest priority, and assigns the first free register to each one
  (i.e. the lowest-numbered register that is not taken by any of its previous
  neighbors). The algorithm prefers registers `r0,r3-r12` and any
  previously-used saved registers; if none of these registers are free, it
  allocates a new saved register instead (starting with `r31`). If there are no
  more saved registers, the variable is spilled to the stack. At the end, if any
  variables were spilled, the whole algorithm is rerun without the spilled
  variables.

Before running this algorithm, MWCC will also try to "coalesce" variables
together. Specifically, if it finds an `mr` instruction like `mr r35,r42` where
`r35` and `r42` are not neighbors, it will merge `r42` and `r35` together into a
single variable (namely `r35`). It will also do this machine registers, e.g. if
it sees `mr r6,r42` for a function call it will automatically allocate `r6` for
`r42`.

This coalescing has a bug where the coalesced variables are not fully removed
from the graph, so coalesced variables still show up as neighbors of other
variables, even though they will never be assigned a register. So, creating new
coalesced variables is a good way to add more neighbors to variables and
influence regalloc order.

For each regalloc pass, the debugger script will dump un-coalesced variables in
order of priority to e.g. `regalloc-gpr-pass-1-assigned.txt`, and all variables
(including coalesced ones) to `regalloc-gpr-pass-1-all.txt`. The floating-point
regalloc dump is similar but with the name `fpr`. Unfortunately most variables
will be temps, but you can cross-reference with the `before-regalloc` PCode dump
to figure out which variables are what.

Generally the strategy for fixing regalloc is to go through the assigned
variables from the top down and find the first place they differ, and then
influence that by reordering things (e.g. making something a compiler temp
instead of a real variable, moving variables to inline functions, etc.) or
adding/removing neighbors to move variables between different "levels" (e.g. by
created new "coalesced" variables).
