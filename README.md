#Project GEMROC

This project is a Wireshark dissector for packets from GEMROC device. The dissector is
implemented as a plugin.

##Compilation

To compile the project link the main directory to the `plugins/epan/` directory in the Wireshark
source tree and add it's path to `CMakeListsCustom.txt` file in root directory of the Wireshark

The `CMakeListsCustom.txt` may not be present. In such case the `CMakeListsCustom.txt.example`
can be used as a template.

The project adds target `gemroc_dissector`, which can be compiled separately,
but version of Wireshark must be the same as version of Wireshark source tree used for compilation.
This can be accomplished using `git checkout tags/wireshark-1.2.3`, with `1.2.3` replaced with the desired version.

Another option is building the whole Wireshark project. In such case the dissector will be built as well.

##Installation
The result of `gemroc_dissector` target compilation, ie. `gemroc_dissector.so` file, can be copied to `plugins/epan` directory of installed Wireshark.
If the whole project was built the plugin will be already installed.

##License
This software is licensed under the GPL v2 License.
