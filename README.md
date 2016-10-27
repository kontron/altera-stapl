altera-stapl
============

Alteras Jam STAPL Bytecode Player with 64-bit support. This is a user-space
port of the altera-stapl driver from the linux kernel. The source released
by Altera wasn't 64-bit compatible. Additionally, the linux version is much
cleaner and old cruft was removed.

Compared to the original Altera sources this has the following new
features:
  * uses the generic GPIO interface, thus should be usable with any
	CPLD/FPGA devices which have their JTAG port connected to GPIOs
	accessible by the kernel.
  * much cleaner source code
  * GPLv2 license


Authors
-------
  * Michael Walle <michael.walle@kontron.com>
