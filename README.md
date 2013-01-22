Dalvik Header Plugin
===============

This is a simple Dalvik header plugin for IDA Pro. While there are
other tools which currently do this, and display the information better
I was attempting to recreate the Dalvik loader for IDA Pro and started
with this. It isn't fully fleshed out yet - though I'm adding extra
classes to it now for detection of anti-disassembler tricks.

Currently IDA Pro does not surface any of the header information which
is annoying and causes me to open multiple tools. Hopefully this will
become fully functional and highlight those anti-disassembler attempts
and provide quick feedback to the analyst.

Much of the code, and concept was adapted from fG!'s Mach-O plugin.

This plugin was only tested on OSX using IDA Pro v6.4, though in theory
it should work fine for all version across platforms. You simply need
to configure the makefile to point properly at your IDA-SDK directory
and also the IDA-LIB directory. After doing this and running the make
command, simply copy the dalvikplugin.pmc to the "plugins" directory
of your IDA Pro installation. More information on compiling in OSX
can be found on fG!'s blog;
http://reverse.put.as/2011/10/31/how-to-create-ida-cc-plugins-with-xcode/

Tim Strazzere - diff@lookout.com - strazz@gmail.com - http://www.strazzere.com/blog