Scanny
======

Scanny is a Ruby on Rails security scanner. It parses Ruby files, looks for various suspicious patterns in them (by traversing the AST) and produces a report. Scanny aims to be simple (it does one thing well) and extensible (it is easy to define new patterns).

**This is currently work in progress and it's probably not useful at this point.**

Credits
-------

The tool was written as a replacement of Thomas Biege's [Ruby on Rails scanner](http://gitorious.org/code-scanner/ror-sec-scanner/) which is used internally in SUSE. This tool uses just regular expressions to look for suspicious places.

AST parsing and checking code was copied and adapted from [Roodi](http://roodi.rubyforge.org/), a tool for detecting Ruby code design issues.
