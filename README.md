Scanny
======

Scanny is a Ruby on Rails security scanner. It parses Ruby files, looks for various suspicious patterns in them (by traversing the AST) and produces a report. Scanny aims to be simple (it does one thing well) and extensible (it is easy to define new patterns).

**This is currently work in progress and it's probably not useful yet.**

Installation
------------

You need to install [Rubinius](http://rubini.us/) first. You can then install Scanny:

    $ git clone git://github.com/openSUSE/scanny.git

The scanner is not available as a gem yet (this will come soon hopefully).

Usage
-----

To scan one or more Ruby file, use the `bin/scanny` command and pass the files to scan as arguments. Scanny will check the files and print a nice report:

    $ cat bad.rb
    `ls #{ARGV[1]}`
    $ bin/scanny bad.rb
    bad.rb [2 checks done | 2 nodes inspected | 1 issues]
      - [high] bad.rb:1: Backticks and %x{...} pass the executed command through shell expansion. (CWE-88, CWE-78)

    Found 1 issues.

Acknowledgement
---------------

The tool was written as a replacement of Thomas Biege's [Ruby on Rails scanner](http://gitorious.org/code-scanner/ror-sec-scanner/) which was used internally at [SUSE](http://www.suse.com/). This tool needed replacement because it look for suspicious patterns using just regular expressions, which is very rough and has expressivity problems with more complex patterns.

The original AST parsing and checking code was copied and adapted from [Roodi](http://roodi.rubyforge.org/), a tool for detecting Ruby code design issues.
