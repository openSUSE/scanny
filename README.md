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

Rake task
---------

To create scanny rake task you need to edit Rakefile.

```ruby
require "scanny/rake_task"

Scanny::RakeTask.new do |t|
  t.name    = "scanny"              # name of rake-task
  t.include = "./custom/checks"     # directory with custom checks
  t.disable = "HTTPRedirectCheck"   # checks to disable
  t.format  = :stdout               # output format
  t.strict  = true                  # scanny strict mode
  t.path    = "./custom/app"        # path to scan
  t.fail_on_error = true            # raise exception on error
  t.ruby_mode = "18"                # ruby parser mode (default 19)
end
```

CI (Continuous Integration)
---------------------------

### Common for all CLI

* Add to ```Gemfile``` scanny gem

```ruby
gem 'scanny'
```

* Create [Rake task](https://github.com/openSUSE/scanny#rake-task).

```ruby
Scanny::RakeTask.new do |t|
  t.format  = :stdout       # you will see output on travis website
  t.fail_on_error = false   # security errors should not break build
end
```

### Travis

* Update your ```.travis.yml``` file. You need add ```before_script``` section.

```yaml
before_script:
- test -s "$HOME/.rvm/scripts/rvm" && source "$HOME/.rvm/scripts/rvm"
- rvm rbx-19mode
- bundle install
- bundle exec rake scanny
- rvm $TRAVIS_RUBY_VERSION
```

### Jenkins

* Add build step

```
bash -l -c '
rvm rbx-head &&
rvm gemset create scanny &&
rvm gemset use scanny &&
bundle install &&
bundle exec rake scanny'
```

* Install [Log Parser Plugin](https://wiki.jenkins-ci.org/display/JENKINS/Log+Parser+Plugin) for Jenkins
* Create rules file

```ruby
# /var/lib/jenkins/rules

info /- \[info\]/
warning /- \[low\]/
error /- \[(medium|high)\]/
```

* Go to ```Manage Jenkins > Configure System > Console Output Parsing```.
Add path to rules with in **Parsing Rules File** field

* Go to and check ```[Project] > Configure > Console output (build log) parsing```
* Select proper **Select Parsing Rules**
* Warnings you can find in ```[Build] > Parsed Console Output```


Writing New Checks
------------------
Internally, Scanny consists of multiple *checks*, each responsible for finding and reporting one suspicious pattern in the code. You can easily extend Scanny by writing new checks.

The checks are loaded automatically from files in the `lib/scanny/checks` directory. Let's look how a simple check may look like:

    module Scanny
      module Checks
        # Finds all invocations of "boo" and "moo" methods.
        class BooMooCheck < Check
          def pattern
            'Send<name = :boo | :moo> | SendWithArguments<name = :boo | :moo>'
          end

          def check(node)
            issue :high, "The \"#{node.name}\" method indicates wandering cows in the code.",
                  :cwe => 999
          end
        end
      end
    end

Checks are subclasses of the `Scanny::Checks::Check` class and they implement two methods: `pattern` and `check`.

### The `pattern` method

The `pattern` method returns a [Machete](https://github.com/openSUSE/machete) pattern describing Rubinius AST nodes this check is interested in. See [Machete documentation](https://github.com/openSUSE/machete/blob/master/README.md) to learn about the pattern syntax.

**Tip:** When creating a check pattern it's often useful to inspect how Rubinius transforms some Ruby constructs into AST nodes. You can do this using the `to_ast` method:

    '42'.to_ast # => #<Rubinius::AST::FixnumLiteral:0x36fc @value=42 @line=1>

### The `check` method

The `check` method will be called on all AST nodes in the scanned files matched by the pattern returned by the `pattern` method. It will be passed the suspicious node. It can perform additional checks on it and report an issue if the node really is problematic.

Issues are reported using the `issue` method. As its arguments it accepts issue impact level (`:info`, `:low`, `:medium` or `:high`) and a message for the user, optionally followed by an options hash. The only currently implemented option is `:cwe`, which allows associating the issue with a [CWE number](http://www.cvedetails.com/cwe-definitions.php) (or multiple numbers if you pass an array).

### Tests

Each check should be tested. The tests are written in RSpec and they are stored in  the `spec/scanny/checks` directory. This is how a test for our sample check may look like:

    require "spec_helper"

    module Scanny::Checks
      describe BooMooCheck do
        it "reports \"boo\" correctly" do
          @runner.should check('boo').with_issue(
            issue(:high, "The \"boo\" method indicates wandering cows in the code.", 999)
          )
        end

        it "reports \"moo\" correctly" do
          @runner.should check('moo').with_issue(
            issue(:high, "The \"moo\" method indicates wandering cows in the code.", 999)
          )
        end
      end
    end

Aim to create as simple test cases as possible. Also test different kinds of issues separately. See the existing tests to learn how more complex checks are tested.

Acknowledgement
---------------

The tool was written as a replacement of Thomas Biege's [Ruby on Rails scanner](http://gitorious.org/code-scanner/ror-sec-scanner/) which was used internally at [SUSE](http://www.suse.com/). This tool needed replacement because it look for suspicious patterns using just regular expressions, which is very rough and has expressivity problems with more complex patterns.

The original AST parsing and checking code was copied and adapted from [Roodi](http://roodi.rubyforge.org/), a tool for detecting Ruby code design issues.
