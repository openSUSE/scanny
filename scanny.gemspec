# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name        = "scanny"
  s.version     = '0.1.0'
  s.platform    = Gem::Platform::RUBY
  s.authors     = ['Thomas Biege', 'Flavio Castelli', 'David Majda', 'Piotr Niełacny']
  s.email       = ['thomas@suse.de', 'fcastelli@novell.com', 'dmajda@suse.cz', 'piotr.nielacny@gmail.com']
  s.homepage    = "https://github.com/openSUSE/scanny"
  s.summary     = "Ruby security scanner"
  s.description = "Find all security issues affecting your code."

  s.required_rubygems_version = ">= 1.3.6"
  s.rubyforge_project         = "scanny"

  s.add_dependency "machete", "0.5.0"
  s.add_dependency "docopt", "0.0.4"

  s.files        = `git ls-files`.split("\n")
  s.executables  = `git ls-files`.split("\n").map{|f| f =~ /^bin\/(.*)/ ? $1 : nil}.compact
  s.require_path = 'lib'
end
