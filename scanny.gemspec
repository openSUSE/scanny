# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name        = "scanny"
  s.version     = '0.0.1'
  s.platform    = Gem::Platform::RUBY
  s.authors     = ['Flavio Castelli', 'David Majda']
  s.email       = ['fcastelli@novell.com','dmajda@novell.com']
  s.homepage    = "https://github.com/dmadja/scanny"
  s.summary     = "Ruby security scanner"
  s.description = "Find all security issues affecting your code."

  s.required_rubygems_version = ">= 1.3.6"
  s.rubyforge_project         = "scanny"

  s.files        = `git ls-files`.split("\n")
  s.executables  = `git ls-files`.split("\n").map{|f| f =~ /^bin\/(.*)/ ? $1 : nil}.compact
  s.require_path = 'lib'
end
